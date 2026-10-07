// Package auth verifies short-lived ES256 access tokens and the ES256 DPoP
// proofs that bind each download to the caller's key (RFC 9449).
package auth

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"calibration-bundles/internal/jwx"
)

// ErrorCode is a stable, machine-readable error identifier surfaced to callers
// (JSON body "error" and DPoP WWW-Authenticate parameters).
type ErrorCode string

const (
	CodeMalformed         ErrorCode = "malformed_request"
	CodeInvalidToken      ErrorCode = "invalid_token"
	CodeExpiredToken      ErrorCode = "expired_token"
	CodeInsufficientScope ErrorCode = "insufficient_scope"
	CodeInvalidDPoP       ErrorCode = "invalid_dpop_proof"
	CodeReplay            ErrorCode = "replay_detected"
)

// Error carries a stable code, HTTP status and human description.
type Error struct {
	Code   ErrorCode
	Status int
	Desc   string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Desc) }

func fail(code ErrorCode, status int, format string, a ...any) error {
	return &Error{Code: code, Status: status, Desc: fmt.Sprintf(format, a...)}
}

// Params are the validated security inputs for one download request.
type Params struct {
	ExpectedIssuer   string
	ExpectedAudience string
	ExpectedSubject  string
	// IssuerKeys are the registered issuer verification keys (the JWKS at
	// issuer_jwk_path). Every key has equal standing: a token carrying a kid
	// selects the one registered key with that kid, while a token without a
	// kid may verify against any of them. When empty, the single IssuerKey
	// below is used.
	IssuerKeys []jwx.RegisteredKey
	// IssuerKey is the single registered issuer key for single-key
	// deployments; consulted only when IssuerKeys is empty.
	IssuerKey    *ecdsa.PublicKey
	PublicOrigin string // e.g. https://api.example.lab
	HTUPath      string // /api/calibration-bundles/{id}
	Now          time.Time
	AccessLeeway time.Duration
	ProofMaxAge  time.Duration
	ProofLeeway  time.Duration
}

// Decision is the result of a fully validated token+proof pair.
type Decision struct {
	Subject string
	// ProofJTI is the single-use proof identifier the caller must now claim
	// durably before releasing bytes.
	ProofJTI string
}

// accessToken claims we rely on.
type accessClaims struct {
	Issuer      string          `json:"iss"`
	Subject     string          `json:"sub"`
	Audience    json.RawMessage `json:"aud"`
	Exp         int64           `json:"exp"`
	IAT         int64           `json:"iat"`
	Nbf         *int64          `json:"nbf"`
	Scope       string          `json:"scope"`
	Permissions []string        `json:"permissions"`
	Cnf         struct {
		Jkt string `json:"jkt"`
	} `json:"cnf"`
}

type proofClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	JTI string `json:"jti"`
	ATH string `json:"ath"`
	IAT int64  `json:"iat"`
	EXP *int64 `json:"exp"`
	NBF *int64 `json:"nbf"`
}

// Verify validates the access token and its DPoP proof. It does NOT consume the
// proof jti: the caller must durably Claim(Decision.ProofJTI) first, so that
// concurrency and restart semantics live in one place.
func Verify(accessToken, dpopProof string, p Params) (*Decision, error) {
	if accessToken == "" {
		return nil, fail(CodeMalformed, 400, "missing access token")
	}
	if dpopProof == "" {
		return nil, fail(CodeInvalidDPoP, 401, "missing DPoP proof in DPoP header")
	}

	tok, err := jwx.ParseCompact(accessToken)
	if err != nil {
		return nil, fail(CodeInvalidToken, 401, "malformed access token: %v", err)
	}

	// --- protected header: ES256 only, JWT typ, no algorithm confusion ---
	if alg, _ := tok.Header["alg"].(string); alg != "ES256" {
		return nil, fail(CodeInvalidToken, 401, "access token alg must be ES256, got %q", alg)
	}
	if typ, _ := tok.Header["typ"].(string); typ != "" && typ != "JWT" {
		return nil, fail(CodeInvalidToken, 401, "access token typ must be JWT, got %q", typ)
	}
	if err := verifyAccessSignature(tok, p); err != nil {
		return nil, err
	}

	var claims accessClaims
	if err := json.Unmarshal(tok.Payload, &claims); err != nil {
		return nil, fail(CodeInvalidToken, 401, "malformed access token claims: %v", err)
	}

	if claims.Issuer != p.ExpectedIssuer {
		return nil, fail(CodeInvalidToken, 401, "iss %q does not match registered issuer %q", claims.Issuer, p.ExpectedIssuer)
	}
	if !audienceContains(claims.Audience, p.ExpectedAudience) {
		return nil, fail(CodeInvalidToken, 401, "aud does not contain %q", p.ExpectedAudience)
	}
	if claims.Subject != p.ExpectedSubject {
		return nil, fail(CodeInvalidToken, 401, "sub %q does not match registered subject %q", claims.Subject, p.ExpectedSubject)
	}

	now := p.Now
	if claims.Exp == 0 {
		return nil, fail(CodeInvalidToken, 401, "access token missing exp")
	}
	if !within(now, claims.IAT, claims.Exp, claims.Nbf, p.AccessLeeway) {
		switch {
		case now.Unix() > claims.Exp+int64(p.AccessLeeway.Seconds()):
			return nil, fail(CodeExpiredToken, 401, "access token expired at %s", unixTime(claims.Exp).Format(time.RFC3339))
		case claims.Nbf != nil && now.Unix() < *claims.Nbf-int64(p.AccessLeeway.Seconds()):
			return nil, fail(CodeInvalidToken, 401, "access token not yet valid")
		default:
			return nil, fail(CodeInvalidToken, 401, "access token outside validity window")
		}
	}

	if !hasBundlesRead(claims.Scope, claims.Permissions) {
		return nil, fail(CodeInsufficientScope, 403, "token lacks bundles:read permission")
	}
	if claims.Cnf.Jkt == "" {
		return nil, fail(CodeInvalidToken, 401, "token cnf.jkt confirmation key is required")
	}
	jkt := strings.TrimSpace(claims.Cnf.Jkt)
	if _, err := jwx.Decode(jkt); err != nil {
		return nil, fail(CodeInvalidToken, 401, "token cnf.jkt is not base64url")
	}

	// ---------------- DPoP proof ----------------
	proof, err := jwx.ParseCompact(dpopProof)
	if err != nil {
		return nil, fail(CodeInvalidDPoP, 401, "malformed DPoP proof: %v", err)
	}
	if typ, _ := proof.Header["typ"].(string); typ != "dpop+jwt" {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof typ must be dpop+jwt, got %q", typ)
	}
	if alg, _ := proof.Header["alg"].(string); alg != "ES256" {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof alg must be ES256, got %q", alg)
	}

	jwkRaw, ok := proof.Header["jwk"]
	if !ok {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof header must embed the public jwk")
	}
	jwkJSON, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP jwk is not JSON: %v", err)
	}
	dpopPub, _, err := jwx.ParsePublicJWK(jwkJSON)
	if err != nil {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP jwk invalid: %v", err)
	}
	if _, kid := proof.Header["kid"]; kid {
		// RFC 9449 proofs carry the key inline; reject ambiguous key selection.
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof must not use kid; embedded jwk is required")
	}
	if err := jwx.VerifyES256(proof, dpopPub); err != nil {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof signature invalid: %v", err)
	}

	// Key binding: thumbprint of proof key == token cnf.jkt.
	px, py := jwx.XY(dpopPub)
	proofJKT := jwx.ThumbprintB64(px, py)
	if proofJKT != jkt {
		return nil, fail(CodeInvalidDPoP, 401,
			"DPoP key thumbprint %s does not match token cnf.jkt %s", proofJKT, jkt)
	}

	var pc proofClaims
	if err := json.Unmarshal(proof.Payload, &pc); err != nil {
		return nil, fail(CodeInvalidDPoP, 401, "malformed DPoP claims: %v", err)
	}
	if pc.JTI == "" || len(pc.JTI) > 1024 {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP jti must be a non-empty identifier")
	}
	if strings.TrimSpace(pc.JTI) == "" {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP jti must not be blank")
	}
	if pc.IAT == 0 {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP iat is required")
	}
	age := now.Sub(unixTime(pc.IAT))
	if age > p.ProofMaxAge+p.ProofLeeway {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof too old: age %s exceeds %s", age.Round(time.Second), p.ProofMaxAge)
	}
	if age < -p.ProofLeeway {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof iat is in the future")
	}
	if pc.EXP != nil && now.Unix() > *pc.EXP+int64(p.ProofLeeway.Seconds()) {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof has expired")
	}
	if pc.NBF != nil && now.Unix() < *pc.NBF-int64(p.ProofLeeway.Seconds()) {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP proof not yet valid")
	}
	if strings.ToUpper(pc.HTM) != "GET" {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP htm must be GET, got %q", pc.HTM)
	}
	expectedHTU := strings.TrimRight(p.PublicOrigin, "/") + p.HTUPath
	if pc.HTU != expectedHTU {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP htu mismatch: expected exactly %q, got %q", expectedHTU, pc.HTU)
	}

	// ath = base64url(SHA-256(access token compact serialization)).
	sum := sha256.Sum256([]byte(accessToken))
	if pc.ATH != jwx.Encode(sum[:]) {
		return nil, fail(CodeInvalidDPoP, 401, "DPoP ath does not bind the presented access token")
	}

	return &Decision{Subject: claims.Subject, ProofJTI: pc.JTI}, nil
}

// verifyAccessSignature checks the access-token signature against the
// registered issuer keys. A token kid selects deterministically: exactly one
// registered key must carry that kid, and no other key is tried. A token
// without a kid may verify against any registered key — every key in the
// JWKS has equal standing, so document order never decides the outcome.
func verifyAccessSignature(tok *jwx.JWS, p Params) error {
	keys := p.IssuerKeys
	if len(keys) == 0 && p.IssuerKey != nil {
		keys = []jwx.RegisteredKey{{Public: p.IssuerKey}}
	}
	if len(keys) == 0 {
		return fail(CodeInvalidToken, 401, "no registered issuer key is configured")
	}

	kid, hasKid, err := accessTokenKid(tok)
	if err != nil {
		return fail(CodeInvalidToken, 401, "%v", err)
	}
	if hasKid {
		var match *jwx.RegisteredKey
		matches := 0
		for i := range keys {
			if keys[i].Kid != "" && keys[i].Kid == kid {
				matches++
				match = &keys[i]
			}
		}
		switch {
		case matches == 0:
			return fail(CodeInvalidToken, 401, "access token kid %q matches no registered issuer key", kid)
		case matches > 1:
			return fail(CodeInvalidToken, 401, "access token kid %q matches %d registered issuer keys; cannot select uniquely", kid, matches)
		}
		if err := jwx.VerifyES256(tok, match.Public); err != nil {
			return fail(CodeInvalidToken, 401, "access token signature rejected by registered issuer key (kid %q): %v", kid, err)
		}
		return nil
	}

	for i := range keys {
		if jwx.VerifyES256(tok, keys[i].Public) == nil {
			return nil
		}
	}
	return fail(CodeInvalidToken, 401, "access token signature rejected by every registered issuer key")
}

// accessTokenKid extracts the optional kid member of the token's protected
// header. A present but non-string kid is rejected; an empty or blank kid is
// treated as absent.
func accessTokenKid(tok *jwx.JWS) (kid string, present bool, err error) {
	raw, ok := tok.Header["kid"]
	if !ok {
		return "", false, nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", false, errors.New("access token kid must be a string")
	}
	if strings.TrimSpace(s) == "" {
		return "", false, nil
	}
	return s, true, nil
}

func within(now time.Time, iat, exp int64, nbf *int64, leeway time.Duration) bool {
	l := int64(leeway.Seconds())
	t := now.Unix()
	if t > exp+l {
		return false
	}
	if nbf != nil && t < *nbf-l {
		return false
	}
	if iat != 0 && t < iat-l {
		return false
	}
	return true
}

func unixTime(u int64) time.Time { return time.Unix(u, 0).UTC() }

// audienceContains accepts aud as a string or an array of strings.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

func hasBundlesRead(scope string, permissions []string) bool {
	for _, s := range strings.Fields(scope) {
		if s == "bundles:read" {
			return true
		}
	}
	for _, s := range permissions {
		if s == "bundles:read" {
			return true
		}
	}
	return false
}

// AsError extracts an *Error from a verification error.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
