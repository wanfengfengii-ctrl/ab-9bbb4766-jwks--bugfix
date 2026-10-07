package auth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"calibration-bundles/internal/auth"
	"calibration-bundles/internal/jwx"
)

type rig struct {
	t      *testing.T
	issuer *ecdsa.PrivateKey
	dpop   *ecdsa.PrivateKey
	jkt    string
	params auth.Params
	now    time.Time
	path   string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	issuer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dpop, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x, y := jwx.XY(&dpop.PublicKey)
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	path := "/api/calibration-bundles/B-1"
	return &rig{
		t:      t,
		issuer: issuer,
		dpop:   dpop,
		jkt:    jwx.ThumbprintB64(x, y),
		now:    now,
		path:   path,
		params: auth.Params{
			ExpectedIssuer:   "https://issuer.example",
			ExpectedAudience: "calibration-api",
			ExpectedSubject:  "partner-a",
			IssuerKey:        &issuer.PublicKey,
			PublicOrigin:     "https://api.example",
			HTUPath:          path,
			Now:              now,
			AccessLeeway:     30 * time.Second,
			ProofMaxAge:      60 * time.Second,
			ProofLeeway:      30 * time.Second,
		},
	}
}

func (r *rig) accessToken(mutate func(m map[string]any), signKey *ecdsa.PrivateKey) string {
	claims := map[string]any{
		"iss":   r.params.ExpectedIssuer,
		"sub":   r.params.ExpectedSubject,
		"aud":   r.params.ExpectedAudience,
		"iat":   r.now.Add(-10 * time.Second).Unix(),
		"exp":   r.now.Add(2 * time.Minute).Unix(),
		"scope": "bundles:read",
		"cnf":   map[string]any{"jkt": r.jkt},
	}
	if mutate != nil {
		mutate(claims)
	}
	if signKey == nil {
		signKey = r.issuer
	}
	pb, _ := json.Marshal(claims)
	tok, err := jwx.SignCompact(map[string]any{"alg": "ES256", "typ": "JWT"}, pb, jwx.ES256Signer{Key: signKey})
	if err != nil {
		r.t.Fatal(err)
	}
	return tok
}

type proofOpts struct {
	key      *ecdsa.PrivateKey
	jti      string
	iat      time.Time
	htm      string
	htuPath  string
	ath      string
	typ      string
	noJWK    bool
	alg      string
	unsigned bool
}

func (r *rig) proof(token string, o proofOpts) string {
	key := o.key
	if key == nil {
		key = r.dpop
	}
	jti := o.jti
	if jti == "" {
		jti = "jti-" + randomHex()
	}
	iat := o.iat
	if iat.IsZero() {
		iat = r.now
	}
	htm := o.htm
	if htm == "" {
		htm = "GET"
	}
	p := o.htuPath
	if p == "" {
		p = r.path
	}
	ath := o.ath
	if ath == "" {
		sum := sha256.Sum256([]byte(token))
		ath = jwx.Encode(sum[:])
	}
	typ := o.typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	alg := o.alg
	if alg == "" {
		alg = "ES256"
	}
	x, y := jwx.XY(&key.PublicKey)
	header := map[string]any{"alg": alg, "typ": typ}
	if !o.noJWK {
		header["jwk"] = map[string]any{
			"kty": "EC", "crv": "P-256",
			"x": jwx.Encode(x), "y": jwx.Encode(y),
		}
	}
	claims := map[string]any{
		"htm": htm,
		"htu": r.params.PublicOrigin + p,
		"jti": jti,
		"ath": ath,
		"iat": iat.Unix(),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	if o.unsigned {
		return jwx.Encode(hb) + "." + jwx.Encode(pb) + "."
	}
	sig, err := jwx.ES256Signer{Key: key}.Sign([]byte(jwx.Encode(hb) + "." + jwx.Encode(pb)))
	if err != nil {
		r.t.Fatal(err)
	}
	return jwx.Encode(hb) + "." + jwx.Encode(pb) + "." + jwx.Encode(sig)
}

func TestValidTokenAndProof(t *testing.T) {
	r := newRig(t)
	tok := r.accessToken(nil, nil)
	proof := r.proof(tok, proofOpts{})
	d, err := auth.Verify(tok, proof, r.params)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if d.Subject != "partner-a" || d.ProofJTI == "" {
		t.Fatalf("bad decision: %+v", d)
	}
}

func TestTokenValidity(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(m map[string]any)
		signKey func(r *rig) *ecdsa.PrivateKey
		want    auth.ErrorCode
	}{
		{"foreign signature", nil, func(r *rig) *ecdsa.PrivateKey {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return k
		}, auth.CodeInvalidToken},
		{"wrong iss", func(m map[string]any) { m["iss"] = "https://rogue" }, nil, auth.CodeInvalidToken},
		{"wrong aud", func(m map[string]any) { m["aud"] = "other" }, nil, auth.CodeInvalidToken},
		{"wrong sub", func(m map[string]any) { m["sub"] = "x" }, nil, auth.CodeInvalidToken},
		{"no scope", func(m map[string]any) { m["scope"] = "nope" }, nil, auth.CodeInsufficientScope},
		{"permission granted", nil, nil, ""},
		{"expired", func(m map[string]any) { m["exp"] = r_now().Add(-time.Hour).Unix() }, nil, auth.CodeExpiredToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			if tc.name == "permission granted" {
				tc.mutate = func(m map[string]any) {
					m["permissions"] = []string{"bundles:read"}
					delete(m, "scope")
				}
			}
			var sk *ecdsa.PrivateKey
			if tc.signKey != nil {
				sk = tc.signKey(r)
			}
			tok := r.accessToken(tc.mutate, sk)
			proof := r.proof(tok, proofOpts{})
			_, err := auth.Verify(tok, proof, r.params)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				return
			}
			ae, ok := auth.AsError(err)
			if !ok || ae.Code != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}

func TestProofBinding(t *testing.T) {
	cases := []struct {
		name string
		mod  func(r *rig, tok string) (string, string)
		want auth.ErrorCode
	}{
		{
			"thumbprint mismatch",
			func(r *rig, tok string) (string, string) {
				other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return tok, r.proof(tok, proofOpts{key: other})
			},
			auth.CodeInvalidDPoP,
		},
		{
			"proof signature wrong key",
			func(r *rig, tok string) (string, string) {
				other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				// header jwk is the bound key, but signature comes from `other`.
				x, y := jwx.XY(&r.dpop.PublicKey)
				hb, _ := json.Marshal(map[string]any{
					"alg": "ES256", "typ": "dpop+jwt",
					"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": jwx.Encode(x), "y": jwx.Encode(y)},
				})
				sum := sha256.Sum256([]byte(tok))
				pb, _ := json.Marshal(map[string]any{
					"htm": "GET", "htu": r.params.PublicOrigin + r.path,
					"jti": "jti-x", "ath": jwx.Encode(sum[:]), "iat": r.now.Unix(),
				})
				sig, _ := jwx.ES256Signer{Key: other}.Sign([]byte(jwx.Encode(hb) + "." + jwx.Encode(pb)))
				return tok, jwx.Encode(hb) + "." + jwx.Encode(pb) + "." + jwx.Encode(sig)
			},
			auth.CodeInvalidDPoP,
		},
		{"bad typ", func(r *rig, tok string) (string, string) {
			return tok, r.proof(tok, proofOpts{typ: "at+jwt"})
		}, auth.CodeInvalidDPoP},
		{"alg none", func(r *rig, tok string) (string, string) {
			return tok, r.proof(tok, proofOpts{alg: "none", unsigned: true})
		}, auth.CodeInvalidDPoP},
		{"missing jwk", func(r *rig, tok string) (string, string) {
			return tok, r.proof(tok, proofOpts{noJWK: true})
		}, auth.CodeInvalidDPoP},
		{"stale iat", func(r *rig, tok string) (string, string) {
			return tok, r.proof(tok, proofOpts{iat: r.now.Add(-5 * time.Minute)})
		}, auth.CodeInvalidDPoP},
		{"future iat", func(r *rig, tok string) (string, string) {
			return tok, r.proof(tok, proofOpts{iat: r.now.Add(5 * time.Minute)})
		}, auth.CodeInvalidDPoP},
		{"htm POST", func(r *rig, tok string) (string, string) {
			return tok, r.proof(tok, proofOpts{htm: "POST"})
		}, auth.CodeInvalidDPoP},
		{"htu wrong path", func(r *rig, tok string) (string, string) {
			return tok, r.proof(tok, proofOpts{htuPath: "/api/other"})
		}, auth.CodeInvalidDPoP},
		{"ath mismatch", func(r *rig, tok string) (string, string) {
			return tok, r.proof(tok, proofOpts{ath: jwx.Encode(make([]byte, 32))})
		}, auth.CodeInvalidDPoP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tok := r.accessToken(nil, nil)
			t2, proof := tc.mod(r, tok)
			_, err := auth.Verify(t2, proof, r.params)
			ae, ok := auth.AsError(err)
			if !ok || ae.Code != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}

func TestProofMaxAgeBoundary(t *testing.T) {
	r := newRig(t)
	tok := r.accessToken(nil, nil)
	// Age exactly at max+leeway-1s passes.
	p := r.proof(tok, proofOpts{iat: r.now.Add(-89 * time.Second)})
	if _, err := auth.Verify(tok, p, r.params); err != nil {
		t.Fatalf("89s old proof should pass: %v", err)
	}
	// Beyond max+leeway fails.
	p = r.proof(tok, proofOpts{iat: r.now.Add(-91 * time.Second)})
	if _, err := auth.Verify(tok, p, r.params); err == nil {
		t.Fatal("91s old proof should be rejected")
	}
}

func TestAudienceArray(t *testing.T) {
	r := newRig(t)
	tok := r.accessToken(func(m map[string]any) {
		m["aud"] = []string{"other", r.params.ExpectedAudience}
	}, nil)
	proof := r.proof(tok, proofOpts{})
	if _, err := auth.Verify(tok, proof, r.params); err != nil {
		t.Fatalf("aud array containing target must pass: %v", err)
	}
}

func TestMalformedInputs(t *testing.T) {
	r := newRig(t)
	if _, err := auth.Verify("", "x", r.params); err == nil {
		t.Fatal("empty token must fail")
	}
	tok := r.accessToken(nil, nil)
	if _, err := auth.Verify(tok, "not-a-jwt", r.params); err == nil {
		t.Fatal("garbage proof must fail")
	}
	if _, err := auth.Verify(tok, strings.Repeat("a", 500)+"..", r.params); err == nil {
		t.Fatal("malformed proof must fail")
	}
}

func r_now() time.Time {
	return time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
}

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return jwx.Encode(b)
}
