// Package minting is test/demo tooling that reproduces the issuer and caller
// side of the protocol: it registers ES256 keys, mints cnf.jkt-bound access
// tokens and ES256 DPoP proofs. It is used by the keygen job and the one-shot
// verify service (never by the resource server).
package minting

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"calibration-bundles/internal/jwx"
)

// AccessClaims are the registered/private claims placed in an access token.
type AccessClaims struct {
	Issuer      string
	Subject     string
	Audience    any // string or []string
	Expiry      time.Time
	IssuedAt    time.Time
	NotBefore   *time.Time
	Scopes      []string // serialized as the space-separated "scope" claim
	Permissions []string // also accepted by the verifier
	JKT         string
	Extra       map[string]any
}

// MintAccessToken builds and ES256-signs the caller's access token.
func MintAccessToken(key *ecdsa.PrivateKey, c AccessClaims) (string, error) {
	now := time.Now().UTC()
	if c.IssuedAt.IsZero() {
		c.IssuedAt = now
	}
	claims := map[string]any{
		"iss": c.Issuer,
		"sub": c.Subject,
		"aud": c.Audience,
		"iat": c.IssuedAt.Unix(),
		"exp": c.Expiry.Unix(),
		"cnf": map[string]any{"jkt": c.JKT},
	}
	if len(c.Scopes) > 0 {
		claims["scope"] = joinSpace(c.Scopes)
	}
	if len(c.Permissions) > 0 {
		claims["permissions"] = c.Permissions
	}
	if c.NotBefore != nil {
		claims["nbf"] = c.NotBefore.Unix()
	}
	for k, v := range c.Extra {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	return jwx.SignCompact(header, payload, jwx.ES256Signer{Key: key})
}

// DPoPClaims are the claims of a sender-constrained proof.
type DPoPClaims struct {
	HTM       string
	HTU       string
	ATH       string
	JTI       string
	IssuedAt  time.Time
	Expiry    *time.Time
	NotBefore *time.Time
	Extra     map[string]any
}

// MintDPoPProof builds and ES256-signs a DPoP proof carrying the public jwk in
// its protected header.
func MintDPoPProof(key *ecdsa.PrivateKey, c DPoPClaims) (string, error) {
	x, y := jwx.XY(&key.PublicKey)
	header := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   jwx.Encode(x),
			"y":   jwx.Encode(y),
		},
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now().UTC()
	}
	claims := map[string]any{
		"htm": c.HTM,
		"htu": c.HTU,
		"jti": c.JTI,
		"ath": c.ATH,
		"iat": c.IssuedAt.Unix(),
	}
	if c.Expiry != nil {
		claims["exp"] = c.Expiry.Unix()
	}
	if c.NotBefore != nil {
		claims["nbf"] = c.NotBefore.Unix()
	}
	for k, v := range c.Extra {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jwx.SignCompact(header, payload, jwx.ES256Signer{Key: key})
}

// ATH returns base64url(SHA-256(access token)), the DPoP ath value.
func ATH(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return jwx.Encode(sum[:])
}

// GenerateP256 creates a fresh P-256 signing key.
func GenerateP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// JKT returns the RFC 7638 thumbprint of the key's public half.
func JKT(key *ecdsa.PrivateKey) string {
	x, y := jwx.XY(&key.PublicKey)
	return jwx.ThumbprintB64(x, y)
}

func joinSpace(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}

// privateJWK is the on-disk representation of an EC private key.
type privateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

// SaveKeyPair writes a public JWK (world-readable) and private JWK (0600) into
// dir. Existing files are left untouched.
func SaveKeyPair(dir string, key *ecdsa.PrivateKey) (pubPath, privPath string, err error) {
	x, y := jwx.XY(&key.PublicKey)
	d := make([]byte, 32)
	key.D.FillBytes(d)
	pub := map[string]any{"kty": "EC", "crv": "P-256", "x": jwx.Encode(x), "y": jwx.Encode(y)}
	priv := privateJWK{"EC", "P-256", jwx.Encode(x), jwx.Encode(y), jwx.Encode(d)}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", err
	}
	pubPath = filepath.Join(dir, "jwk.json")
	privPath = filepath.Join(dir, "jwk-private.json")
	if _, err := os.Stat(pubPath); err == nil {
		return pubPath, privPath, errors.New("key material already exists; refusing to overwrite")
	}
	pb, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pubPath, pb, 0o644); err != nil {
		return "", "", err
	}
	pvb, err := json.MarshalIndent(priv, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(privPath, pvb, 0o600); err != nil {
		return "", "", err
	}
	return pubPath, privPath, nil
}

// LoadPrivateKey reads an EC private JWK as written by SaveKeyPair.
func LoadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var jwk privateJWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("parse private jwk: %w", err)
	}
	pub, _, err := jwx.ParsePublicJWK(raw)
	if err != nil {
		return nil, err
	}
	db, err := jwx.Decode(jwk.D)
	if err != nil || len(db) == 0 || len(db) > 32 {
		return nil, errors.New("private jwk d invalid")
	}
	d := make([]byte, 32)
	copy(d[32-len(db):], db)
	return &ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(d)}, nil
}
