package jwx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Signer signs an already-assembled signing input.
type Signer interface {
	Sign(input []byte) ([]byte, error)
}

// ES256Signer signs with an EC P-256 key, producing raw R||S signatures.
type ES256Signer struct{ Key *ecdsa.PrivateKey }

func (s ES256Signer) Sign(input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	r, ss, err := ecdsa.Sign(rand.Reader, s.Key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return sig, nil
}

// SignCompact builds and signs a JWT with the given protected header and
// JSON payload, using ES256 (raw R||S signature).
func SignCompact(header map[string]any, payload []byte, signer Signer) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	h := Encode(hb)
	p := Encode(payload)
	sig, err := signer.Sign([]byte(h + "." + p))
	if err != nil {
		return "", err
	}
	return h + "." + p + "." + Encode(sig), nil
}

// VerifyES256 validates a parsed JWS against the given P-256 public key.
// Accepts only the fixed-length raw R||S signature form used by JWT/DPoP.
func VerifyES256(jws *JWS, pub *ecdsa.PublicKey) error {
	sig, err := Decode(jws.Signature())
	if err != nil {
		return errors.New("malformed signature encoding")
	}
	if len(sig) != 64 {
		return errors.New("invalid ES256 signature length")
	}
	digest := sha256.Sum256([]byte(jws.SigningInput()))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("signature verification failed")
	}
	return nil
}

// PublicJWK is the subset of an EC JWK needed for verification.
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParsePublicJWK decodes a P-256 EC public JWK.
func ParsePublicJWK(raw []byte) (*ecdsa.PublicKey, *PublicJWK, error) {
	var jwk PublicJWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, nil, err
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, nil, fmt.Errorf("unsupported issuer key: kty=%q crv=%q, require EC/P-256", jwk.Kty, jwk.Crv)
	}
	xb, err := Decode(jwk.X)
	if err != nil || len(xb) != 32 {
		return nil, nil, errors.New("jwk x must be 32 bytes base64url")
	}
	yb, err := Decode(jwk.Y)
	if err != nil || len(yb) != 32 {
		return nil, nil, errors.New("jwk y must be 32 bytes base64url")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, nil, errors.New("jwk point is not on P-256")
	}
	return pub, &jwk, nil
}

// XY returns the fixed-length coordinates of a P-256 public key.
func XY(pub *ecdsa.PublicKey) (x, y []byte) {
	x = make([]byte, 32)
	y = make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return x, y
}
