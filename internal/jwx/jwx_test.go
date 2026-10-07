package jwx_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"calibration-bundles/internal/jwx"
)

// referenceThumbprint is an independent RFC 7638 implementation for the test.
func referenceThumbprint(x, y []byte) string {
	canonical := struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"P-256", "EC",
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y)}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestThumbprintMatchesIndependentReference(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := jwx.XY(&key.PublicKey)
	got := jwx.ThumbprintB64(x, y)
	if got != referenceThumbprint(x, y) {
		t.Fatalf("thumbprint mismatch: %s vs %s", got, referenceThumbprint(x, y))
	}
	if len(got) != 43 {
		t.Fatalf("base64url sha256 should be 43 chars, got %d", len(got))
	}
	if strings.ContainsAny(got, "+/=") {
		t.Fatalf("thumbprint must be base64url no padding: %s", got)
	}
}

func TestES256SignVerifyRoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"hello":"world"}`)
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	tok, err := jwx.SignCompact(header, payload, jwx.ES256Signer{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 parts, got %d", len(parts))
	}
	sig, err := jwx.Decode(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature must be 64 raw bytes, got %d", len(sig))
	}
	parsed, err := jwx.ParseCompact(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwx.VerifyES256(parsed, &key.PublicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if string(parsed.Payload) != string(payload) {
		t.Fatalf("payload mismatch")
	}

	// Flip a payload bit and ensure verification fails.
	tampered := parts[0] + "." + flipBit(parts[1]) + "." + parts[2]
	bad, err := jwx.ParseCompact(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwx.VerifyES256(bad, &key.PublicKey); err == nil {
		t.Fatal("tampered token verified")
	}

	// A different key must reject the signature.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := jwx.VerifyES256(parsed, &other.PublicKey); err == nil {
		t.Fatal("foreign key verified")
	}
}

func TestParsePublicJWKRejectsBadPoints(t *testing.T) {
	x := make([]byte, 32)
	y := make([]byte, 32)
	for i := range x {
		x[i] = 0xFF
	}
	jwk, _ := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": jwx.Encode(x), "y": jwx.Encode(y),
	})
	if _, _, err := jwx.ParsePublicJWK(jwk); err == nil {
		t.Fatal("off-curve point accepted")
	}
	// Wrong curve.
	jwk, _ = json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-384",
		"x": jwx.Encode(big.NewInt(1).Bytes()), "y": jwx.Encode(big.NewInt(1).Bytes()),
	})
	if _, _, err := jwx.ParsePublicJWK(jwk); err == nil {
		t.Fatal("P-384 accepted")
	}
}

func flipBit(b64 string) string {
	raw, _ := base64.RawURLEncoding.DecodeString(b64)
	raw[0] ^= 1
	return base64.RawURLEncoding.EncodeToString(raw)
}
