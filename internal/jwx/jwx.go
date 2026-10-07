// Package jwx contains minimal, dependency-free JWT/JWK/JWS primitives
// (ES256 signing/verification, JWK thumbprints and base64url helpers).
package jwx

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Encode returns base64url without padding, as used by JWT/JWK/JWE.
func Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Decode parses base64url without padding.
func Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Thumbprint computes the RFC 7638 canonical JSON SHA-256 thumbprint of an
// EC P-256 public key, returned as raw bytes.
func Thumbprint(x, y []byte) []byte {
	canonical := fmt.Sprintf(
		`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		Encode(x), Encode(y))
	sum := sha256.Sum256([]byte(canonical))
	return sum[:]
}

// ThumbprintB64 is the base64url(no-padding) RFC 7638 thumbprint, as used in
// the JWT cnf.jkt member and for DPoP key binding.
func ThumbprintB64(x, y []byte) string {
	return Encode(Thumbprint(x, y))
}

func split(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
