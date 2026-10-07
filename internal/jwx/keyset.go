package jwx

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
)

// RegisteredKey is one issuer verification key accepted for access-token
// verification, parsed from a bare public JWK or one JWKS entry.
type RegisteredKey struct {
	Public *ecdsa.PublicKey
	// Kid is the JWK "kid" member; empty when the entry carries none.
	Kid string
}

// ParsePublicKeySet reads issuer verification keys from either a bare public
// JWK or a JWKS document ({"keys":[...]}). Every entry that satisfies the
// ES256 requirements (EC P-256 with on-curve coordinates) is registered with
// equal standing regardless of its position, so key order in the document
// never affects verification. Entries that do not qualify are skipped, and
// exact duplicates (same key material and kid) collapse to one. At least one
// usable key is required.
func ParsePublicKeySet(raw []byte) ([]RegisteredKey, error) {
	var wrap struct {
		Keys []json.RawMessage `json:"keys"`
	}
	entries := []json.RawMessage{raw}
	if err := json.Unmarshal(raw, &wrap); err == nil && len(wrap.Keys) > 0 {
		entries = wrap.Keys
	}
	var out []RegisteredKey
	seen := map[string]bool{}
	for _, entry := range entries {
		pub, jwk, err := ParsePublicJWK(entry)
		if err != nil {
			continue
		}
		x, y := XY(pub)
		id := jwk.Kid + "\x00" + ThumbprintB64(x, y)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, RegisteredKey{Public: pub, Kid: jwk.Kid})
	}
	if len(out) == 0 {
		return nil, errors.New("no usable ES256 P-256 public key found")
	}
	return out, nil
}
