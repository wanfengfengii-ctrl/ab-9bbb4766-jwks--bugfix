package auth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// IssuerKey is one registered ES256 verification key. KID is the optional JWK
// key id a token header may pin; an empty KID denotes a key that is only
// reachable by tokens that do not carry a kid.
type IssuerKey struct {
	KID string
	Key *ecdsa.PublicKey
}

// KeySet is the set of registered issuer keys. Every member has equal
// verification standing: key order in the JWKS never affects a verdict.
type KeySet struct {
	keys []IssuerKey
}

// NewKeySet validates and freezes a registered key set: at least one usable
// P-256 key is required. Kids are not required to be unique at registration
// time: a presented kid that matches more than one key is rejected per-request
// as ambiguous (see resolve) rather than silently picking one.
func NewKeySet(keys []IssuerKey) (*KeySet, error) {
	if len(keys) == 0 {
		return nil, errors.New("issuer key set is empty")
	}
	for i, k := range keys {
		if k.Key == nil {
			return nil, fmt.Errorf("issuer key #%d is missing", i+1)
		}
	}
	cp := make([]IssuerKey, len(keys))
	copy(cp, keys)
	return &KeySet{keys: cp}, nil
}

// resolve returns the candidate keys for an access token.
//
//   - kid present: it must identify exactly one registered key; an unknown or
//     non-unique (ambiguous) kid is rejected without falling back to other
//     registered keys;
//   - kid absent: every registered key is a candidate, independent of order —
//     verification then decides cryptographically.
func (ks *KeySet) resolve(kid string, kidPresent bool) ([]*ecdsa.PublicKey, error) {
	if kidPresent {
		if kid == "" {
			return nil, errors.New("access token kid must be a non-empty string")
		}
		var matched []*ecdsa.PublicKey
		for _, k := range ks.keys {
			if k.KID == kid {
				matched = append(matched, k.Key)
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("access token kid %q is not registered", kid)
		}
		if len(matched) > 1 {
			return nil, fmt.Errorf("access token kid %q matches %d registered keys", kid, len(matched))
		}
		return matched, nil
	}
	out := make([]*ecdsa.PublicKey, 0, len(ks.keys))
	for _, k := range ks.keys {
		out = append(out, k.Key)
	}
	return out, nil
}
