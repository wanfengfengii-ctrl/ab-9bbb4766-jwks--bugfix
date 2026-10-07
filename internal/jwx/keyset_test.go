package jwx_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"calibration-bundles/internal/jwx"
)

// jwkMap renders a public JWK document for key, with an optional kid.
func jwkMap(t *testing.T, key *ecdsa.PrivateKey, kid string) map[string]any {
	t.Helper()
	x, y := jwx.XY(&key.PublicKey)
	m := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": jwx.Encode(x), "y": jwx.Encode(y),
	}
	if kid != "" {
		m["kid"] = kid
	}
	return m
}

func jwksDoc(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParsePublicKeySetBareJWK(t *testing.T) {
	key := mustKey(t)
	raw, _ := json.Marshal(jwkMap(t, key, "rot-1"))
	keys, err := jwx.ParsePublicKeySet(raw)
	if err != nil {
		t.Fatalf("bare JWK: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	if keys[0].Kid != "rot-1" {
		t.Fatalf("kid = %q, want rot-1", keys[0].Kid)
	}
	if keys[0].Public.X.Cmp(key.PublicKey.X) != 0 || keys[0].Public.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("parsed key material differs from the source key")
	}
}

func TestParsePublicKeySetMultiKeyJWKS(t *testing.T) {
	k1, k2, k3 := mustKey(t), mustKey(t), mustKey(t)
	doc := jwksDoc(t,
		jwkMap(t, k1, "a"),
		jwkMap(t, k2, "b"),
		jwkMap(t, k3, ""), // kid-less entry is still registered
	)
	keys, err := jwx.ParsePublicKeySet(doc)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("want 3 keys, got %d", len(keys))
	}
	wantKids := []string{"a", "b", ""}
	for i, want := range wantKids {
		if keys[i].Kid != want {
			t.Fatalf("key %d kid = %q, want %q", i, keys[i].Kid, want)
		}
	}
}

func TestParsePublicKeySetSkipsUnusableEntries(t *testing.T) {
	good := mustKey(t)
	offCurve := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": jwx.Encode(make([]byte, 32)), "y": jwx.Encode(make([]byte, 32)),
	}
	wrongCurve := map[string]any{
		"kty": "EC", "crv": "P-384",
		"x": jwx.Encode(make([]byte, 32)), "y": jwx.Encode(make([]byte, 32)),
	}
	notEC := map[string]any{"kty": "RSA", "n": "abc", "e": "AQAB"}
	garbage := map[string]any{"kty": "EC"}
	doc := jwksDoc(t, offCurve, wrongCurve, notEC, garbage, jwkMap(t, good, "good"))
	keys, err := jwx.ParsePublicKeySet(doc)
	if err != nil {
		t.Fatalf("JWKS with unusable entries: %v", err)
	}
	if len(keys) != 1 || keys[0].Kid != "good" {
		t.Fatalf("want only the good key, got %+v", keys)
	}
}

func TestParsePublicKeySetRequiresOneUsableKey(t *testing.T) {
	for name, doc := range map[string][]byte{
		"empty keys array": []byte(`{"keys":[]}`),
		"not json":         []byte(`{`),
		"only bad entries": jwksDoc(t, map[string]any{"kty": "EC", "crv": "P-384", "x": "a", "y": "b"}),
		"no keys at all":   []byte(`{"something":"else"}`),
	} {
		if _, err := jwx.ParsePublicKeySet(doc); err == nil {
			t.Fatalf("%s: must fail when no usable key exists", name)
		}
	}
}

func TestParsePublicKeySetCollapsesExactDuplicates(t *testing.T) {
	key := mustKey(t)
	doc := jwksDoc(t, jwkMap(t, key, "dup"), jwkMap(t, key, "dup"))
	keys, err := jwx.ParsePublicKeySet(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("identical key+kid listed twice must collapse to one, got %d", len(keys))
	}

	// Same key under two different kids stays two registrations.
	doc = jwksDoc(t, jwkMap(t, key, "one"), jwkMap(t, key, "two"))
	keys, err = jwx.ParsePublicKeySet(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("same key with distinct kids must stay two entries, got %d", len(keys))
	}
}
