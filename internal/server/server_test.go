package server_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"calibration-bundles/internal/config"
	"calibration-bundles/internal/jwx"
	"calibration-bundles/internal/minting"
	"calibration-bundles/internal/server"
	"calibration-bundles/internal/store"
)

type harness struct {
	t        *testing.T
	handler  http.Handler
	issuer   *ecdsa.PrivateKey
	dpop     *ecdsa.PrivateKey
	origin   string
	path     string
	cfg      *config.Config
	evidence []byte
	digest   string
}

func setup(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()

	body1 := []byte("calibration-report\n")
	body2 := []byte{0x00, 0x01, 0x02, 0xFF}
	p1 := filepath.Join(dir, "01-report.txt")
	p2 := filepath.Join(dir, "02-data.bin")
	if err := os.WriteFile(p1, body1, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, body2, 0o444); err != nil {
		t.Fatal(err)
	}

	issuer, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	dpop, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	pubPath, _, err := minting.SaveKeyPair(dir, issuer)
	if err != nil {
		t.Fatal(err)
	}

	evidence := append(append([]byte{}, body1...), body2...)
	sum := sha256.Sum256(evidence)
	d1 := sha256.Sum256(body1)

	cfg := &config.Config{
		PublicOrigin:    "https://api.example.lab",
		Issuer:          "https://issuer.example.lab",
		Audience:        "calibration-bundles-api",
		Subject:         "partner-lab-alpha",
		IssuerJWK:       pubPath,
		AccessLeewaySec: 30,
		DPoPMaxAgeSec:   60,
		DPoPLeewaySec:   30,
		Bundles: []config.Bundle{{
			ID: "B-1",
			Files: []config.File{
				{Number: 1, Path: p1, SHA256: hex.EncodeToString(d1[:])},
				{Number: 2, Path: p2, SHA256: func() string {
					d := sha256.Sum256(body2)
					return hex.EncodeToString(d[:])
				}()},
			},
		}},
	}

	replay, err := store.Open(filepath.Join(dir, "replay"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replay.Close() })

	srv, err := server.New(cfg, replay)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{
		t: t, handler: srv.Handler(),
		issuer: issuer, dpop: dpop,
		origin: cfg.PublicOrigin, path: "/api/calibration-bundles/B-1",
		cfg: cfg, evidence: evidence, digest: hex.EncodeToString(sum[:]),
	}
}

func (h *harness) mint(jti string) (token, proof string) {
	now := time.Now().UTC()
	x, y := jwx.XY(&h.dpop.PublicKey)
	jkt := jwx.ThumbprintB64(x, y)
	payload, _ := json.Marshal(map[string]any{
		"iss":   h.cfg.Issuer,
		"sub":   h.cfg.Subject,
		"aud":   h.cfg.Audience,
		"iat":   now.Add(-5 * time.Second).Unix(),
		"exp":   now.Add(2 * time.Minute).Unix(),
		"scope": "bundles:read",
		"cnf":   map[string]any{"jkt": jkt},
	})
	var err error
	token, err = jwx.SignCompact(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		payload, jwx.ES256Signer{Key: h.issuer})
	if err != nil {
		h.t.Fatal(err)
	}
	proof, err = minting.MintDPoPProof(h.dpop, minting.DPoPClaims{
		HTM: "GET", HTU: h.origin + h.path, ATH: minting.ATH(token),
		JTI: jti, IssuedAt: now,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return token, proof
}

func (h *harness) get(token, proof, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "DPoP "+token)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

func errCode(body io.Reader) string {
	raw, _ := io.ReadAll(body)
	var env struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	return env.Error
}

func TestHappyPathServesExactBytesAndDigestHeaders(t *testing.T) {
	h := setup(t)
	token, proof := h.mint("jti-1")
	rr := h.get(token, proof, h.path)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body, _ := io.ReadAll(rr.Body)
	if string(body) != string(h.evidence) {
		t.Fatalf("evidence bytes mismatch: got %d bytes, want %d", len(body), len(h.evidence))
	}
	if got := rr.Header().Get("X-Bundle-SHA-256"); got != h.digest {
		t.Fatalf("bundle digest header = %s, want %s", got, h.digest)
	}
	d1 := sha256.Sum256([]byte("calibration-report\n"))
	if got := rr.Header().Get("X-Evidence-SHA-256-1"); got != hex.EncodeToString(d1[:]) {
		t.Fatalf("per-file digest header wrong: %s", got)
	}
	if !strings.HasPrefix(rr.Header().Get("Digest"), "sha-256=") {
		t.Fatalf("Digest header missing/wrong: %q", rr.Header().Get("Digest"))
	}
	if rr.Header().Get("Content-Length") != "23" {
		t.Fatalf("content-length = %s, want 23", rr.Header().Get("Content-Length"))
	}
}

func TestReplaySecondUseRejected(t *testing.T) {
	h := setup(t)
	token, proof := h.mint("jti-once")
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusOK {
		t.Fatalf("first use: want 200, got %d %s", rr.Code, rr.Body.String())
	}
	rr := h.get(token, proof, h.path)
	if rr.Code != http.StatusConflict {
		t.Fatalf("second use: want 409, got %d", rr.Code)
	}
	if errCode(rr.Body) != "replay_detected" {
		t.Fatalf("want replay_detected, got %s", rr.Body.String())
	}
}

func TestConcurrentSingleRelease(t *testing.T) {
	h := setup(t)
	token, proof := h.mint("jti-hot")
	const n = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, conflict, other := 0, 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rr := h.get(token, proof, h.path)
			mu.Lock()
			defer mu.Unlock()
			switch rr.Code {
			case http.StatusOK:
				ok++
			case http.StatusConflict:
				conflict++
			default:
				other++
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok != 1 || conflict != n-1 || other != 0 {
		t.Fatalf("want exactly 1 release and %d conflicts, got ok=%d conflict=%d other=%d",
			n-1, ok, conflict, other)
	}
}

func TestMissingAndBadCredentials(t *testing.T) {
	h := setup(t)
	rr := h.get("", "", h.path)
	if rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "malformed_request" {
		t.Fatalf("no creds: %d %s", rr.Code, rr.Body.String())
	}
	token, _ := h.mint("jti-x")
	rr = h.get(token, "", h.path)
	if rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_dpop_proof" {
		t.Fatalf("no proof: %d %s", rr.Code, rr.Body.String())
	}
}

func TestUnknownBundle(t *testing.T) {
	h := setup(t)
	token, _ := h.mint("jti-y")
	now := time.Now().UTC()
	pr, err := minting.MintDPoPProof(h.dpop, minting.DPoPClaims{
		HTM: "GET", HTU: h.origin + "/api/calibration-bundles/nope",
		ATH: minting.ATH(token), JTI: "jti-nope", IssuedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := h.get(token, pr, "/api/calibration-bundles/nope")
	if rr.Code != http.StatusNotFound || errCode(rr.Body) != "bundle_not_found" {
		t.Fatalf("want 404 bundle_not_found, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestHealth(t *testing.T) {
	h := setup(t)
	rr := h.get("", "", "/healthz")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ok"`) {
		t.Fatalf("health: %d %s", rr.Code, rr.Body.String())
	}
}

// ---------------- JWKS key rotation ----------------

// jwksHarness is a server backed by a hand-authored issuer JWKS, with the
// private half of each registered key available for minting.
type jwksHarness struct {
	*harness
	signers map[string]*ecdsa.PrivateKey
}

func publicJWKMap(k *ecdsa.PrivateKey, kid string) map[string]any {
	x, y := jwx.XY(&k.PublicKey)
	m := map[string]any{"kty": "EC", "crv": "P-256", "x": jwx.Encode(x), "y": jwx.Encode(y)}
	if kid != "" {
		m["kid"] = kid
	}
	return m
}

func setupJWKS(t *testing.T, entries []map[string]any, signers map[string]*ecdsa.PrivateKey) *jwksHarness {
	t.Helper()
	dir := t.TempDir()

	body1 := []byte("calibration-report\n")
	p1 := filepath.Join(dir, "01-report.txt")
	if err := os.WriteFile(p1, body1, 0o444); err != nil {
		t.Fatal(err)
	}
	d1 := sha256.Sum256(body1)

	jwksPath := filepath.Join(dir, "jwks.json")
	jwks, _ := json.Marshal(map[string]any{"keys": entries})
	if err := os.WriteFile(jwksPath, jwks, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		PublicOrigin:    "https://api.example.lab",
		Issuer:          "https://issuer.example.lab",
		Audience:        "calibration-bundles-api",
		Subject:         "partner-lab-alpha",
		IssuerJWK:       jwksPath,
		AccessLeewaySec: 30,
		DPoPMaxAgeSec:   60,
		DPoPLeewaySec:   30,
		Bundles: []config.Bundle{{
			ID:    "B-1",
			Files: []config.File{{Number: 1, Path: p1, SHA256: hex.EncodeToString(d1[:])}},
		}},
	}
	replay, err := store.Open(filepath.Join(dir, "replay"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replay.Close() })
	srv, err := server.New(cfg, replay)
	if err != nil {
		t.Fatal(err)
	}
	dpop, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body1)
	return &jwksHarness{
		harness: &harness{
			t: t, handler: srv.Handler(), dpop: dpop, cfg: cfg,
			origin: cfg.PublicOrigin, path: "/api/calibration-bundles/B-1",
			evidence: body1, digest: hex.EncodeToString(sum[:]),
		},
		signers: signers,
	}
}

// mintWith signs the access token with signer, optionally adding a kid header.
func (h *jwksHarness) mintWith(signer *ecdsa.PrivateKey, kid, jti string) (string, string) {
	now := time.Now().UTC()
	x, y := jwx.XY(&h.dpop.PublicKey)
	jkt := jwx.ThumbprintB64(x, y)
	payload, _ := json.Marshal(map[string]any{
		"iss":   h.cfg.Issuer,
		"sub":   h.cfg.Subject,
		"aud":   h.cfg.Audience,
		"iat":   now.Add(-5 * time.Second).Unix(),
		"exp":   now.Add(2 * time.Minute).Unix(),
		"scope": "bundles:read",
		"cnf":   map[string]any{"jkt": jkt},
	})
	header := map[string]any{"alg": "ES256", "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	token, err := jwx.SignCompact(header, payload, jwx.ES256Signer{Key: signer})
	if err != nil {
		h.t.Fatal(err)
	}
	proof, err := minting.MintDPoPProof(h.dpop, minting.DPoPClaims{
		HTM: "GET", HTU: h.origin + h.path, ATH: minting.ATH(token),
		JTI: jti, IssuedAt: now,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return token, proof
}

func TestJWKSSecondKeySucceeds(t *testing.T) {
	other, _ := minting.GenerateP256()
	current, _ := minting.GenerateP256()
	// First entry is an unrelated but valid key; the signing key is second.
	h := setupJWKS(t,
		[]map[string]any{
			publicJWKMap(other, "rotated-out"),
			publicJWKMap(current, "current"),
		},
		map[string]*ecdsa.PrivateKey{"other": other, "current": current})

	token, proof := h.mintWith(current, "", "jti-second")
	rr := h.get(token, proof, h.path)
	if rr.Code != http.StatusOK {
		t.Fatalf("token signed by second JWKS key: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body, _ := io.ReadAll(rr.Body)
	if string(body) != string(h.evidence) {
		t.Fatalf("evidence bytes mismatch")
	}
	if got := rr.Header().Get("X-Bundle-SHA-256"); got != h.digest {
		t.Fatalf("digest header = %s, want %s", got, h.digest)
	}
}

func TestJWKSOrderDoesNotMatter(t *testing.T) {
	key1, _ := minting.GenerateP256()
	key2, _ := minting.GenerateP256()
	entries := []map[string]any{publicJWKMap(key2, "k2"), publicJWKMap(key1, "k1")}
	h := setupJWKS(t, entries, map[string]*ecdsa.PrivateKey{"k1": key1, "k2": key2})
	for name, signer := range map[string]*ecdsa.PrivateKey{"first entry": key2, "second entry": key1} {
		token, proof := h.mintWith(signer, "", "jti-order-"+name)
		if rr := h.get(token, proof, h.path); rr.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d: %s", name, rr.Code, rr.Body.String())
		}
	}
}

func TestJWKSKidSelection(t *testing.T) {
	key1, _ := minting.GenerateP256()
	key2, _ := minting.GenerateP256()
	h := setupJWKS(t,
		[]map[string]any{publicJWKMap(key1, "k1"), publicJWKMap(key2, "k2")},
		map[string]*ecdsa.PrivateKey{"k1": key1, "k2": key2})

	// kid deterministically selects the key even though the token could
	// otherwise verify without one.
	token, proof := h.mintWith(key2, "k2", "jti-kid2")
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusOK {
		t.Fatalf("kid k2: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// kid pinned to k1 but signed by k2: signature must be rejected.
	token, proof = h.mintWith(key2, "k1", "jti-kid-mismatch")
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_token" {
		t.Fatalf("kid/signing key mismatch: want 401 invalid_token, got %d %s", rr.Code, rr.Body.String())
	}
	// Unknown kid is rejected, never falling back to a verifying key.
	token, proof = h.mintWith(key2, "nope", "jti-unknown-kid")
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_token" {
		t.Fatalf("unknown kid: want 401 invalid_token, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestJWKSAmbiguousKidRejected(t *testing.T) {
	key1, _ := minting.GenerateP256()
	key2, _ := minting.GenerateP256()
	h := setupJWKS(t,
		[]map[string]any{publicJWKMap(key1, "dup"), publicJWKMap(key2, "dup")},
		nil)
	token, proof := h.mintWith(key2, "dup", "jti-ambiguous")
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_token" {
		t.Fatalf("ambiguous kid: want 401 invalid_token, got %d %s", rr.Code, rr.Body.String())
	}
	// Without kid, both distinct keys remain usable: order-independent trust.
	token, proof = h.mintWith(key2, "", "jti-ambiguous-nokid")
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusOK {
		t.Fatalf("no kid against set with duplicate kids: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestJWKSSingleEntryAndBareJWK(t *testing.T) {
	key, _ := minting.GenerateP256()
	// Single-entry JWKS.
	h := setupJWKS(t, []map[string]any{publicJWKMap(key, "only")}, map[string]*ecdsa.PrivateKey{"only": key})
	token, proof := h.mintWith(key, "only", "jti-single")
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusOK {
		t.Fatalf("single-entry JWKS: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestJWKSBareJWK(t *testing.T) {
	key, _ := minting.GenerateP256()
	dir := t.TempDir()
	body := []byte("calibration-report\n")
	p := filepath.Join(dir, "01-report.txt")
	if err := os.WriteFile(p, body, 0o444); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(body)
	barePath := filepath.Join(dir, "jwk.json")
	bare, _ := json.Marshal(publicJWKMap(key, ""))
	if err := os.WriteFile(barePath, bare, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		PublicOrigin: "https://api.example.lab", Issuer: "https://issuer.example.lab",
		Audience: "calibration-bundles-api", Subject: "partner-lab-alpha",
		IssuerJWK: barePath, AccessLeewaySec: 30, DPoPMaxAgeSec: 60, DPoPLeewaySec: 30,
		Bundles: []config.Bundle{{ID: "B-1", Files: []config.File{{Number: 1, Path: p, SHA256: hex.EncodeToString(d[:])}}}},
	}
	replay, err := store.Open(filepath.Join(dir, "replay"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replay.Close() })
	srv, err := server.New(cfg, replay)
	if err != nil {
		t.Fatal(err)
	}
	dpop, _ := minting.GenerateP256()
	base := &harness{t: t, handler: srv.Handler(), dpop: dpop, cfg: cfg,
		origin: cfg.PublicOrigin, path: "/api/calibration-bundles/B-1"}
	jh := &jwksHarness{harness: base, signers: map[string]*ecdsa.PrivateKey{"bare": key}}
	token, proof := jh.mintWith(key, "", "jti-bare")
	if rr := jh.get(token, proof, jh.path); rr.Code != http.StatusOK {
		t.Fatalf("bare JWK: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestJWKSForeignAndInvalidSignatures(t *testing.T) {
	good, _ := minting.GenerateP256()
	other, _ := minting.GenerateP256()
	h := setupJWKS(t, []map[string]any{publicJWKMap(good, "good")}, map[string]*ecdsa.PrivateKey{"good": good})

	// Token signed by an unregistered key.
	token, proof := h.mintWith(other, "", "jti-foreign")
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_token" {
		t.Fatalf("foreign key: want 401 invalid_token, got %d %s", rr.Code, rr.Body.String())
	}
	// Registered key signs, then signature bytes are corrupted.
	token, proof = h.mintWith(good, "", "jti-corrupt")
	parts := strings.Split(token, ".")
	token = parts[0] + "." + parts[1] + "." + jwx.Encode(make([]byte, 64))
	// Re-bind the proof ath to the tampered token so the failure is the signature.
	x, y := jwx.XY(&h.dpop.PublicKey)
	_ = x
	_ = y
	now := time.Now().UTC()
	proof, _ = minting.MintDPoPProof(h.dpop, minting.DPoPClaims{
		HTM: "GET", HTU: h.origin + h.path, ATH: minting.ATH(token),
		JTI: "jti-corrupt-proof", IssuedAt: now,
	})
	if rr := h.get(token, proof, h.path); rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_token" {
		t.Fatalf("corrupt signature: want 401 invalid_token, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestParseIssuerKeysRejectsBadJWKS(t *testing.T) {
	// These invalid shapes must surface as a startup error; they are exercised
	// through server.New, which is the public entry point.
	cases := map[string][]byte{
		"empty keys":            []byte(`{"keys":[]}`),
		"bad curve":             []byte(`{"keys":[{"kty":"EC","crv":"P-384","x":"AAAA","y":"BBBB"}]}`),
		"not json":              []byte(`{nope`),
		"malformed key element": []byte(`{"keys":["not-an-object"]}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "issuer.json")
			if err := os.WriteFile(p, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			body := []byte("x")
			ep := filepath.Join(dir, "01.txt")
			if err := os.WriteFile(ep, body, 0o444); err != nil {
				t.Fatal(err)
			}
			d := sha256.Sum256(body)
			cfg := &config.Config{
				PublicOrigin: "https://api.example.lab", Issuer: "i", Audience: "a", Subject: "s",
				IssuerJWK: p, AccessLeewaySec: 30, DPoPMaxAgeSec: 60, DPoPLeewaySec: 30,
				Bundles: []config.Bundle{{ID: "B", Files: []config.File{{Number: 1, Path: ep, SHA256: hex.EncodeToString(d[:])}}}},
			}
			replay, err := store.Open(filepath.Join(dir, "replay"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = replay.Close() })
			if _, err := server.New(cfg, replay); err == nil {
				t.Fatalf("%s: invalid JWKS must fail server init", name)
			}
		})
	}
}
