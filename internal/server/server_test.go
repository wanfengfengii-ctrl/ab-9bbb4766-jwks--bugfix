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

	issuer, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	pubPath, _, err := minting.SaveKeyPair(dir, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return newHarness(t, issuer, pubPath, dir)
}

// newHarness builds a serving harness around an already-provisioned issuer
// JWK document (bare JWK or JWKS) at jwkPath.
func newHarness(t *testing.T, issuer *ecdsa.PrivateKey, jwkPath, dir string) *harness {
	t.Helper()

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

	dpop, err := minting.GenerateP256()
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
		IssuerJWK:       jwkPath,
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
	return h.mintWithKid(jti, "")
}

func (h *harness) mintWithKid(jti, kid string) (token, proof string) {
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
	var err error
	token, err = jwx.SignCompact(header, payload, jwx.ES256Signer{Key: h.issuer})
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

// publicJWKEntry renders one JWKS entry for key, with an optional kid.
func publicJWKEntry(t *testing.T, key *ecdsa.PrivateKey, kid string) map[string]any {
	t.Helper()
	x, y := jwx.XY(&key.PublicKey)
	entry := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": jwx.Encode(x), "y": jwx.Encode(y),
	}
	if kid != "" {
		entry["kid"] = kid
	}
	return entry
}

// writeJWKS stores a {"keys":[...]} document and returns its path.
func writeJWKS(t *testing.T, dir string, entries ...map[string]any) string {
	t.Helper()
	doc, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(path, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// assertExactDownload requires a 200 response whose body and digest headers
// match the prepared evidence exactly.
func assertExactDownload(t *testing.T, h *harness, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body, _ := io.ReadAll(rr.Body)
	if string(body) != string(h.evidence) {
		t.Fatalf("evidence bytes mismatch: got %d bytes, want %d", len(body), len(h.evidence))
	}
	if got := rr.Header().Get("X-Bundle-SHA-256"); got != h.digest {
		t.Fatalf("X-Bundle-SHA-256 = %s, want %s", got, h.digest)
	}
	if !strings.HasPrefix(rr.Header().Get("Digest"), "sha-256=") {
		t.Fatalf("Digest header missing/wrong: %q", rr.Header().Get("Digest"))
	}
}

// The reported rotation scenario: the JWKS lists a valid but unused key
// first and the current signing key second; the caller signs with the second
// key and presents a correctly bound DPoP proof.
func TestJWKSRotationSigningKeyAtAnyPosition(t *testing.T) {
	for _, tc := range []struct {
		name        string
		issuerFirst bool
	}{
		{"signing key is second JWKS entry", false},
		{"signing key is first JWKS entry", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			issuer, err := minting.GenerateP256()
			if err != nil {
				t.Fatal(err)
			}
			unused, err := minting.GenerateP256()
			if err != nil {
				t.Fatal(err)
			}
			entries := []map[string]any{
				publicJWKEntry(t, unused, "standby"),
				publicJWKEntry(t, issuer, "current"),
			}
			if tc.issuerFirst {
				entries[0], entries[1] = entries[1], entries[0]
			}
			h := newHarness(t, issuer, writeJWKS(t, dir, entries...), dir)

			token, proof := h.mint("jti-rotation")
			assertExactDownload(t, h, h.get(token, proof, h.path))
		})
	}
}

func TestJWKSKidSelectsRegisteredKey(t *testing.T) {
	dir := t.TempDir()
	issuer, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	unused, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	jwksPath := writeJWKS(t, dir,
		publicJWKEntry(t, unused, "standby"),
		publicJWKEntry(t, issuer, "current"),
	)
	h := newHarness(t, issuer, jwksPath, dir)

	// A token carrying the registered kid verifies deterministically.
	token, proof := h.mintWithKid("jti-kid-ok", "current")
	assertExactDownload(t, h, h.get(token, proof, h.path))

	// An unknown kid is rejected with the existing invalid_token semantics.
	token, proof = h.mintWithKid("jti-kid-unknown", "no-such-key")
	rr := h.get(token, proof, h.path)
	if rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_token" {
		t.Fatalf("unknown kid: want 401 invalid_token, got %d %s", rr.Code, rr.Body.String())
	}

	// A kid that pins the non-signing registered key is rejected too.
	token, proof = h.mintWithKid("jti-kid-wrong", "standby")
	rr = h.get(token, proof, h.path)
	if rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_token" {
		t.Fatalf("kid of the non-signing key: want 401 invalid_token, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestSingleEntryJWKSStillServes(t *testing.T) {
	dir := t.TempDir()
	issuer, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	jwksPath := writeJWKS(t, dir, publicJWKEntry(t, issuer, "only"))
	h := newHarness(t, issuer, jwksPath, dir)

	token, proof := h.mint("jti-single")
	assertExactDownload(t, h, h.get(token, proof, h.path))
}

func TestJWKSDuplicateKidIsAmbiguous(t *testing.T) {
	dir := t.TempDir()
	issuer, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	other, err := minting.GenerateP256()
	if err != nil {
		t.Fatal(err)
	}
	// Two distinct keys registered under the same kid: not uniquely matchable.
	jwksPath := writeJWKS(t, dir,
		publicJWKEntry(t, issuer, "dup"),
		publicJWKEntry(t, other, "dup"),
	)
	h := newHarness(t, issuer, jwksPath, dir)

	token, proof := h.mintWithKid("jti-dup-kid", "dup")
	rr := h.get(token, proof, h.path)
	if rr.Code != http.StatusUnauthorized || errCode(rr.Body) != "invalid_token" {
		t.Fatalf("ambiguous kid: want 401 invalid_token, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestUnusableIssuerKeyDocumentFailsStartup(t *testing.T) {
	dir := t.TempDir()
	body := []byte("x")
	p := filepath.Join(dir, "01-a.txt")
	if err := os.WriteFile(p, body, 0o444); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(body)
	cfg := &config.Config{
		PublicOrigin:    "https://api.example.lab",
		Issuer:          "https://issuer.example.lab",
		Audience:        "calibration-bundles-api",
		Subject:         "partner-lab-alpha",
		IssuerJWK:       filepath.Join(dir, "broken.json"),
		AccessLeewaySec: 30,
		DPoPMaxAgeSec:   60,
		DPoPLeewaySec:   30,
		Bundles: []config.Bundle{{
			ID:    "B-1",
			Files: []config.File{{Number: 1, Path: p, SHA256: hex.EncodeToString(d[:])}},
		}},
	}
	if err := os.WriteFile(cfg.IssuerJWK, []byte(`{"keys":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	replay, err := store.Open(filepath.Join(dir, "replay"))
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	srv, err := server.New(cfg, replay)
	if err == nil || srv != nil {
		t.Fatal("a key document without any usable key must fail startup")
	}
}
