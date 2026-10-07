// Command verify is the one-shot station acceptance service.
//
// It waits for the calibration server to become healthy, then:
//  1. runs the Go unit tests and a clean build ("code tests, build");
//  2. performs a byte-exact evidence download with full header checks;
//  3. exercises signature/binding/time/replay tampering with stable error
//     codes;
//  4. fires concurrent requests sharing one legitimate proof and asserts a
//     single release;
//  5. starts a second server process against the durable replay log (real
//     restart) and proves previously used proofs still cannot be replayed.
//
// It prints a PASS/FAIL manifest and exits 0 only when every check passed.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"calibration-bundles/internal/config"
	"calibration-bundles/internal/jwx"
	"calibration-bundles/internal/minting"
)

type report struct {
	mu     sync.Mutex
	failed int
	total  int
}

func (r *report) check(name string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++
	if err != nil {
		r.failed++
		log.Printf("FAIL  %s: %v", name, err)
	} else {
		log.Printf("PASS  %s", name)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	var (
		baseURL    = flag.String("base-url", envOr("BASE_URL", "http://calibration-server:8080"), "server base URL")
		cfgPath    = flag.String("config", envOr("CONFIG_PATH", "/etc/calibration/config.json"), "manifest path")
		issuerPriv = flag.String("issuer-key", envOr("ISSUER_KEY", "/secrets/issuer/jwk-private.json"), "issuer private JWK")
		srcDir     = flag.String("src-dir", envOr("SRC_DIR", "/app/src"), "module source dir for go test/build")
		serverBin  = flag.String("server-bin", envOr("SERVER_BIN", "/usr/local/bin/calibration-server"), "server binary for restart test")
		skipGo     = flag.Bool("skip-go", os.Getenv("SKIP_GO") == "1", "skip go test/build phases")
	)
	flag.Parse()

	rep := &report{}

	// ---- Phase 1: code tests + build, before touching the network ----
	if !*skipGo {
		runGoPhase(rep, *srcDir)
	} else {
		log.Printf("SKIP  go test/build (SKIP_GO=1)")
	}

	// ---- Load the same manifest the server uses ----
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("cannot load manifest %s: %v", *cfgPath, err)
	}
	if len(cfg.Bundles) == 0 {
		log.Fatal("manifest declares no bundles")
	}
	bundle := &cfg.Bundles[0]
	expected, expectedDigest, perFile, err := expectedBytes(bundle)
	if err != nil {
		log.Fatalf("prepare expected bytes: %v", err)
	}

	issuerKey, err := minting.LoadPrivateKey(*issuerPriv)
	if err != nil {
		log.Fatalf("load issuer key: %v", err)
	}
	dpopKey, err := minting.GenerateP256()
	if err != nil {
		log.Fatalf("generate dpop key: %v", err)
	}
	jkt := minting.JKT(dpopKey)
	otherKey, _ := minting.GenerateP256()
	otherJKT := minting.JKT(otherKey)

	// ---- Phase 2: wait for health ----
	if err := waitHealthy(*baseURL+"/healthz", 60*time.Second); err != nil {
		log.Fatalf("server did not become healthy: %v", err)
	}
	log.Printf("server healthy at %s", *baseURL)

	s := &smoke{
		cfg:       cfg,
		base:      strings.TrimRight(*baseURL, "/"),
		origin:    cfg.PublicOrigin,
		issuerKey: issuerKey,
		dpopKey:   dpopKey,
		jkt:       jkt,
		otherKey:  otherKey,
		otherJKT:  otherJKT,
		client:    &http.Client{Timeout: 15 * time.Second},
		bundleID:  bundle.ID,
		expected:  expected,
		digest:    expectedDigest,
		perFile:   perFile,
	}

	// ---- Phase 3: happy-path byte-exact download + digest headers ----
	rep.check("download returns byte-identical evidence", s.happyPath())

	// ---- Phase 4: tampering matrix -> stable error codes ----
	s.tamperMatrix(rep)

	// ---- Evidence files are immutable on the station ----
	rep.check("evidence file cannot be modified (read-only)", s.evidenceIsReadOnly())

	// ---- Phase 5: concurrent replay, exactly one release ----
	rep.check("one proof is released exactly once under concurrency", s.concurrentReplay())

	// A fresh, distinct proof is a fresh legitimate download; replaying it
	// afterwards must fail.
	rep.check("fresh proof works once, replay is rejected", s.freshThenReplay())

	// ---- Phase 6: real process restart, durable non-replay ----
	rep.check("used proof cannot be replayed after server restart",
		s.restartPersistence(*serverBin, *cfgPath))

	log.Printf("----- verify summary: %d/%d checks passed -----", rep.total-rep.failed, rep.total)
	if rep.failed != 0 {
		log.Fatalf("VERIFY FAILED: %d check(s) failed", rep.failed)
	}
	log.Printf("VERIFY OK")
}

// ----------------------------- go phase -----------------------------

func runGoPhase(rep *report, src string) {
	if _, err := exec.LookPath("go"); err != nil {
		rep.check("go toolchain available", fmt.Errorf("go not found in PATH"))
		return
	}
	rep.check("go toolchain available", nil)

	cache, _ := os.MkdirTemp("", "gocache-")
	goEnv := append(os.Environ(),
		"GOCACHE="+cache,
		"GOFLAGS=-mod=mod",
		"GOPROXY=off",
		"GOTOOLCHAIN=local",
		"CGO_ENABLED=0",
	)
	test := exec.Command("go", "test", "-buildvcs=false", "./...")
	test.Dir = src
	test.Env = goEnv
	if out, err := test.CombinedOutput(); err != nil {
		rep.check("go test ./...", fmt.Errorf("%w\n%s", err, trim(out)))
	} else {
		rep.check("go test ./...", nil)
		log.Print(string(out))
	}

	build := exec.Command("go", "build", "-buildvcs=false", "-o", filepath.Join(cache, "calibration-server"), "./cmd/server")
	build.Dir = src
	build.Env = goEnv
	if out, err := build.CombinedOutput(); err != nil {
		rep.check("go build ./cmd/server", fmt.Errorf("%w\n%s", err, trim(out)))
	} else {
		rep.check("go build ./cmd/server", nil)
	}
}

func trim(b []byte) string {
	const max = 4000
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}

// ----------------------------- smoke rig -----------------------------

type smoke struct {
	cfg       *config.Config
	base      string
	origin    string
	issuerKey *ecdsa.PrivateKey
	dpopKey   *ecdsa.PrivateKey
	jkt       string
	otherKey  *ecdsa.PrivateKey
	otherJKT  string
	client    *http.Client

	bundleID string
	expected []byte
	digest   string
	perFile  map[int]string
}

type respInfo struct {
	status int
	code   string
	body   []byte
	header http.Header
}

func (s *smoke) bundlePath(id string) string {
	return "/api/calibration-bundles/" + id
}

func (s *smoke) doGet(token, proof, path string) (*respInfo, error) {
	req, err := http.NewRequest(http.MethodGet, s.base+path, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "DPoP "+token)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	info := &respInfo{status: resp.StatusCode, body: body, header: resp.Header.Clone()}
	var envelope struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &envelope)
	info.code = envelope.Error
	return info, nil
}

func (s *smoke) token(now time.Time, jkt string, mutate func(m map[string]any), signKey *ecdsa.PrivateKey) (string, error) {
	claims := map[string]any{
		"iss":   s.cfg.Issuer,
		"sub":   s.cfg.Subject,
		"aud":   s.cfg.Audience,
		"iat":   now.Add(-10 * time.Second).Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"scope": "bundles:read",
		"cnf":   map[string]any{"jkt": jkt},
	}
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jwx.SignCompact(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		payload, jwx.ES256Signer{Key: signKey})
}

func (s *smoke) validToken(now time.Time) (string, error) {
	return s.token(now, s.jkt, nil, s.issuerKey)
}

// proofSpec describes one DPoP proof to sign.
type proofSpec struct {
	key      *ecdsa.PrivateKey
	jti      string
	iat      time.Time
	htm      string
	path     string // request path joined onto configured public origin
	ath      string // explicit ath override; "" -> derive from token
	alg      string // signing header alg (always signed with key, even if lying)
	typ      string
	noJWK    bool
	expUnix  *int64
	signKey  *ecdsa.PrivateKey // key used for signature (defaults to key)
	unsigned bool              // emit empty signature
}

func (s *smoke) proof(token string, sp proofSpec) (string, error) {
	now := time.Now().UTC()
	if sp.jti == "" {
		sp.jti = newJTI()
	}
	if sp.iat.IsZero() {
		sp.iat = now
	}
	if sp.htm == "" {
		sp.htm = "GET"
	}
	if sp.path == "" {
		sp.path = s.bundlePath(s.bundleID)
	}
	ath := sp.ath
	if ath == "" {
		ath = minting.ATH(token)
	}
	alg := sp.alg
	if alg == "" {
		alg = "ES256"
	}
	typ := sp.typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	key := sp.key
	if key == nil {
		key = s.dpopKey
	}
	signKey := sp.signKey
	if signKey == nil {
		signKey = key
	}
	x, y := jwx.XY(&key.PublicKey)
	header := map[string]any{"alg": alg, "typ": typ}
	if !sp.noJWK {
		header["jwk"] = map[string]any{
			"kty": "EC", "crv": "P-256",
			"x": jwx.Encode(x), "y": jwx.Encode(y),
		}
	}
	claims := map[string]any{
		"htm": sp.htm,
		"htu": s.origin + sp.path,
		"jti": sp.jti,
		"ath": ath,
		"iat": sp.iat.Unix(),
	}
	if sp.expUnix != nil {
		claims["exp"] = *sp.expUnix
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	h := jwx.Encode(hb)
	p := jwx.Encode(pb)
	if sp.unsigned {
		return h + "." + p + ".", nil
	}
	sig, err := jwx.ES256Signer{Key: signKey}.Sign([]byte(h + "." + p))
	if err != nil {
		return "", err
	}
	return h + "." + p + "." + jwx.Encode(sig), nil
}

// ----------------------------- phases -----------------------------

func (s *smoke) happyPath() error {
	now := time.Now().UTC()
	tok, err := s.validToken(now)
	if err != nil {
		return err
	}
	pr, err := s.proof(tok, proofSpec{})
	if err != nil {
		return err
	}
	info, err := s.doGet(tok, pr, s.bundlePath(s.bundleID))
	if err != nil {
		return err
	}
	if info.status != 200 {
		return fmt.Errorf("want 200, got %d (%s): %s", info.status, info.code, info.body)
	}
	if !bytes.Equal(info.body, s.expected) {
		return fmt.Errorf("body mismatch: got %d bytes, want %d bytes", len(info.body), len(s.expected))
	}
	if got := info.header.Get("X-Bundle-SHA-256"); got != s.digest {
		return fmt.Errorf("X-Bundle-SHA-256 = %q, want %q", got, s.digest)
	}
	raw, _ := hex.DecodeString(s.digest)
	if want := "sha-256=" + jwx.Encode(raw); info.header.Get("Digest") != want {
		return fmt.Errorf("Digest = %q, want %q", info.header.Get("Digest"), want)
	}
	if got := info.header.Get("Content-Length"); got != fmt.Sprintf("%d", len(s.expected)) {
		return fmt.Errorf("Content-Length = %q, want %d", got, len(s.expected))
	}
	nums := make([]int, 0, len(s.perFile))
	for n := range s.perFile {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for _, n := range nums {
		hdr := fmt.Sprintf("X-Evidence-SHA-256-%d", n)
		if got := info.header.Get(hdr); got != s.perFile[n] {
			return fmt.Errorf("%s = %q, want %q", hdr, got, s.perFile[n])
		}
	}
	return nil
}

func (s *smoke) tamperMatrix(rep *report) {
	now := time.Now().UTC()
	path := s.bundlePath(s.bundleID)

	type expect struct {
		status int
		code   string
	}
	wantInvalidToken := expect{401, "invalid_token"}

	// helper for token variants
	withToken := func(mutate func(m map[string]any), signKey *ecdsa.PrivateKey) (string, error) {
		if signKey == nil {
			signKey = s.issuerKey
		}
		return s.token(now, s.jkt, mutate, signKey)
	}

	cases := []struct {
		name string
		run  func() (*respInfo, error)
		want expect
	}{
		{
			name: "no credentials",
			run:  func() (*respInfo, error) { return s.doGet("", "", path) },
			want: expect{401, "malformed_request"},
		},
		{
			name: "no DPoP proof header",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				return s.doGet(tok, "", path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "Bearer scheme rejected (proof-bound token)",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{})
				req, _ := http.NewRequest(http.MethodGet, s.base+path, nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("DPoP", pr)
				return s.roundTrip(req)
			},
			want: expect{401, "malformed_request"},
		},
		{
			name: "access token signed by foreign key",
			run: func() (*respInfo, error) {
				tok, _ := withToken(nil, s.otherKey)
				pr, _ := s.proof(tok, proofSpec{})
				return s.doGet(tok, pr, path)
			},
			want: wantInvalidToken,
		},
		{
			name: "garbled access token signature",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				parts := strings.Split(tok, ".")
				tok = parts[0] + "." + parts[1] + "." + jwx.Encode(make([]byte, 64))
				pr, _ := s.proof(tok, proofSpec{})
				return s.doGet(tok, pr, path)
			},
			want: wantInvalidToken,
		},
		{
			name: "wrong issuer",
			run: func() (*respInfo, error) {
				tok, _ := withToken(func(m map[string]any) { m["iss"] = "https://rogue.example" }, nil)
				pr, _ := s.proof(tok, proofSpec{})
				return s.doGet(tok, pr, path)
			},
			want: wantInvalidToken,
		},
		{
			name: "wrong audience",
			run: func() (*respInfo, error) {
				tok, _ := withToken(func(m map[string]any) { m["aud"] = "some-other-api" }, nil)
				pr, _ := s.proof(tok, proofSpec{})
				return s.doGet(tok, pr, path)
			},
			want: wantInvalidToken,
		},
		{
			name: "wrong subject",
			run: func() (*respInfo, error) {
				tok, _ := withToken(func(m map[string]any) { m["sub"] = "intruder" }, nil)
				pr, _ := s.proof(tok, proofSpec{})
				return s.doGet(tok, pr, path)
			},
			want: wantInvalidToken,
		},
		{
			name: "missing bundles:read scope",
			run: func() (*respInfo, error) {
				tok, _ := withToken(func(m map[string]any) { m["scope"] = "bundles:admin" }, nil)
				pr, _ := s.proof(tok, proofSpec{})
				return s.doGet(tok, pr, path)
			},
			want: expect{403, "insufficient_scope"},
		},
		{
			name: "expired access token",
			run: func() (*respInfo, error) {
				tok, _ := withToken(func(m map[string]any) {
					m["iat"] = now.Add(-2 * time.Hour).Unix()
					m["exp"] = now.Add(-1 * time.Hour).Unix()
				}, nil)
				pr, _ := s.proof(tok, proofSpec{})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "expired_token"},
		},
		{
			name: "token cnf.jkt binds a different key",
			run: func() (*respInfo, error) {
				tok, _ := s.token(now, s.otherJKT, nil, s.issuerKey)
				pr, _ := s.proof(tok, proofSpec{})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof signed by a different key than its jwk",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{key: s.dpopKey, signKey: s.otherKey})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof typ is not dpop+jwt",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{typ: "JWT"})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof alg none rejected",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{alg: "none", unsigned: true})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof missing embedded jwk",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{noJWK: true})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof jti missing",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{jti: " "})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof iat too old (beyond short lifetime)",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{iat: now.Add(-10 * time.Minute)})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof iat in the future",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{iat: now.Add(10 * time.Minute)})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof htm POST instead of GET",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{htm: "POST"})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof htu has trailing slash",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{path: path + "/"})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof htu uses internal host instead of configured public origin",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				// Hand-built proof whose htu points at the internal base URL.
				pr, err := s.proofWithHTU(tok, s.base+path)
				if err != nil {
					return nil, err
				}
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "proof ath binds a different token",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				other, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{ath: minting.ATH(other)})
				return s.doGet(tok, pr, path)
			},
			want: expect{401, "invalid_dpop_proof"},
		},
		{
			name: "replay of a previously consumed proof",
			run: func() (*respInfo, error) {
				tok, _ := s.validToken(now)
				pr, _ := s.proof(tok, proofSpec{jti: newJTI()})
				first, err := s.doGet(tok, pr, path)
				if err != nil {
					return nil, err
				}
				if first.status != 200 {
					return nil, fmt.Errorf("seed request should succeed, got %d %s", first.status, first.code)
				}
				return s.doGet(tok, pr, path)
			},
			want: expect{409, "replay_detected"},
		},
		{
			name: "unknown bundle id",
			run: func() (*respInfo, error) {
				return s.doGet("", "", s.bundlePath("does-not-exist"))
			},
			want: expect{404, "bundle_not_found"},
		},
	}

	for _, tc := range cases {
		info, err := tc.run()
		if err != nil {
			rep.check("tamper: "+tc.name, fmt.Errorf("request error: %w", err))
			continue
		}
		if info.status != tc.want.status || info.code != tc.want.code {
			rep.check("tamper: "+tc.name, fmt.Errorf("want %d/%s, got %d/%s (%s)",
				tc.want.status, tc.want.code, info.status, info.code, info.body))
		} else {
			rep.check("tamper: "+tc.name, nil)
		}
	}
}

func (s *smoke) proofWithHTU(token, htu string) (string, error) {
	x, y := jwx.XY(&s.dpopKey.PublicKey)
	header := map[string]any{
		"alg": "ES256", "typ": "dpop+jwt",
		"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": jwx.Encode(x), "y": jwx.Encode(y)},
	}
	claims := map[string]any{
		"htm": "GET",
		"htu": htu,
		"jti": newJTI(),
		"ath": minting.ATH(token),
		"iat": time.Now().UTC().Unix(),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	h := jwx.Encode(hb)
	p := jwx.Encode(pb)
	sig, err := jwx.ES256Signer{Key: s.dpopKey}.Sign([]byte(h + "." + p))
	if err != nil {
		return "", err
	}
	return h + "." + p + "." + jwx.Encode(sig), nil
}

func (s *smoke) roundTrip(req *http.Request) (*respInfo, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	info := &respInfo{status: resp.StatusCode, body: body, header: resp.Header.Clone()}
	var envelope struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &envelope)
	info.code = envelope.Error
	return info, nil
}

func (s *smoke) evidenceIsReadOnly() error {
	f := s.cfg.Bundles[0].Files[0]
	fh, err := os.OpenFile(f.Path, os.O_WRONLY, 0)
	if err == nil {
		fh.Close()
		return fmt.Errorf("%s was opened for writing: evidence must be immutable", f.Path)
	}
	return nil
}

func (s *smoke) concurrentReplay() error {
	const n = 32
	now := time.Now().UTC()
	tok, err := s.validToken(now)
	if err != nil {
		return err
	}
	// One single legitimate proof shared by every concurrent request.
	sharedJTI := newJTI()
	proof, err := s.proof(tok, proofSpec{jti: sharedJTI})
	if err != nil {
		return err
	}
	path := s.bundlePath(s.bundleID)

	var wg sync.WaitGroup
	var mu sync.Mutex
	ok200, replay409, other, byteOK := 0, 0, 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			info, err := s.doGet(tok, proof, path)
			if err != nil {
				mu.Lock()
				other++
				mu.Unlock()
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case info.status == 200:
				ok200++
				if bytes.Equal(info.body, s.expected) {
					byteOK++
				}
			case info.status == 409 && info.code == "replay_detected":
				replay409++
			default:
				other++
				log.Printf("unexpected concurrent status: %d %s %s", info.status, info.code, info.body)
			}
		}()
	}
	close(start)
	wg.Wait()

	if ok200 != 1 {
		return fmt.Errorf("exactly one request must succeed, got %d (409=%d, other=%d)", ok200, replay409, other)
	}
	if replay409 != n-1 || other != 0 {
		return fmt.Errorf("remaining %d requests must be replay_detected, got 409=%d other=%d", n-1, replay409, other)
	}
	if byteOK != 1 {
		return fmt.Errorf("winning response bytes did not match the evidence")
	}
	// Immediate sequential replay of the same proof also fails.
	again, err := s.doGet(tok, proof, path)
	if err != nil {
		return err
	}
	if again.status != 409 || again.code != "replay_detected" {
		return fmt.Errorf("post-race replay want 409/replay_detected, got %d/%s", again.status, again.code)
	}
	return nil
}

func (s *smoke) freshThenReplay() error {
	now := time.Now().UTC()
	tok, _ := s.validToken(now)
	pr, _ := s.proof(tok, proofSpec{})
	path := s.bundlePath(s.bundleID)

	first, err := s.doGet(tok, pr, path)
	if err != nil {
		return err
	}
	if first.status != 200 || !bytes.Equal(first.body, s.expected) {
		return fmt.Errorf("fresh proof: want 200 + exact bytes, got %d/%s", first.status, first.code)
	}
	second, err := s.doGet(tok, pr, path)
	if err != nil {
		return err
	}
	if second.status != 409 || second.code != "replay_detected" {
		return fmt.Errorf("replay: want 409/replay_detected, got %d/%s", second.status, second.code)
	}
	return nil
}

// restartPersistence starts a private server instance on a spare port with a
// fresh durable replay directory, performs one download, stops the process
// (true crash/restart semantics), starts it again with the same directory, and
// verifies the old proof is still rejected while a new proof succeeds once.
func (s *smoke) restartPersistence(bin, cfgPath string) error {
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("server binary %s unavailable: %w", bin, err)
	}
	replayDir, err := os.MkdirTemp("", "restart-replay-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(replayDir)
	port := freeTCPPort()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	start := func() (*os.Process, error) {
		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(),
			"CONFIG_PATH="+cfgPath,
			"REPLAY_DIR="+replayDir,
			fmt.Sprintf("LISTEN_ADDR=:%d", port),
		)
		var logBuf lineLog
		cmd.Stdout = &logBuf
		cmd.Stderr = &logBuf
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		if err := waitHealthy(base+"/healthz", 30*time.Second); err != nil {
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("restarted instance unhealthy: %w; logs: %s", err, logBuf.String())
		}
		return cmd.Process, nil
	}
	stop := func(p *os.Process) {
		_ = p.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = p.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.Kill()
			<-done
		}
	}

	proc, err := start()
	if err != nil {
		return fmt.Errorf("first instance: %w", err)
	}

	now := time.Now().UTC()
	tok, err := s.validToken(now)
	if err != nil {
		stop(proc)
		return err
	}
	jti := newJTI()
	pr, err := s.proof(tok, proofSpec{jti: jti})
	if err != nil {
		stop(proc)
		return err
	}

	// Download once against the first instance using a one-off client pointed
	// at the private port.
	privateClient := &smoke{
		cfg: s.cfg, base: base, origin: s.origin,
		client: &http.Client{Timeout: 10 * time.Second},
	}
	info, err := privateClient.doGet(tok, pr, s.bundlePath(s.bundleID))
	if err != nil {
		stop(proc)
		return fmt.Errorf("download before restart: %w", err)
	}
	if info.status != 200 {
		stop(proc)
		return fmt.Errorf("download before restart: want 200, got %d %s", info.status, info.code)
	}
	stop(proc)

	// Restart: new process, same durable replay directory.
	proc2, err := start()
	if err != nil {
		return fmt.Errorf("second instance: %w", err)
	}
	defer stop(proc2)

	info, err = privateClient.doGet(tok, pr, s.bundlePath(s.bundleID))
	if err != nil {
		return fmt.Errorf("replay after restart: %w", err)
	}
	if info.status != 409 || info.code != "replay_detected" {
		return fmt.Errorf("after restart: want 409/replay_detected, got %d/%s", info.status, info.code)
	}

	// A genuinely new proof on the restarted process works exactly once.
	fresh, err := s.proof(tok, proofSpec{})
	if err != nil {
		return err
	}
	info, err = privateClient.doGet(tok, fresh, s.bundlePath(s.bundleID))
	if err != nil {
		return err
	}
	if info.status != 200 || !bytes.Equal(info.body, s.expected) {
		return fmt.Errorf("fresh proof after restart: want 200 + exact bytes, got %d/%s", info.status, info.code)
	}
	info, err = privateClient.doGet(tok, fresh, s.bundlePath(s.bundleID))
	if err != nil {
		return err
	}
	if info.status != 409 || info.code != "replay_detected" {
		return fmt.Errorf("fresh proof's replay after restart: want 409, got %d/%s", info.status, info.code)
	}
	return nil
}

// ----------------------------- helpers -----------------------------

func expectedBytes(b *config.Bundle) ([]byte, string, map[int]string, error) {
	ordered := make([]config.File, len(b.Files))
	copy(ordered, b.Files)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Number < ordered[j].Number })
	h := sha256.New()
	perFile := map[int]string{}
	var buf bytes.Buffer
	for _, f := range ordered {
		raw, err := os.ReadFile(f.Path)
		if err != nil {
			return nil, "", nil, err
		}
		buf.Write(raw)
		h.Write(raw)
		perFile[f.Number] = f.SHA256
	}
	return buf.Bytes(), hex.EncodeToString(h.Sum(nil)), perFile, nil
}

func waitHealthy(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), `"ok"`) {
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s: %v", url, lastErr)
}

func newJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "verify-" + hex.EncodeToString(b)
}

func freeTCPPort() int {
	// net.Listen would be simpler but avoid importing net just for the port
	// probe; bind on :0 via a tiny HTTP-free listener.
	l, err := listen()
	if err != nil {
		return 18080 + int(time.Now().UnixNano()%1000)
	}
	addr := l.Addr().String()
	_ = l.Close()
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		var p int
		fmt.Sscanf(addr[i+1:], "%d", &p)
		if p != 0 {
			return p
		}
	}
	return 18080
}

type lineLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		log.Printf("  [restarted] %s", line)
		l.buf.WriteString(line)
		l.buf.WriteByte('\n')
	}
	return len(p), nil
}
func (l *lineLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
