// Package server exposes the calibration-bundle download API.
package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"calibration-bundles/internal/auth"
	"calibration-bundles/internal/config"
	"calibration-bundles/internal/jwx"
	"calibration-bundles/internal/store"
)

// indexedFile is a validated evidence file in serving order.
type indexedFile struct {
	number int
	path   string
	size   int64
	digest string // lowercase hex sha-256
}

type preparedBundle struct {
	id        string
	files     []indexedFile
	totalSize int64
	digest    string // lowercase hex sha-256 of the concatenated evidence bytes
}

// Server holds the immutable, validated serving state.
type Server struct {
	cfg        *config.Config
	issuerKeys *auth.KeySet
	replay     *store.ReplayStore
	bundles    map[string]*preparedBundle

	healthy   atomic.Bool
	startedAt time.Time
	served    atomic.Int64
	rejected  atomic.Int64
}

// New validates the issuer key set, opens the durable replay log and prepares
// every configured bundle (sizes and digests) for serving.
func New(cfg *config.Config, replay *store.ReplayStore) (*Server, error) {
	raw, err := os.ReadFile(cfg.IssuerJWK)
	if err != nil {
		return nil, fmt.Errorf("load issuer jwk: %w", err)
	}
	registered, err := parseIssuerKeys(raw)
	if err != nil {
		return nil, err
	}
	keys, err := auth.NewKeySet(registered)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:        cfg,
		issuerKeys: keys,
		replay:     replay,
		bundles:    map[string]*preparedBundle{},
		startedAt:  time.Now().UTC(),
	}
	for i := range cfg.Bundles {
		pb, err := prepareBundle(&cfg.Bundles[i])
		if err != nil {
			return nil, err
		}
		s.bundles[pb.id] = pb
	}
	s.healthy.Store(true)
	return s, nil
}

// parseIssuerKeys accepts a bare JWK or a JWKS document {"keys":[...]}.
//
// Every key in a JWKS is registered with equal verification standing: token
// selection happens via the token header kid or, absent one, by trying every
// registered key, so the order of "keys" can never privilege a particular
// key. Each entry must be a valid P-256 EC public JWK; an unknown/invalid entry
// or an empty key set fails startup rather than being silently skipped.
func parseIssuerKeys(raw []byte) ([]auth.IssuerKey, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("registered issuer key: malformed JSON: %w", err)
	}
	var entries [][]byte
	if keysRaw, ok := probe["keys"]; ok {
		var wrap struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(keysRaw, &wrap.Keys); err != nil {
			return nil, fmt.Errorf("registered issuer keys: malformed keys array: %w", err)
		}
		if len(wrap.Keys) == 0 {
			return nil, errors.New("registered issuer keys: JWKS keys array is empty")
		}
		for _, k := range wrap.Keys {
			entries = append(entries, k)
		}
	} else {
		entries = [][]byte{raw}
	}

	out := make([]auth.IssuerKey, 0, len(entries))
	for i, e := range entries {
		pub, jwk, err := jwx.ParsePublicJWK(e)
		if err != nil {
			return nil, fmt.Errorf("registered issuer key #%d: %w", i+1, err)
		}
		out = append(out, auth.IssuerKey{KID: jwk.Kid, Key: pub})
	}
	return out, nil
}

func prepareBundle(b *config.Bundle) (*preparedBundle, error) {
	pb := &preparedBundle{id: b.ID}
	h := sha256.New()
	for i := range b.Files {
		f := &b.Files[i]
		st, err := os.Lstat(f.Path)
		if err != nil {
			return nil, err
		}
		fh, err := openReadOnly(f.Path)
		if err != nil {
			return nil, err
		}
		n, err := io.Copy(h, fh)
		fh.Close()
		if err != nil {
			return nil, err
		}
		pb.files = append(pb.files, indexedFile{
			number: f.Number, path: f.Path, size: st.Size(), digest: f.SHA256,
		})
		pb.totalSize += n
	}
	pb.digest = hex.EncodeToString(h.Sum(nil))
	return pb, nil
}

// Handler wires the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/calibration-bundles/{bundleId}", s.handleGet)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return logRequests(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.healthy.Load() {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	bundleID := r.PathValue("bundleId")
	pb, ok := s.bundles[bundleID]
	if !ok {
		s.writeError(w, r, &auth.Error{
			Code: auth.ErrorCode("bundle_not_found"), Status: http.StatusNotFound,
			Desc: "unknown calibration bundle id",
		})
		return
	}

	accessToken := bearerToken(r.Header.Get("Authorization"))
	if accessToken == "" {
		s.writeError(w, r, &auth.Error{
			Code: auth.CodeMalformed, Status: http.StatusUnauthorized,
			Desc: `missing or malformed Authorization header, expected 'DPoP <access-token>'`,
		})
		return
	}

	now := time.Now().UTC()
	decision, err := auth.Verify(accessToken, r.Header.Get("DPoP"), auth.Params{
		ExpectedIssuer:   s.cfg.Issuer,
		ExpectedAudience: s.cfg.Audience,
		ExpectedSubject:  s.cfg.Subject,
		IssuerKeys:       s.issuerKeys,
		PublicOrigin:     s.cfg.PublicOrigin,
		HTUPath:          r.URL.Path,
		Now:              now,
		AccessLeeway:     time.Duration(s.cfg.AccessLeewaySec) * time.Second,
		ProofMaxAge:      time.Duration(s.cfg.DPoPMaxAgeSec) * time.Second,
		ProofLeeway:      time.Duration(s.cfg.DPoPLeewaySec) * time.Second,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	// Open and lock the evidence bytes BEFORE consuming the single-use proof,
	// but send nothing until the durable claim has succeeded.
	readers := make([]*os.File, 0, len(pb.files))
	defer func() {
		for _, f := range readers {
			f.Close()
		}
	}()
	for _, f := range pb.files {
		fh, err := openReadOnly(f.path)
		if err != nil {
			s.writeError(w, r, &auth.Error{
				Code: auth.ErrorCode("evidence_unavailable"), Status: http.StatusInternalServerError,
				Desc: "evidence file could not be opened",
			})
			return
		}
		readers = append(readers, fh)
	}

	// Atomic, fsync'd single-use gate: exactly one concurrent request wins,
	// and the claim survives process restarts.
	if err := s.replay.Claim(decision.ProofJTI, now.Format(time.RFC3339Nano)); err != nil {
		code := auth.CodeReplay
		status := http.StatusConflict
		if !errorsIsReplay(err) {
			code = auth.ErrorCode("replay_store_failure")
			status = http.StatusServiceUnavailable
		}
		s.writeError(w, r, &auth.Error{Code: code, Status: status, Desc: err.Error()})
		return
	}

	headers := w.Header()
	headers.Set("Content-Type", "application/octet-stream")
	headers.Set("Content-Length", fmt.Sprintf("%d", pb.totalSize))
	headers.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.bin"`, pb.id))
	headers.Set("X-Bundle-Id", pb.id)
	headers.Set("X-Bundle-SHA-256", pb.digest)
	headers.Set("Digest", "sha-256="+base64Digest(pb.digest))
	headers.Set("ETag", `"`+pb.digest+`"`)
	headers.Set("Cache-Control", "no-store")
	for i, f := range pb.files {
		headers.Set(fmt.Sprintf("X-Evidence-SHA-256-%d", f.number), f.digest)
		_ = i
	}

	w.WriteHeader(http.StatusOK)
	for _, fh := range readers {
		if _, err := io.Copy(w, fh); err != nil {
			// Headers/body are already streaming; all we can do is log.
			log.Printf("stream interrupted for bundle %s: %v", pb.id, err)
			return
		}
	}
	s.served.Add(1)
	log.Printf("released bundle=%s bytes=%d sub=%s", pb.id, pb.totalSize, decision.Subject)
}

// bearerToken extracts the token from "DPoP <jwt>". The Bearer scheme is
// rejected because these tokens are DPoP-bound and must carry a proof.
func bearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "DPoP") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func base64Digest(hexDigest string) string {
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		return ""
	}
	return jwx.Encode(raw)
}

func errorsIsReplay(err error) bool { return err == store.ErrReplay }

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	s.rejected.Add(1)
	ae, ok := auth.AsError(err)
	if !ok {
		ae = &auth.Error{Code: auth.ErrorCode("server_error"), Status: http.StatusInternalServerError, Desc: err.Error()}
	}
	body, _ := json.Marshal(map[string]string{
		"error":             string(ae.Code),
		"error_description": ae.Desc,
	})
	if ae.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`DPoP realm="calibration-bundles", error="%s", error_description=%q`,
				ae.Code, ae.Desc))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ae.Status)
	_, _ = w.Write(body)
	log.Printf("reject %s %s -> %d %s (%s)", r.Method, r.URL.Path, ae.Status, ae.Code, ae.Desc)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s remote=%s duration=%s", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start).Round(time.Millisecond))
	})
}
