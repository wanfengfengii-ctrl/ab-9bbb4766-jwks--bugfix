// Command keygen performs clean-station provisioning: it generates the
// registered ES256 issuer key (if none exists) and renders the validated
// bundle manifest, computing lowercase SHA-256 digests of the 1..8 numbered
// evidence files. It is a one-shot job: it exits 0 on success.
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"calibration-bundles/internal/config"
	"calibration-bundles/internal/minting"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	var (
		keysDir      = flag.String("keys-dir", envOr("KEYS_DIR", "/secrets/issuer"), "directory for the issuer JWK pair")
		configPath   = flag.String("config", envOr("CONFIG_PATH", "/etc/calibration/config.json"), "rendered manifest path")
		evidenceDir  = flag.String("evidence-dir", envOr("EVIDENCE_DIR", "/evidence"), "directory of numbered evidence files")
		bundleID     = flag.String("bundle-id", envOr("BUNDLE_ID", "B-2026-0042"), "bundle identifier")
		publicOrigin = flag.String("public-origin", envOr("PUBLIC_ORIGIN", "https://api.met-lab.example"), "public https origin used in htu")
		issuer       = flag.String("issuer", envOr("ISSUER", "https://issuer.met-lab.example"), "expected token issuer (iss)")
		audience     = flag.String("audience", envOr("AUDIENCE", "calibration-bundles-api"), "expected token audience (aud)")
		subject      = flag.String("subject", envOr("SUBJECT", "partner-lab-alpha"), "expected token subject (sub)")
	)
	flag.Parse()

	if !strings.HasPrefix(*publicOrigin, "https://") {
		log.Fatalf("public origin must be https, got %q", *publicOrigin)
	}

	_, pubPath, err := loadOrGenerateKey(*keysDir)
	if err != nil {
		log.Fatalf("issuer key: %v", err)
	}
	privPath := filepath.Join(*keysDir, "jwk-private.json")
	log.Printf("using registered issuer key: %s (private: %s)", pubPath, privPath)

	files, err := discoverEvidence(*evidenceDir)
	if err != nil {
		log.Fatalf("evidence: %v", err)
	}
	if len(files) < 1 || len(files) > 8 {
		log.Fatalf("evidence: need 1..8 numbered files, found %d", len(files))
	}

	cfg := config.Config{
		PublicOrigin:    strings.TrimRight(*publicOrigin, "/"),
		Issuer:          *issuer,
		Audience:        *audience,
		Subject:         *subject,
		IssuerJWK:       pubPath,
		AccessLeewaySec: 30,
		DPoPMaxAgeSec:   60,
		DPoPLeewaySec:   30,
		Bundles: []config.Bundle{{
			ID:    *bundleID,
			Files: files,
		}},
	}

	// Full validation (including digest verification and read-only checks)
	// before anything is written to the shared config volume.
	if err := cfg.Validate(); err != nil {
		log.Fatalf("rendered manifest invalid: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(*configPath), 0o755); err != nil {
		log.Fatalf("config dir: %v", err)
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatalf("encode config: %v", err)
	}
	if err := os.WriteFile(*configPath, append(out, '\n'), 0o644); err != nil {
		log.Fatalf("write config: %v", err)
	}
	log.Printf("manifest written to %s: bundle=%s files=%d", *configPath, *bundleID, len(files))
}

// discoverEvidence finds regular files whose names start with a two-digit
// number 01..08 (e.g. "01-report.txt"), hashes them, and requires the files to
// be regular files. Results are ordered by number and numbers must be unique.
// Config validation performs the effective read-only check after discovery;
// checking permission bits here would reject files on a read-only bind mount
// when their underlying host modes still contain write bits.
func discoverEvidence(dir string) ([]config.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type found struct {
		num  int
		path string
	}
	var items []found
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || len(name) < 2 {
			continue
		}
		n, err := strconv.Atoi(name[:2])
		if err != nil || name[2] != '-' || n < 1 || n > 8 {
			return nil, fmt.Errorf("file %q must be named NN-description with NN in 01..08", name)
		}
		items = append(items, found{n, filepath.Join(dir, name)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].num < items[j].num })

	var files []config.File
	seen := map[int]bool{}
	for _, it := range items {
		if seen[it.num] {
			return nil, fmt.Errorf("duplicate file number %02d", it.num)
		}
		seen[it.num] = true
		st, err := os.Lstat(it.path)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: must be a regular file (no symlinks)", it.path)
		}
		digest, err := hashFile(it.path)
		if err != nil {
			return nil, err
		}
		files = append(files, config.File{Number: it.num, Path: it.path, SHA256: digest})
	}
	return files, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// loadOrGenerateKey reuses an existing issuer key (idempotent re-deploys) or
// generates and persists a fresh P-256 pair on first run.
func loadOrGenerateKey(dir string) (*ecdsa.PrivateKey, string, error) {
	privPath := filepath.Join(dir, "jwk-private.json")
	if _, err := os.Stat(privPath); err == nil {
		key, err := minting.LoadPrivateKey(privPath)
		if err != nil {
			return nil, "", err
		}
		return key, filepath.Join(dir, "jwk.json"), nil
	} else if !os.IsNotExist(err) {
		return nil, "", err
	}
	key, err := minting.GenerateP256()
	if err != nil {
		return nil, "", err
	}
	pubPath, _, err := minting.SaveKeyPair(dir, key)
	if err != nil {
		return nil, "", err
	}
	return key, pubPath, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
