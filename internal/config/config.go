// Package config loads and validates the evidence-bundle manifest.
//
// The manifest is mounted read-only into the station (Docker Compose writes it
// with the keygen job or an operator supplies one) and declares, per bundle,
// one to eight numbered read-only evidence files together with their lowercase
// hex SHA-256 digests.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// File is one numbered, read-only evidence file.
type File struct {
	Number int    `json:"number"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Bundle is a named, ordered collection of 1..8 evidence files.
type Bundle struct {
	ID    string `json:"id"`
	Files []File `json:"files"`
}

// Config is the validated service configuration.
type Config struct {
	PublicOrigin string `json:"public_origin"`
	Issuer       string `json:"issuer"`
	Audience     string `json:"audience"`
	Subject      string `json:"subject"`
	IssuerJWK    string `json:"issuer_jwk_path"`
	// AccessLeeway tolerates clock skew when checking nbf/exp.
	AccessLeewaySec int `json:"access_leeway_seconds"`
	// DPoPMaxAgeSec rejects proofs older than this (short-lived proofs).
	DPoPMaxAgeSec int `json:"dpop_max_age_seconds"`
	// DPoPLeewaySec tolerates clock skew when checking proof iat.
	DPoPLeewaySec int `json:"dpop_leeway_seconds"`

	Bundles []Bundle `json:"bundles"`
}

// Load reads, parses and validates the manifest, and verifies every evidence
// file against its configured digest. Callers may apply environment overrides
// (see ApplyEnv) afterwards.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.PublicOrigin = strings.TrimRight(c.PublicOrigin, "/")
	if c.AccessLeewaySec == 0 {
		c.AccessLeewaySec = 30
	}
	if c.DPoPMaxAgeSec == 0 {
		c.DPoPMaxAgeSec = 60
	}
	if c.DPoPLeewaySec == 0 {
		c.DPoPLeewaySec = 30
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate runs the full configuration validation (identity + bundles +
// evidence digests).
func (c *Config) Validate() error { return c.validate() }

func (c *Config) validate() error {
	if c.PublicOrigin == "" {
		return fmt.Errorf("config: public_origin is required")
	}
	if !strings.HasPrefix(c.PublicOrigin, "https://") {
		return fmt.Errorf("config: public_origin must be an https URL")
	}
	if c.Issuer == "" {
		return fmt.Errorf("config: issuer is required")
	}
	if c.Audience == "" {
		return fmt.Errorf("config: audience is required")
	}
	if c.Subject == "" {
		return fmt.Errorf("config: subject is required")
	}
	if c.IssuerJWK == "" {
		return fmt.Errorf("config: issuer_jwk_path is required")
	}
	if c.DPoPMaxAgeSec <= 0 || c.DPoPMaxAgeSec > 600 {
		return fmt.Errorf("config: dpop_max_age_seconds must be in 1..600")
	}
	if len(c.Bundles) == 0 {
		return fmt.Errorf("config: at least one bundle is required")
	}
	ids := map[string]bool{}
	for bi := range c.Bundles {
		b := &c.Bundles[bi]
		if b.ID == "" {
			return fmt.Errorf("config: bundle #%d has empty id", bi+1)
		}
		if ids[b.ID] {
			return fmt.Errorf("config: duplicate bundle id %q", b.ID)
		}
		ids[b.ID] = true
		if len(b.Files) < 1 || len(b.Files) > 8 {
			return fmt.Errorf("config: bundle %q must contain 1..8 files, has %d", b.ID, len(b.Files))
		}
		seen := map[int]bool{}
		for fi := range b.Files {
			f := &b.Files[fi]
			if f.Number < 1 || f.Number > 8 {
				return fmt.Errorf("config: bundle %q file number must be 1..8, got %d", b.ID, f.Number)
			}
			if seen[f.Number] {
				return fmt.Errorf("config: bundle %q has duplicate file number %d", b.ID, f.Number)
			}
			seen[f.Number] = true
			if f.Path == "" {
				return fmt.Errorf("config: bundle %q file %d has empty path", b.ID, f.Number)
			}
			if len(f.SHA256) != 64 {
				return fmt.Errorf("config: bundle %q file %d sha256 must be 64 hex chars", b.ID, f.Number)
			}
			if f.SHA256 != strings.ToLower(f.SHA256) {
				return fmt.Errorf("config: bundle %q file %d sha256 must be lowercase hex", b.ID, f.Number)
			}
			if _, err := hex.DecodeString(f.SHA256); err != nil {
				return fmt.Errorf("config: bundle %q file %d sha256 is not hex: %w", b.ID, f.Number, err)
			}
			if err := verifyEvidenceFile(f); err != nil {
				return fmt.Errorf("config: bundle %q file %d: %w", b.ID, f.Number, err)
			}
		}
	}
	return nil
}

// verifyEvidenceFile ensures the evidence exists, is a regular non-symlink
// file, and matches the configured digest. Files are only ever opened O_RDONLY.
func verifyEvidenceFile(f *File) error {
	st, err := os.Lstat(f.Path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed", f.Path)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", f.Path)
	}
	// Bind mounts retain the source file's mode bits even when the mount itself
	// is read-only. Check the effective filesystem access instead so a Compose
	// :ro mount is accepted while a genuinely writable file is still rejected.
	if writable, err := os.OpenFile(f.Path, os.O_WRONLY, 0); err == nil {
		_ = writable.Close()
		return fmt.Errorf("%s: file must be read-only", f.Path)
	}
	fh, err := os.OpenFile(f.Path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != f.SHA256 {
		return fmt.Errorf("%s: digest mismatch: configured %s, on disk %s", f.Path, f.SHA256, got)
	}
	return nil
}

// Bundle returns the configured bundle with the given id.
func (c *Config) Bundle(id string) (*Bundle, bool) {
	for i := range c.Bundles {
		if c.Bundles[i].ID == id {
			return &c.Bundles[i], true
		}
	}
	return nil, false
}

// EnvOverride carries operator overrides supplied via environment variables.
type EnvOverride struct {
	PublicOrigin string
	Issuer       string
	Audience     string
	Subject      string
	IssuerJWK    string
}

// Apply overrides manifest identity fields with any non-empty environment
// values, then re-runs the identity validation.
func (c *Config) Apply(o EnvOverride) error {
	if o.PublicOrigin != "" {
		c.PublicOrigin = strings.TrimRight(o.PublicOrigin, "/")
	}
	if o.Issuer != "" {
		c.Issuer = o.Issuer
	}
	if o.Audience != "" {
		c.Audience = o.Audience
	}
	if o.Subject != "" {
		c.Subject = o.Subject
	}
	if o.IssuerJWK != "" {
		c.IssuerJWK = o.IssuerJWK
	}
	return c.validateIdentity()
}

func (c *Config) validateIdentity() error {
	if c.PublicOrigin == "" || !strings.HasPrefix(c.PublicOrigin, "https://") {
		return fmt.Errorf("public_origin must be a non-empty https URL")
	}
	switch {
	case c.Issuer == "":
		return fmt.Errorf("issuer is required")
	case c.Audience == "":
		return fmt.Errorf("audience is required")
	case c.Subject == "":
		return fmt.Errorf("subject is required")
	case c.IssuerJWK == "":
		return fmt.Errorf("issuer_jwk_path is required")
	}
	return nil
}
