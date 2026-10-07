package config_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"calibration-bundles/internal/config"
)

func writeEvidence(t *testing.T, dir string, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseManifest(t *testing.T, dir string, files []config.File) *config.Config {
	return &config.Config{
		PublicOrigin:    "https://api.example",
		Issuer:          "issuer",
		Audience:        "aud",
		Subject:         "sub",
		IssuerJWK:       filepath.Join(dir, "jwk.json"),
		AccessLeewaySec: 10,
		DPoPMaxAgeSec:   60,
		DPoPLeewaySec:   10,
		Bundles:         []config.Bundle{{ID: "B1", Files: files}},
	}
}

func writeManifest(t *testing.T, c *config.Config) string {
	t.Helper()
	if err := os.WriteFile(c.IssuerJWK, []byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(filepath.Dir(c.IssuerJWK), "config.json")
	b, _ := json.Marshal(c)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestValidManifestAccepted(t *testing.T) {
	dir := t.TempDir()
	content := "evidence-body"
	p := writeEvidence(t, dir, "01-a.txt", content, 0o444)
	c := baseManifest(t, dir, []config.File{{Number: 1, Path: p, SHA256: digestOf(content)}})
	path := writeManifest(t, c)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if got := loaded.Bundles[0].Files[0].SHA256; got != digestOf(content) {
		t.Fatalf("digest round-trip mismatch")
	}
}

func TestManifestValidation(t *testing.T) {
	content := "x"
	cases := []struct {
		name string
		mut  func(dir string, c *config.Config)
	}{
		{"public origin must be https", func(dir string, c *config.Config) { c.PublicOrigin = "http://insecure" }},
		{"file count below 1", func(dir string, c *config.Config) { c.Bundles[0].Files = nil }},
		{"file count above 8", func(dir string, c *config.Config) {
			c.Bundles[0].Files = nil
			for i := 1; i <= 9; i++ {
				p := writeEvidence(t, dir, fmt.Sprintf("%02d-f", i), content, 0o444)
				c.Bundles[0].Files = append(c.Bundles[0].Files,
					config.File{Number: i, Path: p, SHA256: digestOf(content)})
			}
		}},
		{"duplicate number", func(dir string, c *config.Config) {
			c.Bundles[0].Files = append(c.Bundles[0].Files, c.Bundles[0].Files[0])
		}},
		{"number out of range", func(dir string, c *config.Config) {
			c.Bundles[0].Files[0].Number = 9
		}},
		{"uppercase digest", func(dir string, c *config.Config) {
			c.Bundles[0].Files[0].SHA256 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		}},
		{"digest mismatch", func(dir string, c *config.Config) {
			c.Bundles[0].Files[0].SHA256 = digestOf("different")
		}},
		{"writable file rejected", func(dir string, c *config.Config) {
			_ = os.Chmod(c.Bundles[0].Files[0].Path, 0o644)
		}},
		{"symlink rejected", func(dir string, c *config.Config) {
			target := c.Bundles[0].Files[0].Path
			link := filepath.Join(dir, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			c.Bundles[0].Files[0].Path = link
		}},
		{"duplicate bundle id", func(dir string, c *config.Config) {
			c.Bundles = append(c.Bundles, c.Bundles[0])
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := writeEvidence(t, dir, "01-a.txt", content, 0o444)
			c := baseManifest(t, dir, []config.File{{Number: 1, Path: p, SHA256: digestOf(content)}})
			tc.mut(dir, c)
			path := writeManifest(t, c)
			if _, err := config.Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
