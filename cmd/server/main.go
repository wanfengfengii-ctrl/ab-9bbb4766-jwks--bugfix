// Command calibration-server serves GET /api/calibration-bundles/{bundleId},
// gated by an ES256 access token and an ES256 DPoP sender-constrained proof.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"calibration-bundles/internal/config"
	"calibration-bundles/internal/server"
	"calibration-bundles/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	configPath := envOr("CONFIG_PATH", "/etc/calibration/config.json")
	replayDir := envOr("REPLAY_DIR", "/var/lib/calibration/replay")
	listenAddr := envOr("LISTEN_ADDR", ":8080")
	if port := os.Getenv("PORT"); port != "" && os.Getenv("LISTEN_ADDR") == "" {
		listenAddr = ":" + strings.TrimPrefix(port, ":")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("configuration invalid: %v", err)
	}
	if err := applyIdentityEnv(cfg); err != nil {
		log.Fatalf("configuration invalid: %v", err)
	}

	replay, err := store.Open(replayDir)
	if err != nil {
		log.Fatalf("replay store: %v", err)
	}
	defer replay.Close()

	srv, err := server.New(cfg, replay)
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("calibration-bundle server listening on %s (origin=%s, %d bundle(s), replay=%s)",
		listenAddr, cfg.PublicOrigin, len(cfg.Bundles), replayDir)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http server: %v", err)
	}
}

// applyIdentityEnv lets the isolated station inject deployment-specific values.
func applyIdentityEnv(cfg *config.Config) error {
	return cfg.Apply(config.EnvOverride{
		PublicOrigin: os.Getenv("PUBLIC_ORIGIN"),
		Issuer:       os.Getenv("ISSUER"),
		Audience:     os.Getenv("AUDIENCE"),
		Subject:      os.Getenv("SUBJECT"),
		IssuerJWK:    os.Getenv("ISSUER_JWK_PATH"),
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
