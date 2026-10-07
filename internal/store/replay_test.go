package store_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"calibration-bundles/internal/store"
)

func TestClaimIsSingleUseAndPersistent(t *testing.T) {
	dir := t.TempDir()

	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Claim("proof-1", "now"); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := s.Claim("proof-1", "now"); err != store.ErrReplay {
		t.Fatalf("second claim want ErrReplay, got %v", err)
	}
	if !s.Consumed("proof-1") {
		t.Fatal("Consumed must report true")
	}
	if s.Consumed("proof-2") {
		t.Fatal("unknown proof must not be consumed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: the consumed set must survive (simulates a restart).
	s2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Claim("proof-1", "now"); err != store.ErrReplay {
		t.Fatalf("after restart, claim want ErrReplay, got %v", err)
	}
	if err := s2.Claim("proof-2", "now"); err != nil {
		t.Fatalf("fresh proof after restart: %v", err)
	}

	// Log is one record per claim.
	raw, err := os.ReadFile(filepath.Join(dir, "used-jti.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range raw {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Fatalf("replay log should hold 2 durable records, got %d", lines)
	}
}

func TestConcurrentClaimsHaveExactlyOneWinner(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const n = 100
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners, replays := 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := s.Claim("hot-proof", "now")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners++
			} else if err == store.ErrReplay {
				replays++
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners != 1 || replays != n-1 {
		t.Fatalf("want 1 winner / %d replays, got %d / %d", n-1, winners, replays)
	}
}

func TestSecondOpenSameDirIsLocked(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s2, err := store.Open(dir)
	if err == nil {
		_ = s2.Close()
		t.Fatal("second Open of the same replay log must fail (flock held by first)")
	}
}
