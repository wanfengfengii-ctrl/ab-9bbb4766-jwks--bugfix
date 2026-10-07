// Package store implements the durable single-use proof registry.
//
// Every accepted DPoP proof jti is appended to an fsync'd write-ahead log
// before the request is allowed. The log is replayed at startup, so a proof
// that was used once can never be used again, even after a process restart or
// under concurrent requests (claiming is atomic under a single mutex).
package store

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ReplayStore is a durable set of consumed proof identifiers.
type ReplayStore struct {
	mu   sync.Mutex
	path string
	f    *os.File
	used map[string]struct{}
}

// Open opens (creating if needed) the write-ahead log and loads all entries.
func Open(dir string) (*ReplayStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("replay dir: %w", err)
	}
	path := filepath.Join(dir, "used-jti.log")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open replay log: %w", err)
	}
	s := &ReplayStore{path: path, f: f, used: map[string]struct{}{}}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("replay log already locked by another server process: %w", err)
	}
	if err := s.load(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

func (s *ReplayStore) load() error {
	if _, err := s.f.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind replay log: %w", err)
	}
	sc := bufio.NewScanner(s.f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "<hex-hash> <unix-ts-ms> <optional jti-prefix>"; key on hash.
		key := line
		if i := strings.IndexByte(line, ' '); i >= 0 {
			key = line[:i]
		}
		s.used[key] = struct{}{}
		n++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read replay log: %w", err)
	}
	if _, err := s.f.Seek(0, 2); err != nil {
		return fmt.Errorf("append-position replay log: %w", err)
	}
	return nil
}

// ErrReplay is returned when the identifier has already been consumed.
var ErrReplay = errors.New("proof already used")

// Claim atomically records jti. It returns ErrReplay if it was (or is being,
// after the lock is released) recorded before. The write is fsync'd before the
// method returns, so concurrent callers see an all-or-nothing winner and a
// process crash cannot resurrect a used proof.
func (s *ReplayStore) Claim(jti string, meta string) error {
	sum := sha256.Sum256([]byte(jti))
	key := hex.EncodeToString(sum[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.used[key]; ok {
		return ErrReplay
	}
	line := fmt.Sprintf("%s %s\n", key, meta)
	if _, err := s.f.WriteString(line); err != nil {
		return fmt.Errorf("append replay log: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("fsync replay log: %w", err)
	}
	s.used[key] = struct{}{}
	return nil
}

// Consumed reports whether jti is in the set (used by health/tests).
func (s *ReplayStore) Consumed(jti string) bool {
	sum := sha256.Sum256([]byte(jti))
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.used[key]
	return ok
}

// Close flushes and closes the log.
func (s *ReplayStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.f.Sync(); err != nil {
		return err
	}
	return s.f.Close()
}
