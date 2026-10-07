//go:build !windows

package store

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock so only one server process can
// own a given replay log at a time (clean deployment / verification runs).
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
