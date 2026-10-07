//go:build !windows

package server

import (
	"os"
	"syscall"
)

// openReadOnly opens a regular file read-only and refuses to traverse a
// symlink (evidence must be a direct regular file; config already Lstat's it).
func openReadOnly(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
