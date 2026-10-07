//go:build windows

package server

import "os"

func openReadOnly(path string) (*os.File, error) { return os.Open(path) }
