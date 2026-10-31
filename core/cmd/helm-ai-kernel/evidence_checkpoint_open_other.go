//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package main

import (
	"errors"
	"os"
)

// Never silently fall back to a blocking special-file open on another target.
func checkpointCLIPathInfo(string) (os.FileInfo, error) { return nil, errors.ErrUnsupported }
func checkpointCLIOpen(string) (*os.File, error)        { return nil, errors.ErrUnsupported }
