//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"fmt"
	"os"
	"syscall"
)

// requireSetupPrivateFileOwner rejects a private key owned by another local
// account on POSIX hosts. Mode 0600 alone is insufficient when a different
// account owns the file and can later replace it.
func requireSetupPrivateFileOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine setup private file ownership: %s", path)
	}
	uid := os.Getuid()
	if uid >= 0 && stat.Uid != uint32(uid) {
		return fmt.Errorf("setup private file is not owned by the current user: %s", path)
	}
	return nil
}
