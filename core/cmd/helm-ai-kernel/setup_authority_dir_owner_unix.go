//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"fmt"
	"os"
	"syscall"
)

// requireSetupAuthorityDirectoryOwner rejects state directories owned by a
// different local account. Even without broad write permissions, that owner
// can replace a child or change its mode later.
func requireSetupAuthorityDirectoryOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine authority state directory ownership: %s", path)
	}
	uid := os.Getuid()
	if uid >= 0 && stat.Uid != uint32(uid) {
		return fmt.Errorf("authority state directory is not owned by the current user: %s", path)
	}
	return nil
}
