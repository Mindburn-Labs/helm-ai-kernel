//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package main

import "os"

// Platforms without the POSIX ownership API still receive strict directory
// type, symlink, and writable-mode checks from requireSetupAuthorityDirectory.
func requireSetupAuthorityDirectoryOwner(_ string, _ os.FileInfo) error { return nil }
