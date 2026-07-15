//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package main

import "os"

// Platforms without the POSIX ownership API still receive strict regular-file,
// symlink, and 0600 checks from readSetupExistingPrivateFile.
func requireSetupPrivateFileOwner(_ string, _ os.FileInfo) error { return nil }
