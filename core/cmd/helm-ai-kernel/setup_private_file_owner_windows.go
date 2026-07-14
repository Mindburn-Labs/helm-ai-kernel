//go:build windows

package main

import "os"

// Windows ownership and ACL verification requires a security-descriptor
// implementation. Keep the portable mode/symlink checks above and avoid
// asserting a POSIX ownership guarantee on this platform.
func requireSetupPrivateFileOwner(_ string, _ os.FileInfo) error { return nil }
