//go:build windows

package main

import "os"

// Windows ACL inspection requires a security-descriptor implementation. The
// portable directory mode and symlink checks still apply; this build does not
// claim the POSIX owner check on Windows.
func requireSetupAuthorityDirectoryOwner(_ string, _ os.FileInfo) error { return nil }
