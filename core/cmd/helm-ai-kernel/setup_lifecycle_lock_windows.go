//go:build windows

package main

import (
	"fmt"
	"os"
)

// The portable standard library does not expose a Windows equivalent of the
// advisory Unix flock used by the local authority lifecycle. Failing closed is
// preferable to claiming cross-process transaction serialization we cannot
// establish.
func lockSetupCodexProjectLifecycleFile(_ *os.File) error {
	return fmt.Errorf("safe cross-process Codex project lifecycle locking is unavailable on Windows")
}

func unlockSetupCodexProjectLifecycleFile(_ *os.File) error { return nil }
