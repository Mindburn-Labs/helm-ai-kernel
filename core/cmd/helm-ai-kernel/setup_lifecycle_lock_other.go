//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package main

import (
	"fmt"
	"os"
)

func lockSetupCodexProjectLifecycleFile(_ *os.File) error {
	return fmt.Errorf("safe cross-process Codex project lifecycle locking is unavailable on this platform")
}

func unlockSetupCodexProjectLifecycleFile(_ *os.File) error { return nil }
