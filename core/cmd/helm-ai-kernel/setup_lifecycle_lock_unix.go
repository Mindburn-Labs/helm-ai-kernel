//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"fmt"
	"os"
	"syscall"
)

func lockSetupCodexProjectLifecycleFile(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another Codex project lifecycle operation is already in progress: %w", err)
	}
	return nil
}

func unlockSetupCodexProjectLifecycleFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
