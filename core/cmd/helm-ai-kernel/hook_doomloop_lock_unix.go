//go:build !windows

package main

import (
	"os"
	"syscall"
	"time"
)

// hookDoomLoopFlock serializes doom-loop state updates with an flock(2)
// advisory lock. The OS releases the lock when the holder's process exits
// (even on crash), so there are no stale locks and no age-based reclaim
// that could delete a live holder's lock — the ownership race of marker-
// file locks is eliminated by construction. Returns (nil, false, nil) when
// the lock is busy past the deadline: callers treat the breaker update as
// skipped (advisory) and continue on the authoritative policy path.
func hookDoomLoopFlock(lockPath string, deadline time.Time) (unlock func(), held bool, err error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, true, nil
		}
		if err != syscall.EWOULDBLOCK || time.Now().After(deadline) {
			_ = f.Close()
			if err == syscall.EWOULDBLOCK {
				return nil, false, nil
			}
			return nil, false, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
