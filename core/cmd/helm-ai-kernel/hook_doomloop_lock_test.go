//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows

package main

import (
	"path/filepath"
	"testing"
	"time"
)

// This file is tagged to the platforms that have a real OS advisory-lock
// primitive. The same explicit flock-capable GOOS set is used by the
// agentruntime store lock; other platforms compile the documented no-op
// fallback, where these mutual-exclusion assertions do not hold.

// TestHookDoomLoopFlockMutualExclusion covers the lock ownership fix: while
// one holder holds the OS lock, a second acquisition within its deadline
// must report busy (not delete the live holder's lock); after release,
// acquisition succeeds again.
func TestHookDoomLoopFlockMutualExclusion(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "hook-doomloop.json.lock")

	unlock, held, err := hookDoomLoopFlock(lockPath, time.Now().Add(time.Second))
	if err != nil || !held {
		t.Fatalf("first acquire: held=%v err=%v", held, err)
	}

	// A second acquirer must not steal or delete the live lock.
	_, held2, err2 := hookDoomLoopFlock(lockPath, time.Now().Add(150*time.Millisecond))
	if err2 != nil {
		t.Fatalf("second acquire err: %v", err2)
	}
	if held2 {
		t.Fatal("second acquire must report busy while the first holder is live")
	}

	unlock()

	// After release the lock is acquirable again (no stale state).
	unlock3, held3, err3 := hookDoomLoopFlock(lockPath, time.Now().Add(time.Second))
	if err3 != nil || !held3 {
		t.Fatalf("re-acquire after release: held=%v err=%v", held3, err3)
	}
	unlock3()
}
