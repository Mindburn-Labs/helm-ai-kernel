//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package agentruntime

import (
	"os"
	"syscall"
)

// lockTurnFile takes an exclusive flock(2) on a per-turn lock file for the
// duration of one store operation. The in-process mutex only serializes goroutines
// inside a single Store; two Store values over the same directory — or two
// processes — would otherwise read the same head and assign the same Seq to
// different events, forking the hash chain permanently.
//
// The OS drops the lock when the holder's descriptor closes, including on
// crash, so there is no stale lock to reclaim and no ownership race of the
// kind a marker file has. The lock file is a sidecar: it holds no state, and
// deleting it between appends costs nothing.
//
// The call blocks until the lock is available. Append holds it for one
// read-modify-write; strict readers take it so they never inspect a partial
// append.
func lockTurnFile(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
