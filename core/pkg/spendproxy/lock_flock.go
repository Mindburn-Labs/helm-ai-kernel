//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package spendproxy

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive flock(2) on path without waiting. The lock
// belongs to the open file, so a second open in the same process conflicts as
// well.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errLocked
		}
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
