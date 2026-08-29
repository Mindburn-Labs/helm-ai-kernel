//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package skillpacks

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
)

// lockProjectionFile takes a non-blocking exclusive advisory lock. The
// persistent sidecar is never deleted, avoiding unlink/recreate split-brain and
// stale marker ownership races. Closing the descriptor releases the lock on
// process exit as well as the normal return path.
func lockProjectionFile(file *os.File) (func() error, error) {
	if file == nil {
		return nil, fmt.Errorf("skillpacks: projection root lock descriptor is required")
	}
	fd := int(file.Fd())
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("skillpacks: stat projection root lock: %w", err)
		}
		return nil, ErrProjectionPathUnsafe
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrProjectionLockContended
		}
		return nil, fmt.Errorf("skillpacks: lock projection root: %w", err)
	}
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			unlockErr := syscall.Flock(fd, syscall.LOCK_UN)
			closeErr := file.Close()
			releaseErr = errors.Join(unlockErr, closeErr)
		})
		return releaseErr
	}, nil
}
