//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package skillpacks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// lockProjectionFile takes a non-blocking exclusive advisory lock. The
// persistent sidecar is never deleted, avoiding unlink/recreate split-brain and
// stale marker ownership races. Closing the descriptor releases the lock on
// process exit as well as the normal return path.
func lockProjectionFile(path string) (func() error, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- path is derived from the validated projection root
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrProjectionPathUnsafe
		}
		return nil, fmt.Errorf("skillpacks: open projection root lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("skillpacks: open projection root lock descriptor")
	}
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
	if err := syncProjectionDirectory(filepath.Dir(path)); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("skillpacks: sync projection root lock parent: %w", err)
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
