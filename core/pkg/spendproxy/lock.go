package spendproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LockFileName is the lock file inside a receipts directory. A running proxy
// and a reconcile hold it for as long as they have the receipt log open, so a
// reconcile cannot append beside a live proxy and two proxies cannot spend one
// balance (helm-tracker#313 r2, finding 14). The OS drops the lock when its
// holder exits, crash included, so a stale file locks nothing.
const LockFileName = "spend-proxy.lock"

// errLocked reports a lock another process holds.
var errLocked = errors.New("locked")

// dirLock is a held receipts-directory lock.
type dirLock struct {
	once    sync.Once
	release func()
}

func (l *dirLock) Unlock() {
	if l != nil {
		l.once.Do(l.release)
	}
}

// lockReceiptsDir takes the receipts directory's lock without waiting.
func lockReceiptsDir(dir string) (*dirLock, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("spendproxy: create receipts dir: %w", err)
	}
	path := filepath.Join(dir, LockFileName)
	release, err := lockFile(path)
	if errors.Is(err, errLocked) {
		return nil, fmt.Errorf("spendproxy: another spend-proxy or reconcile holds the receipts directory %s (lock %s): stop it first", dir, path)
	}
	if err != nil {
		return nil, fmt.Errorf("spendproxy: lock the receipts directory: %w", err)
	}
	return &dirLock{release: release}, nil
}
