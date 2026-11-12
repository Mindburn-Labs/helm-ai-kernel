//go:build windows

package spendproxy

import (
	"errors"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive LockFileEx lock on path without waiting. The OS
// releases it when the handle closes, exit included.
func lockFile(path string) (func(), error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	var ol windows.Overlapped
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol); err != nil {
		_ = windows.CloseHandle(h)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errLocked
		}
		return nil, err
	}
	return func() {
		var unlock windows.Overlapped
		_ = windows.UnlockFileEx(h, 0, 1, 0, &unlock)
		_ = windows.CloseHandle(h)
	}, nil
}
