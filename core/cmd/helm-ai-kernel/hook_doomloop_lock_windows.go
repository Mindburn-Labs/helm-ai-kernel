//go:build windows

package main

import (
	"time"

	"golang.org/x/sys/windows"
)

// hookDoomLoopFlock is the Windows equivalent of the unix flock guard: an
// OS-level byte-range exclusive lock via LockFileEx. The OS releases the
// lock when the holder's handle closes (including process exit/crash), so
// there are no stale locks and no age-based reclaim that could delete a
// live holder's lock. Returns (nil, false, nil) when the lock is busy past
// the deadline: callers treat the breaker update as skipped (advisory).
func hookDoomLoopFlock(lockPath string, deadline time.Time) (unlock func(), held bool, err error) {
	pathPtr, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, false, err
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, false, err
	}
	var ol windows.Overlapped
	for {
		err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
		if err == nil {
			return func() {
				var unlockOl windows.Overlapped
				_ = windows.UnlockFileEx(h, 0, 1, 0, &unlockOl)
				_ = windows.CloseHandle(h)
			}, true, nil
		}
		if errno, ok := err.(windows.Errno); !ok || errno != windows.ERROR_LOCK_VIOLATION || time.Now().After(deadline) {
			_ = windows.CloseHandle(h)
			if errno, ok := err.(windows.Errno); ok && errno == windows.ERROR_LOCK_VIOLATION {
				return nil, false, nil
			}
			return nil, false, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}
