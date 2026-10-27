//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func checkpointCLIPathInfo(path string) (os.FileInfo, error) {
	// os.Lstat on Windows may defer the identity lookup until SameFile, which
	// would observe a replacement. Capture identity eagerly from a handle.
	f, err := checkpointCLIWindowsFile(path, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func checkpointCLIOpen(path string) (*os.File, error) {
	return checkpointCLIWindowsFile(path, windows.GENERIC_READ)
}

func checkpointCLIWindowsFile(path string, access uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("invalid local file path")
	}
	// Open the reparse point itself, never its target. CreateFile does not wait
	// for a busy pipe (there is no WaitNamedPipe); every pipe/device/reparse
	// handle is refused before any read. No OVERLAPPED handle is handed to os.
	h, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("local file unavailable")
	}
	kind, typeErr := windows.GetFileType(h)
	if typeErr != nil || kind != windows.FILE_TYPE_DISK {
		_ = windows.CloseHandle(h)
		return nil, errors.New("regular disk file required")
	}
	var info windows.ByHandleFileInformation
	infoErr := windows.GetFileInformationByHandle(h, &info)
	if infoErr != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(h)
		return nil, errors.New("regular non-reparse disk file required")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		_ = windows.CloseHandle(h)
		return nil, errors.New("local file handle unavailable")
	}
	return f, nil
}
