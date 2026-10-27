//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func checkpointCLIPathInfo(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func checkpointCLIOpen(path string) (*os.File, error) {
	// O_NONBLOCK prevents a raced FIFO from waiting for a writer. O_NOFOLLOW
	// refuses a substituted leaf symlink. The caller validates the opened FD's
	// type, size and captured identity before reading; that also refuses an
	// ancestor redirect to a different file. Ancestor path trust stays local.
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
}
