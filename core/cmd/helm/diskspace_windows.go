//go:build windows

package main

import "fmt"

func availableDiskBytes(path string) (uint64, error) {
	return 0, fmt.Errorf("disk space check is not implemented for %s", path)
}
