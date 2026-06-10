//go:build !linux

package main

import (
	"errors"
	"net"
)

// originalDst is only implementable on Linux (SO_ORIGINAL_DST). On other platforms
// — e.g. macOS while running `go test` — it is a stub. The proxy itself only ever
// runs inside the Linux sidecar container.
func originalDst(_ *net.TCPConn) (string, error) {
	return "", errors.New("SO_ORIGINAL_DST is only supported on linux")
}
