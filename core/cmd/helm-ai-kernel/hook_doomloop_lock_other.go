//go:build !unix && !windows

package main

import (
	"time"
)

// hookDoomLoopFlock has no OS advisory-lock primitive on this platform
// (e.g. plan9, js/wasm). The breaker update is skipped (advisory only);
// the authoritative fail-closed policy decision path is unaffected.
func hookDoomLoopFlock(lockPath string, deadline time.Time) (unlock func(), held bool, err error) {
	return nil, false, nil
}
