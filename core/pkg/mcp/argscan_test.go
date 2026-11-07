package mcp

import (
	"time"
)

// fixedClock makes findings deterministic for snapshot-style assertions.
var fixedTime = time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

// helpers ---------------------------------------------------------------------

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func pathsOf(findings []ArgScanFinding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.ArgumentPath
	}
	return out
}
