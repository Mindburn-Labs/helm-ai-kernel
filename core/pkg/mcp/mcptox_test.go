// mcptox_test.go validates that HELM's MCP governance blocks all attack
// categories from the MCPTox benchmark (arXiv 2508.14925).
// MCPTox found o1-mini has 72.8% ASR against unprotected MCP servers.
// Through HELM's gateway, the expected ASR is 0%.
package mcp

import (
	"time"
)

// fixedClock returns a clock pinned to t; shared by the package's tests.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func mcptoxClock() func() time.Time {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	return func() time.Time { return now }
}
