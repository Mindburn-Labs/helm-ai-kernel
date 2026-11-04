// Package mcp provides MCP server integration with governance.
//
// argscan.go implements detection of shell-injection, SSRF, and related
// injection patterns in MCP tool-call arguments (as opposed to docscan.go
// which scans tool descriptions/metadata).
//
// CVE basis: MIN-178 Radar entry.
//   - CVE-2026-5058 (AWS MCP, CVSS 9.8) — pre-auth RCE via shell-injection in
//     tool arguments.
//   - Aggregate MCP CVE taxonomy (Doyensec / Vulnerable MCP Project, Q1 2026):
//     ~43% of MCP server vulnerabilities are shell-injection variants.
//   - Supporting CVEs on SSRF / path traversal share the same input surface.
//
// Design invariants (matches docscan.go):
//   - Scans tool-call argument values (strings + nested JSON).
//   - Deterministic: same input produces same findings.
//   - Findings are informational — Guardian/PDP makes the verdict.
//   - Thread-safe for concurrent server connections.
//   - Zero false-negatives on the PromptGame "shell injection" class expected;
//     false-positive rate measured on a benign-tool corpus before promotion
//     to a blocking gate (§ follow-ups in MIN-178).
package mcp

import (
	"regexp"
	"time"
)

// ArgScanFinding represents a single suspicious pattern detected in a tool-call argument.
//
// Intentionally shaped identically to DocScanFinding so Guardian can consume
// the two sources with a common decoder.
type ArgScanFinding struct {
	ToolName     string          `json:"tool_name"`
	ServerID     string          `json:"server_id"`
	ArgumentPath string          `json:"argument_path"`
	Severity     DocScanSeverity `json:"severity"`
	Pattern      string          `json:"pattern"`
	MatchedText  string          `json:"matched_text"`
	Description  string          `json:"description"`
	DetectedAt   time.Time       `json:"detected_at"`
}

// argPattern is a compiled detection rule for argument scanning.
type argPattern struct {
	Name     string
	Severity DocScanSeverity
	Regex    *regexp.Regexp
	Desc     string
}

// ArgScanOption configures optional ArgScanner settings.
type ArgScanOption func(*ArgScanner)

// ArgScanner scans MCP tool-call arguments for injection patterns.
// All methods are safe for concurrent use from multiple goroutines.
type ArgScanner struct {
	patterns []argPattern
	clock    func() time.Time
}
