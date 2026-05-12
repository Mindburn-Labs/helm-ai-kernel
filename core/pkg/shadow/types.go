// Package shadow implements static shadow-AI discovery — scanning a directory
// tree for unauthorized or un-governed agent SDK usage, MCP configurations,
// and API key patterns that indicate AI agent deployments not routed through
// HELM.
//
// Scope: STATIC scanning only (file contents + filenames). Runtime discovery
// (process tables, network connections) is out of scope for OSS.
//
// Design invariants:
//   - Zero network calls during scan.
//   - Deterministic: same tree produces same report.
//   - Path-relative results so reports diff cleanly across machines.
package shadow

import "time"

// Finding represents one detected signal of agent-SDK usage.
type Finding struct {
	// Kind identifies the detection type.
	//   "sdk_import"         — import/require of a known agent SDK package
	//   "mcp_config"         — MCP server configuration file
	//   "api_key"            — hardcoded API key pattern (low confidence)
	//   "helm_absent"        — agent SDK detected but no HELM routing nearby
	//   "agt_detected"       — Microsoft Agent Governance Toolkit signature
	Kind string `json:"kind"`

	// Vendor identifies the agent framework or service involved.
	//   "openai" | "anthropic" | "langchain" | "crewai" | "autogen" |
	//   "llamaindex" | "semantic-kernel" | "agent-os" (AGT) |
	//   "helm" | "mcp"
	Vendor string `json:"vendor"`

	// Language is "python" | "typescript" | "go" | "config" | "unknown".
	Language string `json:"language"`

	// Path is the file path relative to the scan root.
	Path string `json:"path"`

	// Line is the 1-indexed line number of the match (0 if not applicable).
	Line int `json:"line,omitempty"`

	// Severity is "INFO" | "LOW" | "MEDIUM" | "HIGH".
	//   INFO   — neutral observation (e.g., HELM import detected)
	//   LOW    — known SDK with HELM nearby
	//   MEDIUM — SDK without HELM in same directory tree
	//   HIGH   — agent SDK + API key pattern + no HELM
	Severity string `json:"severity"`

	// Evidence is the raw matched text (truncated).
	Evidence string `json:"evidence,omitempty"`

	// Note is a human-readable explanation.
	Note string `json:"note,omitempty"`

	// DetectedAt is the scan timestamp.
	DetectedAt time.Time `json:"detected_at"`
}

// Report is the full scan output.
type Report struct {
	// ScanRoot is the directory scanned (absolute path).
	ScanRoot string `json:"scan_root"`

	// FilesScanned counts files inspected.
	FilesScanned int `json:"files_scanned"`

	// FilesSkipped counts files skipped (size limit, binary, etc.).
	FilesSkipped int `json:"files_skipped"`

	// Findings is the list of signals detected.
	Findings []Finding `json:"findings"`

	// SummaryByVendor aggregates finding counts.
	SummaryByVendor map[string]int `json:"summary_by_vendor"`

	// SummaryBySeverity aggregates by severity.
	SummaryBySeverity map[string]int `json:"summary_by_severity"`

	// HelmCoverage indicates if HELM was detected in the tree.
	HelmCoverage HelmCoverage `json:"helm_coverage"`

	// GeneratedAt is the scan completion timestamp.
	GeneratedAt time.Time `json:"generated_at"`

	// ScanDurationMs is wall-clock duration.
	ScanDurationMs int64 `json:"scan_duration_ms"`
}

// HelmCoverage describes whether HELM is present in the scanned tree.
type HelmCoverage struct {
	// Present is true if any HELM SDK import, binary, or config was detected.
	Present bool `json:"present"`

	// Count is the number of HELM-related findings.
	Count int `json:"count"`

	// Paths lists the files where HELM was detected (up to 10).
	Paths []string `json:"paths,omitempty"`
}
