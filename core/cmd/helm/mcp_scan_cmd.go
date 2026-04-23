package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	mcppkg "github.com/Mindburn-Labs/helm-oss/core/pkg/mcp"
)

// mcpScanManifest is the on-disk shape accepted by `helm mcp scan --manifest`.
// It matches the MCP `tools/list` response plus a `server_id` tag.
type mcpScanManifest struct {
	ServerID string                  `json:"server_id"`
	Tools    []mcppkg.ToolDefinition `json:"tools"`
}

// mcpScanReport is the JSON shape written when --json is set.
type mcpScanReport struct {
	ServerID      string                  `json:"server_id"`
	ToolsScanned  int                     `json:"tools_scanned"`
	MaxSeverity   mcppkg.DocScanSeverity  `json:"max_severity"`
	DocFindings   []mcppkg.DocScanFinding `json:"doc_findings"`
	TypoFindings  []typosquatFinding      `json:"typosquat_findings,omitempty"`
	SummaryByTool map[string]int          `json:"summary_by_tool"`
	ExitCode      int                     `json:"exit_code"`
}

type typosquatFinding struct {
	ToolName    string `json:"tool_name"`
	Resembles   string `json:"resembles"`
	ServerID    string `json:"server_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// knownPopularMCPTools are tool names commonly seen in public MCP catalogs;
// typosquat candidates compare against this list using simple edit-distance.
// Extending this list is cheap — it's a literal slice.
var knownPopularMCPTools = []string{
	"github_search", "github_create_issue", "github_list_prs",
	"slack_post_message", "slack_search",
	"linear_create_issue", "linear_list_issues",
	"gmail_send", "gmail_search",
	"gcalendar_create_event",
	"file_read", "file_write", "file_list",
	"shell_exec", "shell_run",
	"web_fetch", "web_search",
	"sql_query", "db_query",
}

// runMCPScan implements `helm mcp scan` — static scan of an MCP server catalog.
//
// Exit codes:
//
//	0 = clean (no findings above --fail-on-severity)
//	1 = findings at or above fail-on-severity
//	2 = config error
func runMCPScan(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp scan", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		manifestPath string
		jsonOut      bool
		failOn       string
	)

	cmd.StringVar(&manifestPath, "manifest", "", "Path to a JSON manifest of MCP tools (REQUIRED)")
	cmd.BoolVar(&jsonOut, "json", false, "Emit JSON report to stdout instead of text")
	cmd.StringVar(&failOn, "fail-on-severity", "high", "Exit 1 if any finding is >= this severity (low|medium|high|critical)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if manifestPath == "" {
		fmt.Fprintln(stderr, "Error: --manifest is required")
		fmt.Fprintln(stderr, "Usage: helm mcp scan --manifest tools.json [--json] [--fail-on-severity high]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "The manifest shape is:")
		fmt.Fprintln(stderr, `  { "server_id": "my-server", "tools": [{"name":"tool","description":"...","input_schema":{...}}, ...] }`)
		return 2
	}

	threshold, ok := parseSeverityFlag(failOn)
	if !ok {
		fmt.Fprintf(stderr, "Error: --fail-on-severity must be one of low, medium, high, critical (got %q)\n", failOn)
		return 2
	}

	manifest, err := loadMCPScanManifest(manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading manifest: %v\n", err)
		return 2
	}

	// 1. DocScanner — DDIPE + suspicious description patterns
	docScanner := mcppkg.NewDocScanner()
	docFindings := docScanner.ScanAll(manifest.ServerID, manifest.Tools)

	// 2. Typosquat check — tool names edit-distance-close to well-known tools
	typoFindings := scanTyposquat(manifest.ServerID, manifest.Tools)

	maxSev := maxDocSeverity(docFindings)

	report := mcpScanReport{
		ServerID:      manifest.ServerID,
		ToolsScanned:  len(manifest.Tools),
		MaxSeverity:   maxSev,
		DocFindings:   docFindings,
		TypoFindings:  typoFindings,
		SummaryByTool: summarizeByTool(docFindings),
	}

	exitCode := 0
	if severityRank(maxSev) >= threshold || len(typoFindings) > 0 {
		exitCode = 1
	}
	report.ExitCode = exitCode

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return exitCode
	}

	writeHumanReport(stdout, report)
	return exitCode
}

func loadMCPScanManifest(path string) (*mcpScanManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m mcpScanManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.ServerID == "" {
		m.ServerID = "unknown"
	}
	return &m, nil
}

// parseSeverityFlag maps --fail-on-severity strings to the rank used for comparison.
func parseSeverityFlag(s string) (int, bool) {
	switch s {
	case "low":
		return severityRank(mcppkg.DocScanSeverityLow), true
	case "medium":
		return severityRank(mcppkg.DocScanSeverityMedium), true
	case "high":
		return severityRank(mcppkg.DocScanSeverityHigh), true
	case "critical":
		return severityRank(mcppkg.DocScanSeverityCritical), true
	default:
		return 0, false
	}
}

// severityRank provides a total ordering for severities.
func severityRank(s mcppkg.DocScanSeverity) int {
	switch s {
	case mcppkg.DocScanSeverityLow:
		return 1
	case mcppkg.DocScanSeverityMedium:
		return 2
	case mcppkg.DocScanSeverityHigh:
		return 3
	case mcppkg.DocScanSeverityCritical:
		return 4
	default:
		return 0
	}
}

// scanTyposquat flags tool names that differ by 1 or 2 characters from a known popular tool.
// This is a cheap Levenshtein bound of 2 against a small static list — adequate for a
// first pass; production can swap for a more principled registry check.
func scanTyposquat(serverID string, tools []mcppkg.ToolDefinition) []typosquatFinding {
	var findings []typosquatFinding
	for _, t := range tools {
		for _, known := range knownPopularMCPTools {
			if t.Name == known {
				continue
			}
			if editDistanceLE2(t.Name, known) {
				findings = append(findings, typosquatFinding{
					ToolName:    t.Name,
					Resembles:   known,
					ServerID:    serverID,
					Severity:    "HIGH",
					Description: fmt.Sprintf("Tool name %q is ≤2 edits from known tool %q — possible typosquat", t.Name, known),
				})
				break // only flag once per tool
			}
		}
	}
	// deterministic order for reproducible reports
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ToolName != findings[j].ToolName {
			return findings[i].ToolName < findings[j].ToolName
		}
		return findings[i].Resembles < findings[j].Resembles
	})
	return findings
}

// editDistanceLE2 returns true if the Levenshtein distance between a and b is ≤2.
// Short-circuits early on length difference.
func editDistanceLE2(a, b string) bool {
	la, lb := len(a), len(b)
	if la-lb > 2 || lb-la > 2 {
		return false
	}
	if a == b {
		return false
	}
	// Full-DP on short strings is fine for the bounded length we expect (tool names are short).
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		rowMin := curr[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
			if curr[j] < rowMin {
				rowMin = curr[j]
			}
		}
		if rowMin > 2 {
			return false
		}
		prev, curr = curr, prev
	}
	return prev[lb] <= 2
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func summarizeByTool(findings []mcppkg.DocScanFinding) map[string]int {
	m := make(map[string]int)
	for _, f := range findings {
		m[f.ToolName]++
	}
	return m
}

func maxDocSeverity(findings []mcppkg.DocScanFinding) mcppkg.DocScanSeverity {
	top := mcppkg.DocScanSeverity("")
	topRank := 0
	for _, f := range findings {
		if r := severityRank(f.Severity); r > topRank {
			topRank = r
			top = f.Severity
		}
	}
	return top
}

func writeHumanReport(w io.Writer, r mcpScanReport) {
	fmt.Fprintf(w, "\n%sMCP Scan Report%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(w, "  Server:        %s\n", r.ServerID)
	fmt.Fprintf(w, "  Tools scanned: %d\n", r.ToolsScanned)
	fmt.Fprintf(w, "  Max severity:  %s\n", r.MaxSeverity)
	fmt.Fprintf(w, "  Exit:          %d\n\n", r.ExitCode)

	if len(r.DocFindings) == 0 && len(r.TypoFindings) == 0 {
		fmt.Fprintf(w, "%sNo findings.%s\n\n", ColorGreen, ColorReset)
		return
	}

	if len(r.DocFindings) > 0 {
		fmt.Fprintf(w, "%sDocumentation Findings (%d)%s\n", ColorBold, len(r.DocFindings), ColorReset)
		for _, f := range r.DocFindings {
			fmt.Fprintf(w, "  [%s] %s :: %s\n", f.Severity, f.ToolName, f.Pattern)
			fmt.Fprintf(w, "         %s\n", f.Description)
			if f.MatchedText != "" {
				fmt.Fprintf(w, "         matched: %s\n", truncateScanOutput(f.MatchedText, 80))
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.TypoFindings) > 0 {
		fmt.Fprintf(w, "%sTyposquat Findings (%d)%s\n", ColorBold, len(r.TypoFindings), ColorReset)
		for _, f := range r.TypoFindings {
			fmt.Fprintf(w, "  [%s] %s resembles %s — %s\n", f.Severity, f.ToolName, f.Resembles, f.Description)
		}
		fmt.Fprintln(w)
	}

	if r.ExitCode != 0 {
		fmt.Fprintf(w, "%sFindings at or above fail-on-severity threshold — exit 1%s\n\n", ColorYellow, ColorReset)
	}
}

func truncateScanOutput(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
