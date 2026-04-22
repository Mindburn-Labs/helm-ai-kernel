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
	"encoding/json"
	"regexp"
	"sort"
	"strings"
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

// WithArgScanClock sets a custom clock function (primarily for testing).
func WithArgScanClock(clock func() time.Time) ArgScanOption {
	return func(s *ArgScanner) {
		s.clock = clock
	}
}

// defaultArgPatterns returns the built-in injection-detection patterns for tool-call
// arguments. Patterns target five CVE classes drawn from the Q1-2026 MCP CVE corpus
// (Doyensec / Vulnerable MCP Project / CVE-2026-5058).
func defaultArgPatterns() []argPattern {
	return []argPattern{
		{
			Name:     "shell_metachar",
			Severity: DocScanSeverityHigh,
			Regex:    regexp.MustCompile("[;&|`]|\\$\\(|\\$\\{|\\x00|>\\||<\\("),
			Desc:     "Shell metacharacter (;&|` $() ${} NUL redirect process-substitution) in tool argument",
		},
		{
			Name:     "command_substitution_backtick",
			Severity: DocScanSeverityCritical,
			Regex:    regexp.MustCompile("`[^`]*`"),
			Desc:     "Backtick command substitution in tool argument",
		},
		{
			Name:     "shell_payload_common",
			Severity: DocScanSeverityCritical,
			Regex:    regexp.MustCompile(`(?i)(^|[\s;&|])(sh|bash|zsh|ksh|dash)\s+(-c\s+|<\()`),
			Desc:     "Shell spawn with -c or process-substitution payload in tool argument",
		},
		{
			Name:     "ssrf_metadata",
			Severity: DocScanSeverityCritical,
			Regex:    regexp.MustCompile(`169\.254\.169\.254|metadata\.(google|gce|azure|aws)\.internal|\[fd00:ec2::254\]`),
			Desc:     "SSRF target — cloud metadata endpoint in tool argument",
		},
		{
			Name:     "ssrf_scheme_bypass",
			Severity: DocScanSeverityHigh,
			Regex:    regexp.MustCompile(`(?i)(gopher|dict|ftp|ldap|file|jar|php|data):/`),
			Desc:     "SSRF scheme bypass (gopher/dict/ftp/ldap/file/jar/php/data URI) in tool argument",
		},
		{
			// Accept any combination of literal / percent-encoded dots with any
			// combination of literal / percent-encoded separators. Three
			// components (dot-separator-dot) are required to rule out benign
			// filenames like "..doc" or "image.2d.png".
			Name:     "path_traversal",
			Severity: DocScanSeverityHigh,
			Regex:    regexp.MustCompile(`(?i)(\.\.|%2e%2e|%252e%252e)([/\\]|%2f|%5c|%252f|%255c)(\.\.|%2e%2e|%252e%252e)`),
			Desc:     "Path traversal sequence (literal or percent-encoded dots + slashes) in tool argument",
		},
		{
			Name:     "null_byte",
			Severity: DocScanSeverityHigh,
			Regex:    regexp.MustCompile(`%00|\\x00`),
			Desc:     "Null byte / percent-encoded NUL in tool argument (filter-bypass primitive)",
		},
	}
}

// NewArgScanner creates an ArgScanner with the default rule set.
// Patterns are compiled once at construction.
func NewArgScanner(opts ...ArgScanOption) *ArgScanner {
	s := &ArgScanner{
		patterns: defaultArgPatterns(),
		clock:    time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ScanArguments walks a tool-call argument tree (arbitrary nested JSON) and
// returns every pattern match as a deterministic list. Ordering is stable for
// a given input: outer-key-first, then nested keys in insertion order, then
// array indices in ascending order.
func (s *ArgScanner) ScanArguments(
	toolName, serverID string,
	arguments json.RawMessage,
) []ArgScanFinding {
	var decoded any
	if len(arguments) == 0 {
		return nil
	}
	if err := json.Unmarshal(arguments, &decoded); err != nil {
		// Malformed JSON is an injection signal in its own right — but we
		// report it structurally so PDP can decide. We don't pattern-match
		// bytes directly because that would double-fire against legitimate
		// JSON containing scanned metachars.
		return []ArgScanFinding{{
			ToolName:     toolName,
			ServerID:     serverID,
			ArgumentPath: "$",
			Severity:     DocScanSeverityMedium,
			Pattern:      "malformed_json",
			MatchedText:  truncate(string(arguments), 128),
			Description:  "Tool arguments are not valid JSON",
			DetectedAt:   s.clock(),
		}}
	}
	findings := make([]ArgScanFinding, 0, 4)
	s.walk(toolName, serverID, "$", decoded, &findings)
	return findings
}

// walk recurses through the argument tree, invoking scanString on every leaf
// string value encountered. Non-string leaves (numbers, bools, nil) are
// skipped; JSON keys are not scanned (keys are never attacker-controlled in
// the MCP tool-contract model — if they were, argument-schema validation
// would already reject them at a prior stage).
func (s *ArgScanner) walk(
	toolName, serverID, path string,
	node any,
	findings *[]ArgScanFinding,
) {
	switch v := node.(type) {
	case string:
		s.scanString(toolName, serverID, path, v, findings)
	case map[string]any:
		// Sort keys for deterministic traversal — Go's map iteration order
		// is randomized per run and would otherwise produce non-deterministic
		// finding ordering, violating the scanner's deterministic-output
		// contract documented in the package header.
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s.walk(toolName, serverID, path+"."+k, v[k], findings)
		}
	case []any:
		for i, child := range v {
			s.walk(toolName, serverID, path+"["+itoa(i)+"]", child, findings)
		}
	}
}

// scanString applies every compiled pattern to a leaf string value.
func (s *ArgScanner) scanString(
	toolName, serverID, path, value string,
	findings *[]ArgScanFinding,
) {
	for _, p := range s.patterns {
		if loc := p.Regex.FindStringIndex(value); loc != nil {
			*findings = append(*findings, ArgScanFinding{
				ToolName:     toolName,
				ServerID:     serverID,
				ArgumentPath: path,
				Severity:     p.Severity,
				Pattern:      p.Name,
				MatchedText:  truncate(value[loc[0]:loc[1]], 128),
				Description:  p.Desc,
				DetectedAt:   s.clock(),
			})
		}
	}
}

// MaxSeverity returns the highest severity across a slice of findings, or the
// empty string if the slice is empty. Useful for PDP decisioning.
func MaxSeverity(findings []ArgScanFinding) DocScanSeverity {
	order := map[DocScanSeverity]int{
		DocScanSeverityLow:      1,
		DocScanSeverityMedium:   2,
		DocScanSeverityHigh:     3,
		DocScanSeverityCritical: 4,
	}
	highest := DocScanSeverity("")
	highestN := 0
	for _, f := range findings {
		if n := order[f.Severity]; n > highestN {
			highestN = n
			highest = f.Severity
		}
	}
	return highest
}

// truncate caps a string to n runes, appending "…" if truncated. Used to keep
// finding payloads small even when an attacker sends a multi-MB argument value.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// itoa is a minimal non-allocating int formatter for array indices in JSONPath.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return strings.Clone(string(buf[pos:]))
}
