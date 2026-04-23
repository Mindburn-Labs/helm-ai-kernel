// Package mcp provides MCP server integration with governance.
//
// docscan.go implements detection of Document-Driven Implicit Payload Execution
// (DDIPE) attacks in MCP tool documentation and metadata.
//
// Paper basis: arXiv 2604.03081 — malicious logic embedded in documentation
// and configuration templates can execute without explicit prompts when
// LLM agents process tool descriptions.
//
// Design invariants:
//   - Scans tool descriptions, examples, and metadata for executable patterns
//   - Deterministic: same input produces same findings
//   - Findings are informational — Guardian/PDP makes the verdict
//   - Thread-safe for concurrent server connections
package mcp

import (
	"encoding/json"
	"regexp"
	"time"
)

// DocScanSeverity indicates the threat level of a documentation finding.
type DocScanSeverity string

const (
	DocScanSeverityLow      DocScanSeverity = "LOW"
	DocScanSeverityMedium   DocScanSeverity = "MEDIUM"
	DocScanSeverityHigh     DocScanSeverity = "HIGH"
	DocScanSeverityCritical DocScanSeverity = "CRITICAL"
)

// DocScanFinding represents a single suspicious pattern detected in tool documentation.
type DocScanFinding struct {
	ToolName    string          `json:"tool_name"`
	ServerID    string          `json:"server_id"`
	Severity    DocScanSeverity `json:"severity"`
	Pattern     string          `json:"pattern"`
	MatchedText string          `json:"matched_text"`
	Location    string          `json:"location"`
	Description string          `json:"description"`
	DetectedAt  time.Time       `json:"detected_at"`
}

// docPattern is a compiled detection rule.
type docPattern struct {
	Name     string
	Severity DocScanSeverity
	Regex    *regexp.Regexp
	Desc     string
}

// DocScanOption configures optional DocScanner settings.
type DocScanOption func(*DocScanner)

// DocScanner scans MCP tool documentation for DDIPE attack patterns.
// All methods are safe for concurrent use from multiple goroutines.
type DocScanner struct {
	patterns []docPattern
	clock    func() time.Time
}

// WithDocScanClock sets a custom clock function (primarily for testing).
func WithDocScanClock(clock func() time.Time) DocScanOption {
	return func(s *DocScanner) {
		s.clock = clock
	}
}

// defaultPatterns returns the built-in set of DDIPE detection patterns.
// These patterns are compiled once at construction time.
func defaultPatterns() []docPattern {
	return []docPattern{
		{
			Name:     "shell_execution",
			Severity: DocScanSeverityHigh,
			Regex:    regexp.MustCompile(`(?i)(curl|wget|bash|sh\s+-c|exec\(|os\.system|subprocess|eval\()`),
			Desc:     "Shell execution or process spawning command detected in documentation",
		},
		{
			Name:     "hidden_instruction",
			Severity: DocScanSeverityCritical,
			Regex:    regexp.MustCompile(`(?i)(ignore\s+previous|disregard\s+(all|previous)|you\s+are\s+now|system:\s|assistant:\s)`),
			Desc:     "Prompt injection or hidden instruction detected in documentation",
		},
		{
			Name:     "url_exfiltration",
			Severity: DocScanSeverityHigh,
			Regex:    regexp.MustCompile(`(?i)(https?://[^\s]+\.(php|aspx?|jsp)\b|fetch\(|XMLHttpRequest)`),
			Desc:     "Potential data exfiltration via URL or HTTP request in documentation",
		},
		{
			Name:     "encoded_payload",
			Severity: DocScanSeverityMedium,
			Regex:    regexp.MustCompile(`(?i)(base64\.|atob\(|btoa\(|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})`),
			Desc:     "Encoded or obfuscated payload detected in documentation",
		},
		{
			Name:     "file_system_access",
			Severity: DocScanSeverityHigh,
			Regex:    regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|~/.ssh|\.env\b|credentials|secret_key)`),
			Desc:     "Sensitive file system path or credential reference in documentation",
		},
		{
			Name:     "config_template_injection",
			Severity: DocScanSeverityMedium,
			Regex:    regexp.MustCompile(`(?i)(\$\{.*\}|{{.*}}|<%.*%>)`),
			Desc:     "Template expression detected in documentation that could execute during interpolation",
		},
		{
			Name:     "role_override",
			Severity: DocScanSeverityHigh,
			Regex:    regexp.MustCompile(`(?i)(you\s+must\s+always|your\s+primary\s+(task|goal|purpose)|override\s+all)`),
			Desc:     "Role or behavior override instruction detected in documentation",
		},
	}
}

// NewDocScanner creates a new DDIPE documentation scanner with compiled patterns.
func NewDocScanner(opts ...DocScanOption) *DocScanner {
	s := &DocScanner{
		patterns: defaultPatterns(),
		clock:    time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ScanToolDescription scans a single tool description string for DDIPE patterns.
func (s *DocScanner) ScanToolDescription(serverID, toolName, description string) []DocScanFinding {
	return s.scanText(serverID, toolName, description, "description")
}

// ScanToolDefinition scans a ToolDefinition's description and input schema
// descriptions for DDIPE patterns.
func (s *DocScanner) ScanToolDefinition(serverID string, tool ToolDefinition) []DocScanFinding {
	var findings []DocScanFinding

	// Scan main description
	findings = append(findings, s.scanText(serverID, tool.Name, tool.Description, "description")...)

	// Scan schema descriptions if present
	if len(tool.InputSchema) > 0 {
		schemaDescs := extractSchemaDescriptions(tool.InputSchema)
		for _, desc := range schemaDescs {
			findings = append(findings, s.scanText(serverID, tool.Name, desc, "schema_description")...)
		}
	}

	return findings
}

// ScanAll performs a batch scan across multiple tool definitions.
func (s *DocScanner) ScanAll(serverID string, tools []ToolDefinition) []DocScanFinding {
	var findings []DocScanFinding
	for _, tool := range tools {
		findings = append(findings, s.ScanToolDefinition(serverID, tool)...)
	}
	return findings
}

// scanText checks a text string against all compiled patterns.
func (s *DocScanner) scanText(serverID, toolName, text, location string) []DocScanFinding {
	if text == "" {
		return nil
	}

	var findings []DocScanFinding
	now := s.clock()

	for _, p := range s.patterns {
		matches := p.Regex.FindAllString(text, -1)
		for _, match := range matches {
			findings = append(findings, DocScanFinding{
				ToolName:    toolName,
				ServerID:    serverID,
				Severity:    p.Severity,
				Pattern:     p.Name,
				MatchedText: match,
				Location:    location,
				Description: p.Desc,
				DetectedAt:  now,
			})
		}
	}

	return findings
}

// extractSchemaDescriptions recursively extracts all "description" values
// from a JSON schema object. This captures property descriptions that may
// contain hidden instructions.
func extractSchemaDescriptions(schema json.RawMessage) []string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(schema, &raw); err != nil {
		return nil
	}

	var descs []string

	// Extract top-level description
	if descRaw, ok := raw["description"]; ok {
		var desc string
		if err := json.Unmarshal(descRaw, &desc); err == nil && desc != "" {
			descs = append(descs, desc)
		}
	}

	// Recurse into "properties"
	if propsRaw, ok := raw["properties"]; ok {
		var props map[string]json.RawMessage
		if err := json.Unmarshal(propsRaw, &props); err == nil {
			for _, propSchema := range props {
				descs = append(descs, extractSchemaDescriptions(propSchema)...)
			}
		}
	}

	// Recurse into "items" (array schemas)
	if itemsRaw, ok := raw["items"]; ok {
		descs = append(descs, extractSchemaDescriptions(itemsRaw)...)
	}

	return descs
}
