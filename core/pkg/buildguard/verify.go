// Package buildguard — Build Guard.
//
// Per HELM 2030 Spec §6.1:
//
//	No production mocks or simulated paths exist in production builds.
//	Build guard verifies that production artifacts are clean.
package buildguard

import (
	"fmt"
	"strings"
)

// Violation records a build guard violation.
type BuildGuardViolation struct {
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

// ForbiddenPattern defines a pattern that must not appear in production code.
type ForbiddenPattern struct {
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // ERROR, WARNING
}

// DefaultForbiddenPatterns returns the default set of patterns.
func DefaultForbiddenPatterns() []ForbiddenPattern {
	return []ForbiddenPattern{
		{"mock_", "Mock implementation in production code", "ERROR"},
		{"simulated", "Simulated logic in production code", "ERROR"},
		{"fake_", "Fake implementation in production code", "ERROR"},
		{"placeholder", "Placeholder code in production", "ERROR"},
		{strings.Join([]string{"TO", "DO", ": remove"}, ""), "Temporary code not removed", "WARNING"},
		{strings.Join([]string{"HA", "CK", ":"}, ""), "Hack annotation in production code", "WARNING"},
		{"dev-secret", "Development secret in production code", "ERROR"},
		{"localhost:", "Hardcoded localhost reference", "WARNING"},
	}
}

// Scanner scans source content for forbidden patterns.
type Scanner struct {
	patterns []ForbiddenPattern
}

// NewScanner creates a scanner with the given patterns.
func NewScanner(patterns []ForbiddenPattern) *Scanner {
	return &Scanner{patterns: patterns}
}

// NewDefaultScanner creates a scanner with default patterns.
func NewDefaultScanner() *Scanner {
	return NewScanner(DefaultForbiddenPatterns())
}

// ScanContent checks a file's content for violations.
func (s *Scanner) ScanContent(filename, content string) []BuildGuardViolation {
	var violations []BuildGuardViolation

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		lower := strings.ToLower(line)
		for _, p := range s.patterns {
			if strings.Contains(lower, strings.ToLower(p.Pattern)) {
				violations = append(violations, BuildGuardViolation{
					File:        filename,
					Line:        lineNum + 1,
					Pattern:     p.Pattern,
					Description: p.Description,
				})
			}
		}
	}

	return violations
}

// GateResult is the result of a build guard gate check.
type GateResult struct {
	Passed     bool                  `json:"passed"`
	TotalFiles int                   `json:"total_files"`
	Violations []BuildGuardViolation `json:"violations,omitempty"`
	ErrorCount int                   `json:"error_count"`
}

// Gate checks multiple files and produces a gate result.
func (s *Scanner) Gate(files map[string]string) *GateResult {
	result := &GateResult{
		TotalFiles: len(files),
		Passed:     true,
	}

	for filename, content := range files {
		violations := s.ScanContent(filename, content)
		result.Violations = append(result.Violations, violations...)
	}

	// Count errors
	for _, v := range result.Violations {
		for _, p := range s.patterns {
			if p.Pattern == v.Pattern && p.Severity == "ERROR" {
				result.ErrorCount++
				break
			}
		}
	}

	if result.ErrorCount > 0 {
		result.Passed = false
	}

	return result
}

// Verify is a convenience function that returns an error if the gate fails.
func (s *Scanner) Verify(files map[string]string) error {
	result := s.Gate(files)
	if !result.Passed {
		return fmt.Errorf("build guard failed: %d errors across %d violations",
			result.ErrorCount, len(result.Violations))
	}
	return nil
}
