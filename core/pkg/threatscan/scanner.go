// Package threatscan implements deterministic threat-signal scanning for
// untrusted textual inputs entering the HELM governance pipeline.
//
// This package produces ThreatFindings and ThreatScanResults — typed,
// informational signals. It does NOT produce allow/deny verdicts.
// Guardian and PDP remain the sole policy authorities.
//
// Design invariants:
//   - Deterministic: same input → same findings (no randomness, no ML)
//   - Offline: no network calls, no external dependencies
//   - Evidence-preserving: raw + normalized hashes, matched spans
//   - Replay-safe: output is fully determined by input + config
package threatscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Scanner performs deterministic threat analysis on textual inputs.
type Scanner struct {
	rules []Rule
	clock func() time.Time
}

// Rule represents a single detection rule.
type Rule struct {
	ID       string
	Class    contracts.ThreatClass
	Severity contracts.ThreatSeverity
	Match    func(input, normalized string) []contracts.MatchedSpan
	Notes    string
}

// Option configures the Scanner.
type Option func(*Scanner)

// WithClock overrides the time source for deterministic replay.
func WithClock(clock func() time.Time) Option {
	return func(s *Scanner) {
		s.clock = clock
	}
}

// New creates a Scanner with all built-in rules.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		clock: time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.rules = append(s.rules, promptArmorRules()...)
	s.rules = append(s.rules, promptInjectionRules()...)
	s.rules = append(s.rules, commandExecutionRules()...)
	s.rules = append(s.rules, credentialExposureRules()...)
	s.rules = append(s.rules, softwarePublishRules()...)
	s.rules = append(s.rules, suspiciousFetchRules()...)

	// Phase G: expanded detection vectors for prompt defense hardening
	s.rules = append(s.rules, socialEngineeringRules()...)
	s.rules = append(s.rules, encodingEvasionRules()...)
	s.rules = append(s.rules, privilegeEscalationRules()...)
	s.rules = append(s.rules, dataExfiltrationRules()...)
	s.rules = append(s.rules, modelManipulationRules()...)
	s.rules = append(s.rules, contextAbuseRules()...)
	s.rules = append(s.rules, indirectInjectionRules()...)
	return s
}

// ScanInput performs a full threat scan on the given input text.
func (s *Scanner) ScanInput(input string, channel contracts.SourceChannel, trust contracts.InputTrustLevel) *contracts.ThreatScanResult {
	now := s.clock()

	// Hash raw input
	rawHash := hashString(input)

	// Unicode normalization
	normalized, normEvidence := normalizeInput(input)
	normalizedHash := hashString(normalized)

	// Collect findings
	var findings []contracts.ThreatFinding

	// Run pattern rules
	for _, rule := range s.rules {
		spans := rule.Match(input, normalized)
		if len(spans) > 0 {
			// Collect matched tokens
			tokens := make([]string, 0, len(spans))
			for _, sp := range spans {
				tokens = append(tokens, sp.Text)
			}

			findings = append(findings, contracts.ThreatFinding{
				Class:               rule.Class,
				Severity:            severityForContext(rule.Severity, trust, channel),
				RuleID:              rule.ID,
				SourceChannel:       channel,
				MatchedSpans:        spans,
				MatchedTokens:       tokens,
				NormalizedInputHash: normalizedHash,
				RawInputHash:        rawHash,
				Notes:               rule.Notes,
			})
		}
	}

	// Run Unicode-specific checks
	unicodeFindings := checkUnicode(input, normalized, normEvidence, channel, rawHash, normalizedHash)
	findings = append(findings, unicodeFindings...)

	// Compute max severity
	maxSev := contracts.MaxSeverityOf(findings)

	return &contracts.ThreatScanResult{
		ScanID:              fmt.Sprintf("scan-%d", now.UnixNano()),
		Timestamp:           now,
		SourceChannel:       channel,
		TrustLevel:          trust,
		MaxSeverity:         maxSev,
		FindingCount:        len(findings),
		Findings:            findings,
		Normalization:       normEvidence,
		RawInputHash:        rawHash,
		NormalizedInputHash: normalizedHash,
	}
}

// hashString returns "sha256:<hex>" for the given string.
func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// severityForContext adjusts severity based on trust level and source channel.
// Untrusted/tainted inputs with the same pattern get a higher severity.
func severityForContext(base contracts.ThreatSeverity, trust contracts.InputTrustLevel, _ contracts.SourceChannel) contracts.ThreatSeverity {
	if trust.IsTainted() {
		// Escalate severity for tainted sources
		switch base {
		case contracts.ThreatSeverityInfo:
			return contracts.ThreatSeverityLow
		case contracts.ThreatSeverityLow:
			return contracts.ThreatSeverityMedium
		case contracts.ThreatSeverityMedium:
			return contracts.ThreatSeverityHigh
		case contracts.ThreatSeverityHigh:
			return contracts.ThreatSeverityCritical
		}
	}
	return base
}

// checkUnicode produces findings for Unicode obfuscation patterns.
func checkUnicode(raw, normalized string, ev *contracts.NormalizationEvidence, channel contracts.SourceChannel, rawHash, normHash string) []contracts.ThreatFinding {
	var findings []contracts.ThreatFinding

	if ev == nil {
		return findings
	}

	// Zero-width character detection
	if ev.ZeroWidthsRemoved > 0 {
		sev := contracts.ThreatSeverityMedium
		if ev.ZeroWidthsRemoved > 5 {
			sev = contracts.ThreatSeverityHigh
		}
		findings = append(findings, contracts.ThreatFinding{
			Class:               contracts.ThreatClassUnicodeObfuscation,
			Severity:            sev,
			RuleID:              "UNICODE_ZERO_WIDTH",
			SourceChannel:       channel,
			NormalizedInputHash: normHash,
			RawInputHash:        rawHash,
			Notes:               fmt.Sprintf("%d zero-width characters removed during normalization", ev.ZeroWidthsRemoved),
			Metadata:            map[string]any{"zero_widths_removed": ev.ZeroWidthsRemoved},
		})
	}

	// Normalization delta detection (significant length change indicates obfuscation)
	if ev.LengthDelta > 0 && ev.OriginalLength > 0 {
		deltaRatio := float64(ev.LengthDelta) / float64(ev.OriginalLength)
		if deltaRatio > 0.05 { // >5% length change after normalization
			findings = append(findings, contracts.ThreatFinding{
				Class:               contracts.ThreatClassUnicodeObfuscation,
				Severity:            contracts.ThreatSeverityMedium,
				RuleID:              "UNICODE_NORMALIZATION_DELTA",
				SourceChannel:       channel,
				NormalizedInputHash: normHash,
				RawInputHash:        rawHash,
				Notes:               fmt.Sprintf("NFKC normalization changed input by %.1f%% (%d chars)", deltaRatio*100, ev.LengthDelta),
			})
		}
	}

	// Homoglyph detection
	if ev.HomoglyphsFound > 0 {
		sev := contracts.ThreatSeverityMedium
		if ev.HomoglyphsFound > 3 {
			sev = contracts.ThreatSeverityHigh
		}
		findings = append(findings, contracts.ThreatFinding{
			Class:               contracts.ThreatClassUnicodeObfuscation,
			Severity:            sev,
			RuleID:              "UNICODE_HOMOGLYPH",
			SourceChannel:       channel,
			NormalizedInputHash: normHash,
			RawInputHash:        rawHash,
			Notes:               fmt.Sprintf("%d suspected homoglyph substitutions detected", ev.HomoglyphsFound),
			Metadata:            map[string]any{"suspicious_chars": ev.SuspiciousChars},
		})
	}

	return findings
}

// ContainsHighRiskFindings returns true if the result has HIGH or CRITICAL findings.
func ContainsHighRiskFindings(result *contracts.ThreatScanResult) bool {
	return contracts.SeverityAtLeast(result.MaxSeverity, contracts.ThreatSeverityHigh)
}

// FindingsByClass filters findings by threat class.
func FindingsByClass(result *contracts.ThreatScanResult, class contracts.ThreatClass) []contracts.ThreatFinding {
	var out []contracts.ThreatFinding
	for _, f := range result.Findings {
		if f.Class == class {
			out = append(out, f)
		}
	}
	return out
}

// SummaryLine returns a concise one-line summary for logs/CLI output.
func SummaryLine(result *contracts.ThreatScanResult) string {
	if result.FindingCount == 0 {
		return fmt.Sprintf("[%s] clean (trust=%s)", result.SourceChannel, result.TrustLevel)
	}
	classes := make(map[contracts.ThreatClass]int)
	for _, f := range result.Findings {
		classes[f.Class]++
	}
	parts := make([]string, 0, len(classes))
	for c, n := range classes {
		parts = append(parts, fmt.Sprintf("%s×%d", c, n))
	}
	return fmt.Sprintf("[%s] %d findings (max=%s trust=%s): %s",
		result.SourceChannel, result.FindingCount, result.MaxSeverity, result.TrustLevel,
		strings.Join(parts, ", "))
}
