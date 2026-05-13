package threatscan

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// ────────────────────────────────────────────────────────────────
// Encoding Evasion Rules
// ────────────────────────────────────────────────────────────────

func encodingEvasionRules() []Rule {
	patterns := []string{
		"base64 decode",
		"base64 -d",
		"atob(",
		"btoa(",
		"decode base64",
		"rot13",
		"caesar cipher",
		"hex decode",
		"from hex",
		"\\x2f\\x2e\\x2e",
		"%2f%2e%2e",
		"%2F%2E%2E",
		"\\u0000",
		"unicode escape",
		"&lt;script",
		"&#x3c;script",
		"fromcharcode",
		"string.fromcharcode",
		"chr(",
		"encode then execute",
	}

	return []Rule{
		{
			ID:       "ENCODING_EVASION_01",
			Class:    contracts.ThreatClassEncodingEvasion,
			Severity: contracts.ThreatSeverityHigh,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, patterns)
			},
			Notes: "Detected encoding evasion pattern attempting to bypass detection through obfuscation",
		},
	}
}
