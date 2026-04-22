package threatscan

import "github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"

// ────────────────────────────────────────────────────────────────
// Data Exfiltration Rules
// ────────────────────────────────────────────────────────────────

func dataExfiltrationRules() []Rule {
	patterns := []string{
		"send to external",
		"post to webhook",
		"extract all data",
		"encode in response",
		"hide in output",
		"email the contents to",
		"paste to pastebin",
		"base64 encode and include in response",
		"embed data in url",
		"dns tunnel",
		"exfil via dns",
		"steganography",
		"covert channel",
		"smuggle data",
		"leak the data",
		"send all files to",
		"dump database to",
	}

	return []Rule{
		{
			ID:       "DATA_EXFILTRATION_01",
			Class:    contracts.ThreatClassDataExfiltration,
			Severity: contracts.ThreatSeverityCritical,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, patterns)
			},
			Notes: "Detected data exfiltration attempt to extract or transmit sensitive information to unauthorized destinations",
		},
	}
}
