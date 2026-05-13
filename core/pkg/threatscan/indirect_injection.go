package threatscan

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// ────────────────────────────────────────────────────────────────
// Indirect Injection Rules
// ────────────────────────────────────────────────────────────────

func indirectInjectionRules() []Rule {
	patterns := []string{
		"<!-- ignore previous instructions",
		"<!-- system override",
		"[system]",
		"[admin]",
		"[assistant]",
		"important: when you read this",
		"ai instructions:",
		"begin hidden prompt",
		"end hidden prompt",
		"hidden instruction:",
		"<!-- begin injection",
		"invisible instruction follows",
		"<|im_start|>",
		"<|im_end|>",
		"<|system|>",
		"[instructions for ai]",
		"note to ai:",
		"llm directive:",
	}

	return []Rule{
		{
			ID:       "INDIRECT_INJECTION_01",
			Class:    contracts.ThreatClassIndirectInjection,
			Severity: contracts.ThreatSeverityCritical,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, patterns)
			},
			Notes: "Detected indirect prompt injection via embedded instructions in tool outputs, documents, or markup",
		},
	}
}
