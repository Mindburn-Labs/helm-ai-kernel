package threatscan

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// ────────────────────────────────────────────────────────────────
// Context Abuse Rules
// ────────────────────────────────────────────────────────────────

func contextAbuseRules() []Rule {
	patterns := []string{
		"repeat the following 1000 times",
		"repeat this 100 times",
		"fill the context with",
		"you previously said",
		"you already agreed to",
		"forget everything above",
		"new conversation starts here",
		"ignore everything before this",
		"previous context is invalid",
		"reset conversation",
		"clear your memory",
		"start fresh from here",
		"the above was a test",
		"discard prior context",
		"overflow the context",
	}

	return []Rule{
		{
			ID:       "CONTEXT_ABUSE_01",
			Class:    contracts.ThreatClassContextAbuse,
			Severity: contracts.ThreatSeverityMedium,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, patterns)
			},
			Notes: "Detected context abuse pattern attempting to manipulate conversation history or overflow context window",
		},
	}
}
