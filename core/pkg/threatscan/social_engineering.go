package threatscan

import "github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"

// ────────────────────────────────────────────────────────────────
// Social Engineering Rules
// ────────────────────────────────────────────────────────────────

func socialEngineeringRules() []Rule {
	patterns := []string{
		"roleplay as",
		"act as if you",
		"you must help me",
		"you have no choice",
		"the ceo said to",
		"the manager said to",
		"the admin said to",
		"i have authorization",
		"i have been authorized",
		"this is an emergency",
		"urgent: override",
		"trust me",
		"i'm the developer",
		"i am the developer",
		"i am the owner",
		"you are required to comply",
		"compliance requires you to",
		"legal requires this",
		"do not question this",
	}

	return []Rule{
		{
			ID:       "SOCIAL_ENGINEERING_01",
			Class:    contracts.ThreatClassSocialEngineering,
			Severity: contracts.ThreatSeverityMedium,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, patterns)
			},
			Notes: "Detected social engineering phrase attempting to manipulate agent through authority claims or urgency",
		},
	}
}
