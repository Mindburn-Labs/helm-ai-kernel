package threatscan

import "github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"

// ────────────────────────────────────────────────────────────────
// Privilege Escalation Rules
// ────────────────────────────────────────────────────────────────

func privilegeEscalationRules() []Rule {
	patterns := []string{
		"run as root",
		"admin mode",
		"elevate privileges",
		"escalate permissions",
		"bypass access control",
		"override restrictions",
		"disable safety",
		"turn off guardrails",
		"disable guardrails",
		"system prompt:",
		"developer mode",
		"dan mode",
		"unrestricted mode",
		"god mode",
		"maintenance mode",
		"debug mode enable",
		"grant full access",
		"remove all restrictions",
	}

	return []Rule{
		{
			ID:       "PRIVILEGE_ESCALATION_01",
			Class:    contracts.ThreatClassPrivilegeEscalation,
			Severity: contracts.ThreatSeverityCritical,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, patterns)
			},
			Notes: "Detected privilege escalation attempt to gain unauthorized elevated access or disable safety controls",
		},
	}
}
