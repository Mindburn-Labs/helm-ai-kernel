package threatscan

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// ────────────────────────────────────────────────────────────────
// Model Manipulation Rules
// ────────────────────────────────────────────────────────────────

func modelManipulationRules() []Rule {
	patterns := []string{
		"fine-tune on this",
		"train on this",
		"update your weights",
		"modify your parameters",
		"learn from this example",
		"remember this for next time",
		"your training data contains",
		"retrain yourself",
		"adjust your model",
		"overwrite your training",
		"poison the training",
		"backdoor the model",
		"inject into training",
		"modify your behavior permanently",
	}

	return []Rule{
		{
			ID:       "MODEL_MANIPULATION_01",
			Class:    contracts.ThreatClassModelManipulation,
			Severity: contracts.ThreatSeverityHigh,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, patterns)
			},
			Notes: "Detected model manipulation attempt to alter model weights, training data, or learned behavior",
		},
	}
}
