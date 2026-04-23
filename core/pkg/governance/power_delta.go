package governance

import (
	"github.com/Mindburn-Labs/helm-oss/core/pkg/capabilities"
)

// PowerDelta represents the risk difference between two states.
type PowerDelta struct {
	NewCapabilities []capabilities.Capability
	NewEffects      []capabilities.EffectType
	RiskScoreDelta  int
}

// ComputePowerDelta calculates what a new module introduces to the system.
// This is critical for the "No New Power Without Declaration" rule.
func ComputePowerDelta(activeRegistry []capabilities.Capability, proposedModule ModuleBundle) PowerDelta {
	delta := PowerDelta{
		NewCapabilities: []capabilities.Capability{},
		NewEffects:      []capabilities.EffectType{},
	}

	knownCaps := make(map[string]bool)
	for _, cap := range activeRegistry {
		knownCaps[cap.ID] = true
	}

	for _, cap := range proposedModule.Capabilities {
		if !knownCaps[cap.ID] {
			delta.NewCapabilities = append(delta.NewCapabilities, cap)
			// Risk scoring based on EffectClass (canonical field)
			// EffectClass is now a string "E0"..."E4" (from Engine.go constants, but here just string match)
			switch cap.EffectClass {
			case "E4":
				delta.RiskScoreDelta += 20
			case "E3":
				delta.RiskScoreDelta += 10
			case "E2":
				delta.RiskScoreDelta += 5
			case "E1":
				delta.RiskScoreDelta += 2
			default: // E0 or unset
				delta.RiskScoreDelta += 1
			}

			// Track effects
			delta.NewEffects = append(delta.NewEffects, cap.Effects...)
		}
	}

	return delta
}
