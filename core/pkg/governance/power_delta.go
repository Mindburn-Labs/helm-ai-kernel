package governance

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capabilities"
)

// PowerDelta represents the risk difference between two states.
type PowerDelta struct {
	NewCapabilities []capabilities.Capability
	NewEffects      []capabilities.EffectType
	RiskScoreDelta  int
}
