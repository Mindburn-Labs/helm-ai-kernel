package governance

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capabilities"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

// EffectClass defines the risk level of an effect.
type EffectClass string

const (
	EffectClassE0 EffectClass = "E0" // Informational
	EffectClassE1 EffectClass = "E1" // Low Risk / Reversible
	EffectClassE2 EffectClass = "E2" // Medium Risk / State Mutation
	EffectClassE3 EffectClass = "E3" // High Risk / Sensitive Data
	EffectClassE4 EffectClass = "E4" // Critical / Irreversible
)

type DecisionEngine struct {
	keyring  *Keyring
	compiler *prg.Compiler
	policy   map[string]bool // Legacy Allowlist
	catalog  *capabilities.ToolCatalog
}
