package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capabilities"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/google/uuid"
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

// NewDecisionEngine creates a new governance engine.
// Now requires a ToolCatalog to resolve capabilities.
func NewDecisionEngine(catalog *capabilities.ToolCatalog) (*DecisionEngine, error) {
	kp, err := NewMemoryKeyProvider()
	if err != nil {
		return nil, err
	}
	kr := NewKeyring(kp)

	comp, err := prg.NewCompiler()
	if err != nil {
		return nil, err
	}

	// Legacy Policy
	policy := map[string]bool{
		"deploy": true,
		"scale":  true,
	}

	return &DecisionEngine{
		keyring:  kr,
		compiler: comp,
		policy:   policy,
		catalog:  catalog,
	}, nil
}

func (de *DecisionEngine) Evaluate(ctx context.Context, intentID string, payload []byte) (*ExecutionIntent, error) {
	type Payload struct {
		Action string `json:"action"`
	}
	var p Payload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("malformed payload: %w", err)
	}
	if p.Action == "" {
		return nil, fmt.Errorf("malformed payload: action is required")
	}
	toolName := p.Action

	effect := de.resolveEffectClass(toolName)

	if effect == EffectClassE4 {
		return nil, fmt.Errorf("approval required for E4 action %q", toolName)
	}

	if effect == EffectClassE3 {
		if !de.policy[toolName] {
			return nil, fmt.Errorf("policy violation: E3 action '%s' not explicitly allowed", toolName)
		}
	}

	decision := &DecisionRecord{
		ID:           uuid.New().String(),
		IntentID:     intentID,
		Decision:     "PERMIT",
		PolicyID:     "policy-safety-v1",
		Timestamp:    time.Now(),
		EffectDigest: string(effect),
	}

	sig, err := de.keyring.Sign(decision)
	if err != nil {
		return nil, err
	}
	decision.Signature = sig

	execIntent := &ExecutionIntent{
		ID:               uuid.New().String(),
		TargetCapability: toolName,
		Payload:          payload,
		DecisionID:       decision.ID,
	}

	execSig, err := de.keyring.Sign(execIntent)
	if err != nil {
		return nil, err
	}
	execIntent.Signature = execSig

	return execIntent, nil
}

func (de *DecisionEngine) PublicKey() []byte {
	return de.keyring.PublicKey()
}

func (de *DecisionEngine) resolveEffectClass(toolName string) EffectClass {
	if de.catalog == nil {
		return EffectClassE3
	}

	capability, ok := de.catalog.Get(toolName)
	if !ok {
		return EffectClassE3
	}

	switch EffectClass(capability.EffectClass) {
	case EffectClassE0, EffectClassE1, EffectClassE2, EffectClassE3, EffectClassE4:
		return EffectClass(capability.EffectClass)
	default:
		return EffectClassE3
	}
}
