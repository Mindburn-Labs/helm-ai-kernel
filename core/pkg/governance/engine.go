package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/capabilities"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
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
	// Create Keyring with Memory Provider (or HSM in prod)
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
	// 1. Parse Payload
	type Payload struct {
		Action string `json:"action"`
	}
	var p Payload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("malformed payload: %w", err)
	}
	toolName := p.Action

	// 2. Resolve Capability & Effect
	var effect EffectClass
	if de.catalog != nil {
		if cap, ok := de.catalog.Get(toolName); ok {
			// Resolve effect based on capabilities
			// Map tool capability's effect class to EffectClass type
			effect = EffectClass(cap.EffectClass)
			if effect == "" {
				// Default mapping if missing
				// Or use resolver if it still exists (it was deleted? No, wait, I deleted capabilities/effects.go but `capabilities` package exists)
				// I deleted effects.go, so NewEffectResolver matching call above might fail if it was in that file.
				// engine.go imports `capabilities`.
				// If `NewEffectResolver` was in `effects.go`, the code above `capabilities.NewEffectResolver()` will fail.
				// I should remove `resolver` field and usage if I deleted the file.
				// Fallback to strict E3
				effect = EffectClassE3
			}
		} else {
			// Unknown tool? Default to High Risk
			effect = EffectClassE3
		}
	} else {
		// No catalog? Fallback to legacy
		effect = EffectClassE3
	}

	// 3. Enforce Safety Policy (The "Constitution")
	// E4: Always DENY in this MVP (requires Human Loop)
	if effect == EffectClassE4 {
		return nil, fmt.Errorf("SAFETY VIOLATION: E4 action '%s' requires human approval (not implemented)", toolName)
	}

	// E3: Strict Allowlist
	if effect == EffectClassE3 {
		if !de.policy[toolName] {
			return nil, fmt.Errorf("policy violation: E3 action '%s' not explicitly allowed", toolName)
		}
	}

	// E0-E2: Allowed (Soft Actions)
	// Fallthrough

	decision := &DecisionRecord{
		ID:           uuid.New().String(),
		IntentID:     intentID,
		Decision:     "PERMIT",
		PolicyID:     "policy-safety-v1",
		Timestamp:    time.Now(),
		EffectDigest: string(effect),
	}

	// 4. Sign Decision
	sig, err := de.keyring.Sign(decision)
	if err != nil {
		return nil, err
	}
	decision.Signature = sig

	// 5. Mint ExecutionIntent
	execIntent := &ExecutionIntent{
		ID:               uuid.New().String(),
		TargetCapability: toolName,
		Payload:          payload,
		DecisionID:       decision.ID,
	}

	// 6. Sign ExecutionIntent
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
