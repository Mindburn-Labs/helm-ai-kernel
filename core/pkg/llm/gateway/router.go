// Package gateway provides the Local Inference Gateway (LIG).
//
// The Local Inference Gateway forcibly normalizes execution across divergent
// local providers (Ollama, llama.cpp, vLLM, LM Studio) to ensure they meet
// strict HELM capability contracts.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// GatewayRouter normalizes capability requests across providers.
type GatewayRouter struct {
	activeProfile *Profile
}

// NewGatewayRouter creates a new instance of the Local Inference Gateway router.
func NewGatewayRouter() *GatewayRouter {
	return &GatewayRouter{}
}

// Route ensures the requested execution matches a blessed profile and routes it securely.
func (r *GatewayRouter) Route(ctx context.Context, profileID string) error {
	profiles := GetBlessedProfiles()
	var selected *Profile
	for _, p := range profiles {
		if p.ID == profileID {
			pcopy := p
			selected = &pcopy
			break
		}
	}
	
	if selected == nil {
		return fmt.Errorf("lig: access denied, unblessed profile '%s'", profileID)
	}
	
	r.activeProfile = selected
	return nil
}

// ActiveProfile returns the currently bound profile.
func (r *GatewayRouter) ActiveProfile() *Profile {
	return r.activeProfile
}

// ExecContext represents normalized LLM execution parameters within HELM.
type ExecContext struct {
	Prompt      string
	Temperature float32
	System      string
	JSONMode    bool
	Tools       []string // Simplified tool URIs
}

// ExecResult encapsulates the normalized output alongside telemetry for ProofGraph receipts.
type ExecResult struct {
	Content      string
	GatewayID    string
	RuntimeType  ProviderType
	RuntimeVersion string
	ModelHash    string
	Duration     time.Duration
}

// Execute performs an inference request, enforcing LIG constraints.
func (r *GatewayRouter) Execute(ctx context.Context, req ExecContext) (*ExecResult, error) {
	if r.activeProfile == nil {
		return nil, errors.New("lig: no active profile routed; must call Route() first")
	}
	
	// Capability Guards
	if req.JSONMode && !r.activeProfile.Capabilities.SupportsJSONMode {
		return nil, fmt.Errorf("lig: capability constraint violation; model %s does not support JSON mode", r.activeProfile.ID)
	}
	if len(req.Tools) > 0 && !r.activeProfile.Capabilities.SupportsTools {
		return nil, fmt.Errorf("lig: capability constraint violation; model %s does not support tools", r.activeProfile.ID)
	}

	start := time.Now()
	
	// Simulated execution routing. The true implementation binds to the respective 
	// JSON/HTTP APIs of the providers (e.g. localhost:11434 for Ollama).
	time.Sleep(50 * time.Millisecond)
	
	return &ExecResult{
		Content:        fmt.Sprintf("LIG Normalized Execution: Simulated output for %s", req.Prompt),
		GatewayID:      "lig-local-node-01",
		RuntimeType:    r.activeProfile.Provider,
		RuntimeVersion: "1.0.0", // Extracted dynamically in full implementation
		ModelHash:      "sha256-pending", // Exact hash snapshot prevents substitution attacks
		Duration:       time.Since(start),
	}, nil
}
