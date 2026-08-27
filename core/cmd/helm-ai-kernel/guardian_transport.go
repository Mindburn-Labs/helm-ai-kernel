package main

import (
	"context"
	"fmt"
	"strings"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

type guardianTransportBinding struct {
	EffectClass               string
	Destination               string
	EgressDestinationRequired bool
	SessionID                 string
	SourceChannel             contracts.SourceChannel
	TrustLevel                contracts.InputTrustLevel
}

// bindAuthenticatedGuardianContext removes caller-authored security evidence
// and replaces it with values sourced from authenticated middleware and the
// trusted transport adapter.
func bindAuthenticatedGuardianContext(ctx context.Context, values map[string]any, binding guardianTransportBinding) error {
	if values == nil {
		return fmt.Errorf("guardian transport context is required")
	}
	for key := range values {
		if guardian.IsReservedSecurityContextKey(key) {
			delete(values, key)
		}
	}
	credentialHash, ok := helmauth.AuthenticatedCredentialHash(ctx)
	if !ok {
		return fmt.Errorf("authenticated credential evidence is unavailable")
	}
	values[guardian.ContextSecurityTrusted] = true
	values[guardian.ContextCredentialHash] = credentialHash
	if value := strings.TrimSpace(binding.EffectClass); value != "" {
		values[guardian.ContextEffectClass] = value
	}
	if value := strings.TrimSpace(binding.Destination); value != "" {
		values[guardian.ContextDestination] = value
	}
	if binding.EgressDestinationRequired {
		values[guardian.ContextEgressDestinationRequired] = true
	}
	if value := strings.TrimSpace(binding.SessionID); value != "" {
		values[guardian.ContextSessionID] = value
	}
	if binding.SourceChannel != "" {
		values[guardian.ContextSourceChannel] = string(binding.SourceChannel)
	}
	if binding.TrustLevel != "" {
		values[guardian.ContextTrustLevel] = string(binding.TrustLevel)
	}
	return nil
}
