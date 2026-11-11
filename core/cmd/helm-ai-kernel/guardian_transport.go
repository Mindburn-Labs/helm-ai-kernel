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
	EffectClass string
	// EffectClassSource is who asserted EffectClass, one of the
	// guardian.EffectClassSource values. It is bound with the class so the
	// signed effect never presents a caller's declaration as attested.
	EffectClassSource         string
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
		if binding.EffectClassSource != "" {
			values[guardian.ContextEffectClassSource] = binding.EffectClassSource
		}
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

// resolveEffectClass returns the effect class to bind for an evaluated action
// and who asserted it. The request's value is a caller declaration: it is
// bound only when it is one of E0..E4, and never below the class the kernel's
// effect type catalog gives the action, so a caller cannot talk a catalogued
// effect under a policy ceiling. A value that is not a class (the public
// contract lets effect_level carry a policy resource) binds no class at all.
func resolveEffectClass(action, declared string) (class, source string) {
	declared = strings.TrimSpace(declared)
	if !contracts.ValidEffectClass(declared) {
		declared = ""
	}
	catalogued := ""
	if contracts.LookupEffectType(action) != nil {
		catalogued = contracts.EffectRiskClass(action)
	}
	switch {
	case catalogued != "" && declared <= catalogued:
		// E0..E4 order as strings; an undeclared class is the empty string.
		return catalogued, guardian.EffectClassSourceEffectCatalog
	case declared != "":
		return declared, guardian.EffectClassSourceCallerDeclared
	default:
		return "", ""
	}
}
