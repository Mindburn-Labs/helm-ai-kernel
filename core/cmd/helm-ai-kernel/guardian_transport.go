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
	EffectClassSource string
	// EffectClassDeclared is the caller's own value when EffectClass is not it.
	EffectClassDeclared       string
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
		if declared := strings.TrimSpace(binding.EffectClassDeclared); declared != "" && declared != value {
			values[guardian.ContextEffectClassDeclared] = declared
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

// resolveEffectClass returns the effect class to bind for an evaluated
// request, who asserted it, and the caller's own value when that is not what
// was bound.
//
// The request's value is a declaration. It is bound as it is (the public
// contract lets it carry a policy label that is not E0..E4, and policy rules
// may match one), marked caller_declared, unless the kernel's effect type
// catalog knows the action or the resource: then the bound class is never
// below the catalog's, so a caller cannot talk a catalogued effect under a
// policy ceiling by declaring a lower class, a label, or by naming the effect
// as the resource of a tool call. The replaced declaration is returned so a
// rule that restricts on it still sees it.
func resolveEffectClass(action, resource, declared string) (class, source, replaced string) {
	declared = strings.TrimSpace(declared)
	floor := ""
	for _, id := range []string{action, resource} {
		// E0..E4 order as strings.
		if catalogued, ok := contracts.CataloguedEffectClass(strings.TrimSpace(id)); ok && catalogued > floor {
			floor = catalogued
		}
	}
	switch {
	case floor != "" && (!contracts.ValidEffectClass(declared) || declared <= floor):
		if declared == floor {
			declared = ""
		}
		return floor, guardian.EffectClassSourceEffectCatalog, declared
	case declared != "":
		return declared, guardian.EffectClassSourceCallerDeclared, ""
	default:
		return "", "", ""
	}
}
