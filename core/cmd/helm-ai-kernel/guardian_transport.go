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
// may match one) and marked caller_declared, unless the kernel's effect type
// catalog knows the evaluated action: then the bound class is never below the
// catalog's and is marked effect_catalog, so a caller cannot talk a catalogued
// effect under a policy ceiling by declaring a lower class or a label.
//
// The evaluated action is the request's action. For EXECUTE_TOOL it is also
// the resource, because Guardian evaluates that resource as the tool. The
// resource of any other action is the caller's description of what the action
// touches and proves nothing about the action. A catalogued effect named
// there raises a class the caller declared and does nothing else: it never
// lowers the class, never turns a label into a class and never makes the
// class catalogued. If it did, a caller would choose the class of any action
// by naming an effect beside it, and the signed effect would call that choice
// the kernel's.
//
// The replaced declaration is returned so a rule that restricts on it still
// sees it.
func resolveEffectClass(action, resource, declared string) (class, source, replaced string) {
	declared = strings.TrimSpace(declared)
	class = declared
	// E0..E4 order as strings. An id the catalog does not know leaves floor
	// empty.
	floor, _ := contracts.CataloguedEffectClass(strings.TrimSpace(action))
	if named, ok := contracts.CataloguedEffectClass(strings.TrimSpace(resource)); ok {
		// The exact comparison Guardian binds the tool by.
		if action == "EXECUTE_TOOL" {
			if named > floor {
				floor = named
			}
		} else if contracts.ValidEffectClass(class) && named > class {
			class = named
		}
	}
	switch {
	case floor != "" && (!contracts.ValidEffectClass(class) || class <= floor):
		class, source = floor, guardian.EffectClassSourceEffectCatalog
	case class != "":
		source = guardian.EffectClassSourceCallerDeclared
	default:
		return "", "", ""
	}
	if declared != class {
		replaced = declared
	}
	return class, source, replaced
}
