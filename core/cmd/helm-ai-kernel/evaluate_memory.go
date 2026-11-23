package main

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

func isMemoryEvaluateAction(tool string) bool {
	return strings.HasPrefix(strings.TrimSpace(tool), "memory.")
}

var memoryEvaluateArgKeys = map[string]struct{}{
	"schema_version":  {},
	"operation":       {},
	"memory_class":    {},
	"scope":           {},
	"target_scope":    {},
	"data_class":      {},
	"data_boundary":   {},
	"purpose":         {},
	"content_hash":    {},
	"query_hash":      {},
	"record_id":       {},
	"entry_id":        {},
	"provenance_hash": {},
	"retention_days":  {},
	"provider_id":     {},
	"model_id":        {},
	"budget":          {},
}

var memoryEvaluateBudgetKeys = map[string]struct{}{
	"decision":     {},
	"receipt_hash": {},
}

const memorySchemaVersion = "memory-policy/v1"

var (
	memoryHashPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	memoryProviderPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	memoryModelPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

	memoryOperationValues = map[string]struct{}{
		"memory.read":    {},
		"memory.write":   {},
		"memory.promote": {},
		"memory.egress":  {},
	}
	memoryClassValues = map[string]struct{}{
		"M0_EPHEMERAL":  {},
		"M1_EPISODIC":   {},
		"M2_ENTITY":     {},
		"M3_SEMANTIC":   {},
		"M4_PROCEDURAL": {},
	}
	memoryScopeValues = map[string]struct{}{
		"PRIVATE":   {},
		"WORKSPACE": {},
		"COMPANY":   {},
	}
	memoryTargetScopeValues = map[string]struct{}{
		"WORKSPACE": {},
		"COMPANY":   {},
	}
	memoryDataClassValues = map[string]struct{}{
		"PUBLIC":       {},
		"INTERNAL":     {},
		"CONFIDENTIAL": {},
		"PII":          {},
		"REGULATED":    {},
	}
	memoryDataBoundaryValues = map[string]struct{}{
		"local_only":   {},
		"org_boundary": {},
		"external":     {},
	}
	memoryBudgetDecisionValues = map[string]struct{}{
		"ALLOW": {},
		"DENY":  {},
	}
)

// validateMemoryEvaluateArgs enforces the source-owned memory policy input
// schema at the HTTP edge. The reserved Control Plane authority envelope is
// an additive wire binding and is validated separately. Keeping this
// validation typed and closed prevents policy text patterns from interpreting
// unknown siblings or nested values as source fields.
func validateMemoryEvaluateArgs(args map[string]any, tool string) error {
	if args == nil {
		return fmt.Errorf("evaluate memory args must be an object")
	}
	if _, ok := args["budget"]; !ok {
		return fmt.Errorf("evaluate memory args field %q is required", "budget")
	}
	for key, value := range args {
		if key == evaluateAuthorityArgsKey {
			continue
		}
		if _, ok := memoryEvaluateArgKeys[key]; !ok {
			return fmt.Errorf("evaluate memory args field %q is not permitted", key)
		}
		if key == "budget" {
			if err := validateMemoryBudget(value); err != nil {
				return err
			}
		} else if isCompositeEvaluateValue(value) {
			return fmt.Errorf("evaluate memory args field %q must be a scalar", key)
		}
	}

	schemaVersion, err := requireMemoryString(args, "schema_version")
	if err != nil {
		return err
	}
	if schemaVersion != memorySchemaVersion {
		return fmt.Errorf("evaluate memory args field %q has an invalid value", "schema_version")
	}
	operation, err := requireMemoryEnum(args, "operation", memoryOperationValues)
	if err != nil {
		return err
	}
	if operation != strings.TrimSpace(tool) {
		return fmt.Errorf("evaluate memory args operation does not match tool")
	}
	if _, err := requireMemoryEnum(args, "memory_class", memoryClassValues); err != nil {
		return err
	}
	if _, err := requireMemoryEnum(args, "scope", memoryScopeValues); err != nil {
		return err
	}
	if _, err := optionalMemoryEnum(args, "target_scope", memoryTargetScopeValues); err != nil {
		return err
	}
	if _, err := requireMemoryEnum(args, "data_class", memoryDataClassValues); err != nil {
		return err
	}
	dataBoundary, err := requireMemoryEnum(args, "data_boundary", memoryDataBoundaryValues)
	if err != nil {
		return err
	}
	if purpose, err := requireMemoryString(args, "purpose"); err != nil {
		return err
	} else if err := validateMemoryStringLength("purpose", purpose, 1, 512); err != nil {
		return err
	}
	if _, err := requireMemoryHash(args, "content_hash"); err != nil {
		return err
	}
	if _, err := optionalMemoryHash(args, "query_hash"); err != nil {
		return err
	}
	if _, err := optionalMemoryBoundedString(args, "record_id", 1, 256); err != nil {
		return err
	}
	if _, err := optionalMemoryBoundedString(args, "entry_id", 1, 256); err != nil {
		return err
	}
	if _, err := optionalMemoryHash(args, "provenance_hash"); err != nil {
		return err
	}
	if _, err := optionalMemoryInteger(args, "retention_days"); err != nil {
		return err
	}
	if _, err := optionalMemoryPattern(args, "provider_id", memoryProviderPattern); err != nil {
		return err
	}
	if _, err := optionalMemoryPattern(args, "model_id", memoryModelPattern); err != nil {
		return err
	}

	switch operation {
	case "memory.read":
		if _, err := requireMemoryHash(args, "query_hash"); err != nil {
			return err
		}
		if dataBoundary != "local_only" && dataBoundary != "org_boundary" {
			return fmt.Errorf("evaluate memory args field %q is incompatible with operation", "data_boundary")
		}
	case "memory.write":
		if _, err := requireMemoryBoundedString(args, "record_id", 1, 256); err != nil {
			return err
		}
		if _, err := requireMemoryHash(args, "provenance_hash"); err != nil {
			return err
		}
		if _, err := requireMemoryInteger(args, "retention_days"); err != nil {
			return err
		}
		if dataBoundary != "local_only" && dataBoundary != "org_boundary" {
			return fmt.Errorf("evaluate memory args field %q is incompatible with operation", "data_boundary")
		}
	case "memory.promote":
		if _, err := requireMemoryBoundedString(args, "entry_id", 1, 256); err != nil {
			return err
		}
		if _, err := requireMemoryHash(args, "provenance_hash"); err != nil {
			return err
		}
		targetScope, err := requireMemoryEnum(args, "target_scope", memoryTargetScopeValues)
		if err != nil {
			return err
		}
		scope, err := requireMemoryEnum(args, "scope", memoryScopeValues)
		if err != nil {
			return err
		}
		if scope != "PRIVATE" || dataBoundary != "org_boundary" || targetScope == "" {
			return fmt.Errorf("evaluate memory args scope and boundary are incompatible with operation")
		}
	case "memory.egress":
		if _, err := requireMemoryPattern(args, "provider_id", memoryProviderPattern); err != nil {
			return err
		}
		if _, err := requireMemoryPattern(args, "model_id", memoryModelPattern); err != nil {
			return err
		}
		if dataBoundary != "external" {
			return fmt.Errorf("evaluate memory args field %q is incompatible with operation", "data_boundary")
		}
	}
	return nil
}

func validateMemoryBudget(value any) error {
	budget, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("evaluate memory args budget must be an object")
	}
	for key, nested := range budget {
		if _, ok := memoryEvaluateBudgetKeys[key]; !ok {
			return fmt.Errorf("evaluate memory args budget field %q is not permitted", key)
		}
		if isCompositeEvaluateValue(nested) {
			return fmt.Errorf("evaluate memory args budget field %q must be a scalar", key)
		}
	}
	decision, err := requireMemoryEnumFromObject(budget, "decision", memoryBudgetDecisionValues)
	if err != nil {
		return err
	}
	if decision == "" {
		return fmt.Errorf("evaluate memory args budget field %q is required", "decision")
	}
	if _, err := requireMemoryHashFromObject(budget, "receipt_hash"); err != nil {
		return err
	}
	return nil
}

func requireMemoryString(args map[string]any, key string) (string, error) {
	value, ok := args[key]
	if !ok {
		return "", fmt.Errorf("evaluate memory args field %q is required", key)
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("evaluate memory args field %q must be a string", key)
	}
	return stringValue, nil
}

func optionalMemoryString(args map[string]any, key string) (string, bool, error) {
	value, ok := args[key]
	if !ok {
		return "", false, nil
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", true, fmt.Errorf("evaluate memory args field %q must be a string", key)
	}
	return stringValue, true, nil
}

func requireMemoryEnum(args map[string]any, key string, allowed map[string]struct{}) (string, error) {
	value, err := requireMemoryString(args, key)
	if err != nil {
		return "", err
	}
	if _, ok := allowed[value]; !ok {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid value", key)
	}
	return value, nil
}

func optionalMemoryEnum(args map[string]any, key string, allowed map[string]struct{}) (string, error) {
	value, present, err := optionalMemoryString(args, key)
	if err != nil || !present {
		return value, err
	}
	if _, ok := allowed[value]; !ok {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid value", key)
	}
	return value, nil
}

func requireMemoryEnumFromObject(object map[string]any, key string, allowed map[string]struct{}) (string, error) {
	value, err := requireMemoryStringFromObject(object, key)
	if err != nil {
		return "", err
	}
	if _, ok := allowed[value]; !ok {
		return "", fmt.Errorf("evaluate memory args budget field %q has an invalid value", key)
	}
	return value, nil
}

func requireMemoryStringFromObject(object map[string]any, key string) (string, error) {
	value, ok := object[key]
	if !ok {
		return "", fmt.Errorf("evaluate memory args budget field %q is required", key)
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("evaluate memory args budget field %q must be a string", key)
	}
	return stringValue, nil
}

func requireMemoryHash(args map[string]any, key string) (string, error) {
	value, err := requireMemoryString(args, key)
	if err != nil {
		return "", err
	}
	if !memoryHashPattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid hash", key)
	}
	return value, nil
}

func optionalMemoryHash(args map[string]any, key string) (string, error) {
	value, present, err := optionalMemoryString(args, key)
	if err != nil || !present {
		return value, err
	}
	if !memoryHashPattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid hash", key)
	}
	return value, nil
}

func requireMemoryHashFromObject(object map[string]any, key string) (string, error) {
	value, err := requireMemoryStringFromObject(object, key)
	if err != nil {
		return "", err
	}
	if !memoryHashPattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args budget field %q has an invalid hash", key)
	}
	return value, nil
}

func validateMemoryStringLength(key, value string, min, max int) error {
	length := utf8.RuneCountInString(value)
	if length < min || length > max {
		return fmt.Errorf("evaluate memory args field %q has an invalid length", key)
	}
	return nil
}

func requireMemoryBoundedString(args map[string]any, key string, min, max int) (string, error) {
	value, err := requireMemoryString(args, key)
	if err != nil {
		return "", err
	}
	if err := validateMemoryStringLength(key, value, min, max); err != nil {
		return "", err
	}
	return value, nil
}

func optionalMemoryBoundedString(args map[string]any, key string, min, max int) (string, error) {
	value, present, err := optionalMemoryString(args, key)
	if err != nil || !present {
		return value, err
	}
	if err := validateMemoryStringLength(key, value, min, max); err != nil {
		return "", err
	}
	return value, nil
}

func requireMemoryPattern(args map[string]any, key string, pattern *regexp.Regexp) (string, error) {
	value, err := requireMemoryString(args, key)
	if err != nil {
		return "", err
	}
	if !pattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid value", key)
	}
	return value, nil
}

func optionalMemoryPattern(args map[string]any, key string, pattern *regexp.Regexp) (string, error) {
	value, present, err := optionalMemoryString(args, key)
	if err != nil || !present {
		return value, err
	}
	if !pattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid value", key)
	}
	return value, nil
}

func requireMemoryInteger(args map[string]any, key string) (float64, error) {
	value, ok := args[key]
	if !ok {
		return 0, fmt.Errorf("evaluate memory args field %q is required", key)
	}
	return validateMemoryInteger(key, value)
}

func optionalMemoryInteger(args map[string]any, key string) (float64, error) {
	value, ok := args[key]
	if !ok {
		return 0, nil
	}
	return validateMemoryInteger(key, value)
}

func validateMemoryInteger(key string, value any) (float64, error) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < 1 || number > 3650 {
		return 0, fmt.Errorf("evaluate memory args field %q must be an integer from 1 through 3650", key)
	}
	return number, nil
}

func isCompositeEvaluateValue(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}

var evaluateAuthorityContextKeys = map[string]struct{}{
	"principal":    {},
	"principal_id": {},
	"agent_id":     {},
	"tenant":       {},
	"tenantId":     {},
	"tenant_id":    {},
	"workspace":    {},
	"workspaceId":  {},
	"workspace_id": {},
}

// validateMemoryEvaluateContext rejects nested identity aliases that could
// satisfy a policy pattern without being the route's authenticated binding.
// Top-level aliases retain the legacy route behavior: they are stripped and
// replaced below with authenticated values.
func validateMemoryEvaluateContext(context map[string]any) error {
	state := evaluateAuthorityWalkState{}
	return walkMemoryEvaluateContext(context, true, &state)
}

func walkMemoryEvaluateContext(value any, topLevel bool, state *evaluateAuthorityWalkState) error {
	composite := false
	switch value.(type) {
	case map[string]any, []any:
		composite = true
	}
	if err := state.enter(composite); err != nil {
		return err
	}
	if composite {
		defer state.leave(true)
	}

	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if !topLevel {
				if _, authorityKey := evaluateAuthorityContextKeys[key]; authorityKey {
					return fmt.Errorf("evaluate memory context authority keys may only appear at the top level")
				}
			}
			if err := walkMemoryEvaluateContext(nested, false, state); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range typed {
			if err := walkMemoryEvaluateContext(nested, false, state); err != nil {
				return err
			}
		}
	}
	return nil
}
