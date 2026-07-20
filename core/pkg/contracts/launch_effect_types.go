package contracts

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	// LaunchEffectCatalogVersion is intentionally a prerelease. Launch effects
	// are not admitted by DefaultEffectCatalog or the Kernel policy boundary
	// until their consumer schemas, policies, connector certification, and
	// conformance vectors are promoted atomically.
	LaunchEffectCatalogVersion     = "1.1.0-alpha.1"
	LaunchEffectInputSchemaVersion = "launch_effect_input.v1"
	LaunchEffectStatusPreview      = "preview"

	launchAuthorizationEnvelopeSchema = "effects/launch/launch_effect_envelope.v1.json"
	launchReceiptSchema               = "effects/launch/launch_effect_receipt.v1.json"

	LaunchActionProviderProvision        = "urn:helm:provider-route:provision"
	LaunchActionDeployProductionActivate = "urn:helm:provider-route:activate"
	LaunchActionSpendAuthorize           = "urn:helm:spend:authorize"
	LaunchActionProviderRollback         = "urn:helm:provider-route:rollback"
	LaunchActionProviderTeardown         = "urn:helm:provider-route:teardown"
	LaunchActionCompanyArtifactUpdate    = "urn:helm:company-artifact:update"

	// LaunchConnectorProviderRoute is the only provider-effect entry point at
	// the Kernel boundary. The exact provider connector and action are bound
	// inside the approved RouteBinding and canonical effect input. This keeps
	// provider-specific vocabulary out of the Kernel taxonomy without granting
	// a wildcard connector capability.
	LaunchConnectorProviderRoute  = "helm-provider-route"
	LaunchConnectorSpendAuthority = "helm-spend-authority"
	LaunchConnectorCompanyState   = "helm-company-state"

	// DigitalOcean remains the first provider profile and conformance fixture;
	// these identifiers are deliberately not used as Kernel catalog bounds.
	LaunchConnectorDigitalOcean               = "digitalocean-app-platform"
	LaunchProviderActionDigitalOceanProvision = "urn:helm:connector:digitalocean:apps:create"
	LaunchProviderActionDigitalOceanActivate  = "urn:helm:connector:digitalocean:apps:activate"
	LaunchProviderActionDigitalOceanRollback  = "urn:helm:connector:digitalocean:deployments:rollback"
	LaunchProviderActionDigitalOceanTeardown  = "urn:helm:connector:digitalocean:apps:delete"
)

// LaunchMissionEffectCatalogPreview returns the source-owned preview contract
// for Launch Mission effects. Catalog membership is descriptive, not
// authorization. Authority Court is the sole policy evaluator, and these
// effects deliberately remain absent from DefaultEffectCatalog until promotion.
func LaunchMissionEffectCatalogPreview() *EffectTypeCatalog {
	commonHooks := []string{
		"base_effect_expansion",
		"authority_court",
		"single_use_effect_permit",
		"emergency_dispatch_fence",
	}

	return &EffectTypeCatalog{
		CatalogVersion: LaunchEffectCatalogVersion,
		EffectTypes: []EffectType{
			{
				TypeID:                      EffectTypeProviderProvision,
				Name:                        "Provider Provision",
				Description:                 "Creates the exact provider resource set bound to a launch plan, canonical spend authority, and a fresh single-use permit.",
				Status:                      LaunchEffectStatusPreview,
				Taxon:                       "E3",
				BaseEffectTypes:             []string{"INFRA_CHANGE", "BILLING_CHANGE", "EXTERNAL_API_CALL"},
				Idempotency:                 launchIdempotency("reconcile_then_return_existing"),
				Classification:              Classification{Reversibility: "compensatable", BlastRadius: "system_wide", Urgency: "time_sensitive"},
				DefaultApprovalLevel:        "single_human",
				RequiresEvidence:            true,
				CompensationRequired:        false,
				CompensationEffectType:      EffectTypeProviderTeardown,
				CompensationAuthorization:   "fresh_dual_control_only_no_preauthorization",
				InputSchema:                 "effects/launch/provider_provision.v1.json",
				AuthorizationEnvelopeSchema: launchAuthorizationEnvelopeSchema,
				ReceiptSchema:               launchReceiptSchema,
				ConnectorID:                 LaunchConnectorProviderRoute,
				ActionURN:                   LaunchActionProviderProvision,
				PreflightRequired:           true,
				TwoPhaseCommitRequired:      true,
				MinEvidenceGrade:            "E3",
				PolicyHooks:                 appendHooks(commonHooks, "spend_authority", "provider_reconciliation", "failure_freeze_until_fresh_teardown"),
			},
			{
				TypeID:                      EffectTypeDeployProductionActivate,
				Name:                        "Production Deployment Activate",
				Description:                 "Cuts over one immutable, verified deployment; it grants no standing or deployment-on-push authority.",
				Status:                      LaunchEffectStatusPreview,
				Taxon:                       "E3",
				BaseEffectTypes:             []string{"DEPLOY_RELEASE", "CONFIG_CHANGE"},
				Idempotency:                 launchIdempotency("reconcile_then_return_existing"),
				Classification:              Classification{Reversibility: "compensatable", BlastRadius: "system_wide", Urgency: "time_sensitive"},
				DefaultApprovalLevel:        "single_human",
				RequiresEvidence:            true,
				CompensationRequired:        true,
				CompensationEffectType:      EffectTypeProviderRollback,
				CompensationAuthorization:   "preauthorized_exact_target_or_fresh_single_human",
				InputSchema:                 "effects/launch/deploy_production_activate.v1.json",
				AuthorizationEnvelopeSchema: launchAuthorizationEnvelopeSchema,
				ReceiptSchema:               launchReceiptSchema,
				ConnectorID:                 LaunchConnectorProviderRoute,
				ActionURN:                   LaunchActionDeployProductionActivate,
				PreflightRequired:           true,
				TwoPhaseCommitRequired:      true,
				MinEvidenceGrade:            "E3",
				PolicyHooks:                 appendHooks(commonHooks, "release_authority", "provider_reconciliation", "rollback_target_binding"),
			},
			{
				TypeID:                      EffectTypeSpendAuthorize,
				Name:                        "Spend Authorize",
				Description:                 "Records a bounded, expiring monthly spend authorization for customer-owned billing; it never moves, holds, or commits customer funds.",
				Status:                      LaunchEffectStatusPreview,
				Taxon:                       "E3",
				BaseEffectTypes:             []string{"BILLING_CHANGE"},
				Idempotency:                 launchIdempotency("return_existing"),
				Classification:              Classification{Reversibility: "reversible", BlastRadius: "system_wide", Urgency: "time_sensitive"},
				DefaultApprovalLevel:        "single_human",
				RequiresEvidence:            true,
				CompensationRequired:        false,
				CompensationAuthorization:   "expiry_or_explicit_revoke",
				InputSchema:                 "effects/launch/spend_authorize.v1.json",
				AuthorizationEnvelopeSchema: launchAuthorizationEnvelopeSchema,
				ReceiptSchema:               launchReceiptSchema,
				ConnectorID:                 LaunchConnectorSpendAuthority,
				ActionURN:                   LaunchActionSpendAuthorize,
				PreflightRequired:           true,
				TwoPhaseCommitRequired:      true,
				MinEvidenceGrade:            "E3",
				PolicyHooks:                 appendHooks(commonHooks, "spend_authority", "provider_terms", "monthly_gross_cap"),
			},
			{
				TypeID:                      EffectTypeProviderRollback,
				Name:                        "Provider Rollback",
				Description:                 "Restores one exact immutable deployment using compare-and-set source and target state bindings.",
				Status:                      LaunchEffectStatusPreview,
				Taxon:                       "E3",
				BaseEffectTypes:             []string{"DEPLOY_RELEASE", "INFRA_CHANGE"},
				Idempotency:                 launchIdempotency("reconcile_then_return_existing"),
				Classification:              Classification{Reversibility: "compensatable", BlastRadius: "system_wide", Urgency: "immediate"},
				DefaultApprovalLevel:        "single_human",
				RequiresEvidence:            true,
				CompensationRequired:        false,
				CompensationAuthorization:   "compensation_terminal_or_fresh_activation",
				InputSchema:                 "effects/launch/provider_rollback.v1.json",
				AuthorizationEnvelopeSchema: launchAuthorizationEnvelopeSchema,
				ReceiptSchema:               launchReceiptSchema,
				ConnectorID:                 LaunchConnectorProviderRoute,
				ActionURN:                   LaunchActionProviderRollback,
				PreflightRequired:           true,
				TwoPhaseCommitRequired:      true,
				MinEvidenceGrade:            "E3",
				PolicyHooks:                 appendHooks(commonHooks, "release_authority", "provider_reconciliation", "compare_and_set_state"),
			},
			{
				TypeID:                      EffectTypeProviderTeardown,
				Name:                        "Provider Teardown",
				Description:                 "Deletes only the exact mission-owned resource after fresh dual-control approval and destructive-state clearance.",
				Status:                      LaunchEffectStatusPreview,
				Taxon:                       "E4",
				BaseEffectTypes:             []string{"DATA_DELETE", "INFRA_CHANGE", "BILLING_CHANGE"},
				Idempotency:                 launchIdempotency("reconcile_then_return_existing"),
				Classification:              Classification{Reversibility: "irreversible", BlastRadius: "system_wide", Urgency: "time_sensitive"},
				DefaultApprovalLevel:        "dual_control",
				RequiresEvidence:            true,
				CompensationRequired:        false,
				CompensationAuthorization:   "none_irreversible",
				InputSchema:                 "effects/launch/provider_teardown.v1.json",
				AuthorizationEnvelopeSchema: launchAuthorizationEnvelopeSchema,
				ReceiptSchema:               launchReceiptSchema,
				ConnectorID:                 LaunchConnectorProviderRoute,
				ActionURN:                   LaunchActionProviderTeardown,
				PreflightRequired:           true,
				TwoPhaseCommitRequired:      true,
				MinEvidenceGrade:            "E3",
				PolicyHooks:                 appendHooks(commonHooks, "fresh_dual_control", "ownership_proof", "retention_clearance", "provider_reconciliation"),
			},
			{
				TypeID:                      EffectTypeCompanyArtifactUpdate,
				Name:                        "Company Artifact Update",
				Description:                 "Promotes a reconciled mission result into company state using an exact compare-and-set revision.",
				Status:                      LaunchEffectStatusPreview,
				Taxon:                       "E2",
				BaseEffectTypes:             []string{"DATA_WRITE"},
				Idempotency:                 launchIdempotency("return_existing"),
				Classification:              Classification{Reversibility: "reversible", BlastRadius: "dataset", Urgency: "deferrable"},
				DefaultApprovalLevel:        "single_human",
				RequiresEvidence:            true,
				CompensationRequired:        true,
				CompensationEffectType:      EffectTypeCompanyArtifactUpdate,
				CompensationAuthorization:   "fresh_single_human_compare_and_set",
				InputSchema:                 "effects/launch/company_artifact_update.v1.json",
				AuthorizationEnvelopeSchema: launchAuthorizationEnvelopeSchema,
				ReceiptSchema:               launchReceiptSchema,
				ConnectorID:                 LaunchConnectorCompanyState,
				ActionURN:                   LaunchActionCompanyArtifactUpdate,
				PreflightRequired:           true,
				TwoPhaseCommitRequired:      true,
				MinEvidenceGrade:            "E2",
				PolicyHooks:                 appendHooks(commonHooks, "mission_reconciliation", "artifact_compare_and_set", "evidence_pack_finalized"),
			},
		},
	}
}

// LookupLaunchMissionEffectPreview returns a preview definition without making
// it executable through the default runtime catalog.
func LookupLaunchMissionEffectPreview(typeID string) *EffectType {
	catalog := LaunchMissionEffectCatalogPreview()
	for i := range catalog.EffectTypes {
		if catalog.EffectTypes[i].TypeID == typeID {
			return &catalog.EffectTypes[i]
		}
	}
	return nil
}

// IsLaunchMissionEffectPreview reports whether an identifier is reserved by the
// non-executable Launch Mission preview catalog.
func IsLaunchMissionEffectPreview(typeID string) bool {
	return LookupLaunchMissionEffectPreview(typeID) != nil
}

// DeriveLaunchEffectIdempotencyKey hashes the entire schema-validated input
// using RFC 8785 JCS. The effect ID and schema version are part of every input,
// so a contract-version or payload change necessarily produces a new key.
// Callers MUST validate the input schema before deriving the key.
func DeriveLaunchEffectIdempotencyKey(typeID string, input map[string]any) (string, error) {
	contract := LookupLaunchMissionEffectPreview(typeID)
	if contract == nil {
		return "", fmt.Errorf("launch effect %q is not registered", typeID)
	}
	if input == nil {
		return "", errors.New("launch effect input is required")
	}
	if got, ok := input["effect_id"].(string); !ok || got != typeID {
		return "", fmt.Errorf("launch effect input effect_id must equal %q", typeID)
	}
	if got, ok := input["schema_version"].(string); !ok || got != LaunchEffectInputSchemaVersion {
		return "", fmt.Errorf("launch effect input schema_version must equal %q", LaunchEffectInputSchemaVersion)
	}
	normalized, err := normalizeLaunchEffectCanonicalValue(input)
	if err != nil {
		return "", fmt.Errorf("derive launch effect idempotency key: %w", err)
	}
	hash, err := canonicalize.CanonicalHash(normalized)
	if err != nil {
		return "", fmt.Errorf("derive launch effect idempotency key: %w", err)
	}
	return "sha256:" + hash, nil
}

// normalizeLaunchEffectCanonicalValue removes language- and decoder-specific
// integer spellings before JCS. Launch effect schemas intentionally admit only
// integer JSON numbers, so 1, 1.0, json.Number("1e0"), int64(1), and
// float64(1) must all bind the same bytes. Values outside the interoperable
// IEEE-754 safe-integer range fail closed instead of producing hashes that a
// JavaScript or another RFC 8785 implementation cannot reproduce exactly.
func normalizeLaunchEffectCanonicalValue(value any) (any, error) {
	const maxSafeInteger = int64(9007199254740991)
	switch typed := value.(type) {
	case map[string]any:
		normalized := make(map[string]any, len(typed))
		for key, item := range typed {
			canonicalItem, err := normalizeLaunchEffectCanonicalValue(item)
			if err != nil {
				return nil, fmt.Errorf("field %q: %w", key, err)
			}
			normalized[key] = canonicalItem
		}
		return normalized, nil
	case []any:
		normalized := make([]any, len(typed))
		for index, item := range typed {
			canonicalItem, err := normalizeLaunchEffectCanonicalValue(item)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", index, err)
			}
			normalized[index] = canonicalItem
		}
		return normalized, nil
	case json.Number:
		return normalizeLaunchEffectJSONNumber(typed, maxSafeInteger)
	case float64:
		return normalizeLaunchEffectFloat(typed, maxSafeInteger)
	case float32:
		return normalizeLaunchEffectFloat(float64(typed), maxSafeInteger)
	case int:
		return normalizeLaunchEffectSignedInteger(int64(typed), maxSafeInteger)
	case int8:
		return int64(typed), nil
	case int16:
		return int64(typed), nil
	case int32:
		return int64(typed), nil
	case int64:
		return normalizeLaunchEffectSignedInteger(typed, maxSafeInteger)
	case uint:
		return normalizeLaunchEffectUnsignedInteger(uint64(typed), uint64(maxSafeInteger))
	case uint8:
		return int64(typed), nil
	case uint16:
		return int64(typed), nil
	case uint32:
		return int64(typed), nil
	case uint64:
		return normalizeLaunchEffectUnsignedInteger(typed, uint64(maxSafeInteger))
	default:
		return value, nil
	}
}

func normalizeLaunchEffectFloat(value float64, maxSafeInteger int64) (int64, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || math.Abs(value) > float64(maxSafeInteger) {
		return 0, errors.New("number must be an interoperable safe integer")
	}
	return int64(value), nil
}

func normalizeLaunchEffectJSONNumber(value json.Number, maxSafeInteger int64) (int64, error) {
	rational, ok := new(big.Rat).SetString(value.String())
	if !ok || !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, errors.New("JSON number must be an interoperable integer")
	}
	return normalizeLaunchEffectSignedInteger(rational.Num().Int64(), maxSafeInteger)
}

func normalizeLaunchEffectSignedInteger(value, maxSafeInteger int64) (int64, error) {
	if value < -maxSafeInteger || value > maxSafeInteger {
		return 0, errors.New("integer exceeds the interoperable safe-integer range")
	}
	return value, nil
}

func normalizeLaunchEffectUnsignedInteger(value, maxSafeInteger uint64) (int64, error) {
	if value > maxSafeInteger {
		return 0, errors.New("integer exceeds the interoperable safe-integer range")
	}
	return int64(value), nil
}

// ValidateLaunchEffectIdempotencyKey rejects arbitrary caller-provided keys.
func ValidateLaunchEffectIdempotencyKey(typeID string, input map[string]any, provided string) error {
	expected, err := DeriveLaunchEffectIdempotencyKey(typeID, input)
	if err != nil {
		return err
	}
	if len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		return errors.New("launch effect idempotency key does not match canonical input")
	}
	return nil
}

// ValidateLaunchEffectInputSemantics applies cross-field fail-closed checks
// that JSON Schema Draft 2020-12 cannot express portably. Schema validation
// remains a mandatory predecessor.
func ValidateLaunchEffectInputSemantics(typeID string, input map[string]any) error {
	if _, err := DeriveLaunchEffectIdempotencyKey(typeID, input); err != nil {
		return err
	}
	if err := validateLaunchEffectFixedSemantics(typeID, input); err != nil {
		return err
	}
	if typeID != EffectTypeSpendAuthorize {
		return nil
	}

	grossCap, err := launchInteger(input, "gross_cap_minor")
	if err != nil {
		return err
	}
	baseCost, err := launchInteger(input, "base_provider_cost_minor")
	if err != nil {
		return err
	}
	grossExposure, err := launchInteger(input, "gross_exposure_minor")
	if err != nil {
		return err
	}
	expectedCash, err := launchInteger(input, "expected_cash_minor")
	if err != nil {
		return err
	}
	verifiedCredit, err := launchInteger(input, "verified_credit_minor")
	if err != nil {
		return err
	}
	reserve, err := launchInteger(input, "tax_fx_reserve_minor")
	if err != nil {
		return err
	}
	if grossCap < 0 {
		return errors.New("launch spend authorization gross cap cannot be negative")
	}
	if baseCost < 0 || grossExposure < 0 || expectedCash < 0 || verifiedCredit < 0 || reserve < 0 {
		return errors.New("launch spend authorization monetary values cannot be negative")
	}
	if baseCost+reserve != grossExposure {
		return errors.New("launch spend authorization gross exposure must equal base provider cost plus tax and FX reserve")
	}
	if grossExposure > grossCap {
		return errors.New("launch spend authorization gross exposure cannot exceed gross cap")
	}
	if verifiedCredit > baseCost {
		return errors.New("launch spend authorization verified credit cannot exceed base provider cost")
	}
	creditStatus, _ := input["credit_status"].(string)
	if creditStatus != "ACTIVE_CREDIT_VERIFIED" && verifiedCredit != 0 {
		return errors.New("launch spend authorization may apply credit only when active credit is verified")
	}
	creditApplied := int64(0)
	if creditStatus == "ACTIVE_CREDIT_VERIFIED" {
		creditApplied = verifiedCredit
	}
	if expectedCash != grossExposure-creditApplied {
		return errors.New("launch spend authorization expected cash must equal gross exposure minus verified active credit")
	}
	authorizedAt, err := launchInputTime(input, "authorized_at")
	if err != nil {
		return err
	}
	expiresAt, err := launchInputTime(input, "expires_at")
	if err != nil {
		return err
	}
	if !authorizedAt.Before(expiresAt) || expiresAt.After(authorizedAt.AddDate(0, 1, 0)) {
		return errors.New("launch spend authorization must expire within one calendar month of authorization")
	}
	if expiresAt.Sub(authorizedAt) < time.Second {
		return errors.New("launch spend authorization lifetime is empty")
	}
	return nil
}

func validateLaunchEffectFixedSemantics(typeID string, input map[string]any) error {
	if launchEffectRequiresProviderRoute(typeID) {
		if !launchInputNonEmptyString(input, "route_placement_id") || !launchInputNonEmptyString(input, "provider_certification_ref") {
			return errors.New("launch provider effect must bind an exact route placement and certification record")
		}
		certificationHash, ok := input["provider_certification_hash"].(string)
		if !ok || !validLaunchSHA256(certificationHash) {
			return errors.New("launch provider effect certification hash is invalid")
		}
	}
	switch typeID {
	case EffectTypeProviderProvision:
		if !launchInputNonEmptyString(input, "provider") ||
			!launchInputNonEmptyString(input, "region") ||
			!launchInputNonEmptyString(input, "jurisdiction") ||
			!launchInputNonEmptyString(input, "billing_cadence") ||
			!launchInputNonEmptyString(input, "commitment_term") ||
			!launchInputNonEmptyString(input, "gross_cap_currency") ||
			!launchInputStringIs(input, "teardown_authority_mode", "FRESH_DUAL_CONTROL_REQUIRED") {
			return errors.New("provider provision is missing route, billing, or fresh teardown authority constraints")
		}
		grossCap, err := launchInteger(input, "gross_cap_minor")
		if err != nil {
			return err
		}
		grossExposure, err := launchInteger(input, "gross_exposure_minor")
		if err != nil {
			return err
		}
		if grossCap < 0 || grossExposure < 0 || grossExposure > grossCap {
			return errors.New("provider provision gross exposure exceeds its approval-bound gross cap")
		}
		for _, forbidden := range []string{"preauthorized_teardown_permit_ref", "teardown_permit_ref", "delete_permit_ref"} {
			if _, exists := input[forbidden]; exists {
				return errors.New("provider provision cannot carry preauthorized deletion authority")
			}
		}
	case EffectTypeDeployProductionActivate:
		if !launchInputNonEmptyString(input, "provider") || !launchInputNonEmptyString(input, "region") || !launchInputNonEmptyString(input, "jurisdiction") || !launchInputStringIs(input, "rollback_authorization_mode", "PREAUTHORIZED_EXACT_TARGET") {
			return errors.New("production activation violates route or exact-target rollback constraints")
		}
		if err := validateLaunchActivationCompensation(input); err != nil {
			return err
		}
		if err := validateLaunchPrimaryEndpoint(input); err != nil {
			return err
		}
		for _, forbidden := range []string{"enable_autodeploy", "deployment_on_push", "continuous_deployment"} {
			if _, exists := input[forbidden]; exists {
				return errors.New("production activation cannot carry standing deployment authority")
			}
		}
	case EffectTypeSpendAuthorize:
		if !launchInputNonEmptyString(input, "provider") ||
			!launchInputNonEmptyString(input, "currency") ||
			!launchInputNonEmptyString(input, "billing_cadence") ||
			!launchInputNonEmptyString(input, "commitment_term") {
			return errors.New("launch spend authorization is missing provider, currency, cadence, or commitment bindings")
		}
		if autoRenew, ok := input["helm_auto_renews_authority"].(bool); !ok || autoRenew {
			return errors.New("launch spend authorization cannot grant HELM recurring renewal authority")
		}
	case EffectTypeProviderRollback:
		if !launchInputNonEmptyString(input, "provider") || !launchInputNonEmptyString(input, "region") || !launchInputNonEmptyString(input, "jurisdiction") ||
			!launchInputStringIs(input, "rollback_authorization_mode", "PREAUTHORIZED_EXACT_TARGET") {
			return errors.New("provider rollback must bind an exact route using exact-target preauthorization")
		}
		compensationClass, _ := input["compensation_class"].(string)
		if _, ok := launchCompensationClasses[compensationClass]; !ok || !launchInputNonEmptyString(input, "source_state_ref") || !launchInputNonEmptyString(input, "target_state_ref") || !launchInputNonEmptyString(input, "compensation_plan_ref") {
			return errors.New("provider rollback must bind an exact supported state compensation")
		}
		if _, err := launchInputTime(input, "rollback_permit_expiry"); err != nil {
			return err
		}
	case EffectTypeProviderTeardown:
		if !launchInputNonEmptyString(input, "provider") || !launchInputNonEmptyString(input, "region") || !launchInputNonEmptyString(input, "jurisdiction") {
			return errors.New("provider teardown must bind an exact provider route")
		}
	}
	return nil
}

func launchEffectRequiresProviderRoute(effectID string) bool {
	switch effectID {
	case EffectTypeProviderProvision, EffectTypeDeployProductionActivate, EffectTypeSpendAuthorize, EffectTypeProviderRollback, EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}

func validateLaunchPrimaryEndpoint(input map[string]any) error {
	targetKind, _ := input["exposure_kind"].(string)
	raw, present := input["primary_endpoint"].(string)
	if targetKind != "ENDPOINT" {
		if present && raw != "" {
			return errors.New("non-endpoint production activation cannot claim a primary endpoint")
		}
		return nil
	}
	if !present || raw == "" {
		return errors.New("endpoint production activation requires a primary endpoint")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("production activation primary endpoint must be an HTTPS URL without credentials, query, or fragment")
	}
	if !launchInputNonEmptyString(input, "tls_evidence_hash") {
		return errors.New("endpoint production activation requires TLS evidence")
	}
	return nil
}

func validateLaunchActivationCompensation(input map[string]any) error {
	activationClass, _ := input["activation_class"].(string)
	compensationClass, _ := input["compensation_class"].(string)
	expected := map[string]string{
		LaunchTransitionReleaseCutover: LaunchCompensationReleaseRollback,
		LaunchTransitionResourceState:  LaunchCompensationResourceRestore,
		LaunchTransitionDataRestore:    LaunchCompensationDataRestore,
		LaunchTransitionInfraReconcile: LaunchCompensationInfraReconcile,
		LaunchTransitionComposite:      LaunchCompensationComposite,
	}
	if expected[activationClass] == "" || expected[activationClass] != compensationClass {
		return errors.New("production activation transition and compensation classes are incompatible")
	}
	for _, field := range []string{"source_state_ref", "target_state_ref", "transition_plan_ref", "compensation_target_ref"} {
		if !launchInputNonEmptyString(input, field) {
			return fmt.Errorf("production activation %s is required", field)
		}
	}
	return nil
}

func launchInputStringIs(input map[string]any, field, expected string) bool {
	value, ok := input[field].(string)
	return ok && value == expected
}

func launchInputNonEmptyString(input map[string]any, field string) bool {
	value, ok := input[field].(string)
	return ok && strings.TrimSpace(value) != ""
}

func launchInputTime(input map[string]any, field string) (time.Time, error) {
	value, ok := input[field].(string)
	if !ok {
		return time.Time{}, fmt.Errorf("launch effect input %s must be a date-time", field)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("launch effect input %s must be a date-time", field)
	}
	return parsed, nil
}

func launchIdempotency(onDuplicate string) IdempotencyRef {
	return IdempotencyRef{
		Strategy:       "content_hash",
		KeyComposition: []string{"$canonical_input"},
		OnDuplicate:    onDuplicate,
	}
}

func appendHooks(base []string, hooks ...string) []string {
	out := make([]string, 0, len(base)+len(hooks))
	out = append(out, base...)
	out = append(out, hooks...)
	return out
}

func launchInteger(input map[string]any, field string) (int64, error) {
	switch value := input[field].(type) {
	case int:
		return normalizeLaunchEffectSignedInteger(int64(value), 9007199254740991)
	case int8:
		return int64(value), nil
	case int16:
		return int64(value), nil
	case int32:
		return int64(value), nil
	case int64:
		return normalizeLaunchEffectSignedInteger(value, 9007199254740991)
	case uint:
		return normalizeLaunchEffectUnsignedInteger(uint64(value), 9007199254740991)
	case uint8:
		return int64(value), nil
	case uint16:
		return int64(value), nil
	case uint32:
		return int64(value), nil
	case uint64:
		return normalizeLaunchEffectUnsignedInteger(value, 9007199254740991)
	case json.Number:
		return normalizeLaunchEffectJSONNumber(value, 9007199254740991)
	case float32:
		return normalizeLaunchEffectFloat(float64(value), 9007199254740991)
	case float64:
		return normalizeLaunchEffectFloat(value, 9007199254740991)
	default:
		return 0, fmt.Errorf("launch effect input %s must be an integer", field)
	}
}
