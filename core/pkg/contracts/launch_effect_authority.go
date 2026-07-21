// quantum_posture: launch authorization uses classical Ed25519 signatures
// and makes no hybrid or post-quantum protection claim.
package contracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const LaunchEffectEnvelopeSchemaVersion = "launch_effect_envelope.v1"

// LaunchEffectAuthorizationEnvelope is the preview dispatch contract. Merely
// constructing this value grants no authority: VerifyLaunchEffectAuthorizationEnvelope
// must resolve and bind the single-use permit immediately before dispatch.
type LaunchEffectAuthorizationEnvelope struct {
	SchemaVersion           string         `json:"schema_version"`
	EffectID                string         `json:"effect_id"`
	TenantID                string         `json:"tenant_id"`
	WorkspaceID             string         `json:"workspace_id"`
	MissionID               string         `json:"mission_id"`
	Principal               string         `json:"principal"`
	Audience                string         `json:"audience"`
	KernelTrustRootID       string         `json:"kernel_trust_root_id"`
	EffectOrdinal           int            `json:"effect_ordinal"`
	InputSchemaRef          string         `json:"input_schema_ref"`
	InputSchemaHash         string         `json:"input_schema_hash"`
	Input                   map[string]any `json:"input"`
	InputHash               string         `json:"input_hash"`
	IdempotencyKey          string         `json:"idempotency_key"`
	PlanHash                string         `json:"plan_hash"`
	ApprovalArtifactRef     string         `json:"approval_artifact_ref"`
	ApprovalArtifactHash    string         `json:"approval_artifact_hash"`
	ApprovalConsumptionRef  string         `json:"approval_consumption_ref"`
	ApprovalConsumptionHash string         `json:"approval_consumption_hash"`
	DispatchAdmissionRef    string         `json:"dispatch_admission_ref"`
	DispatchAdmissionHash   string         `json:"dispatch_admission_hash"`
	DependencySetRef        string         `json:"dependency_set_ref"`
	DependencySetHash       string         `json:"dependency_set_hash"`
	PolicyEpoch             string         `json:"policy_epoch"`
	EmergencyFenceEpoch     int64          `json:"emergency_fence_epoch"`
	Verdict                 string         `json:"verdict"`
	KernelVerdictRef        string         `json:"kernel_verdict_ref"`
	KernelVerdictIssuedAt   string         `json:"kernel_verdict_issued_at"`
	KernelVerdictExpiry     string         `json:"kernel_verdict_expiry"`
	KernelVerdictSignerKey  string         `json:"kernel_verdict_signer_key_id"`
	KernelVerdictHash       string         `json:"kernel_verdict_hash"`
	KernelVerdictSignature  string         `json:"kernel_verdict_signature"`
	EffectPermitRef         string         `json:"effect_permit_ref"`
	EffectPermitHash        string         `json:"effect_permit_hash"`
	PermitNonce             string         `json:"permit_nonce"`
	PermitIssuedAt          string         `json:"permit_issued_at"`
	PermitExpiry            string         `json:"permit_expiry"`
	ProofSessionRef         string         `json:"proof_session_ref"`
	EvidenceReservationRef  string         `json:"evidence_reservation_ref"`
	ConnectorID             string         `json:"connector_id"`
	ConnectorContractHash   string         `json:"connector_contract_hash"`
	ConnectorAuthorityRef   string         `json:"connector_authority_ref"`
	ConnectorAuthorityHash  string         `json:"connector_authority_hash"`
	ActionURN               string         `json:"action_urn"`
	RequestBodyHash         string         `json:"request_body_hash"`
	ArgsC14NHash            string         `json:"args_c14n_hash"`
	DispatchDeadline        string         `json:"dispatch_deadline"`
	ReplayHint              string         `json:"replay_hint"`
}

// LaunchEffectPermitBinding is a data-plane dispatch CAS, not a parallel
// approval. It is usable only after a canonical ApprovalGrant has already been
// verified and consumed by the exact principal/audience below.
type LaunchEffectPermitBinding struct {
	EffectPermitRef         string
	EffectPermitHash        string
	PermitNonce             string
	ProofSessionRef         string
	EvidenceReservationRef  string
	PermitIssuedAt          time.Time
	PermitExpiry            time.Time
	KernelVerdictRef        string
	KernelVerdictHash       string
	KernelVerdictIssuedAt   time.Time
	KernelVerdictExpiry     time.Time
	EffectID                string
	TenantID                string
	WorkspaceID             string
	MissionID               string
	Principal               string
	Audience                string
	KernelTrustRootID       string
	EffectOrdinal           int
	InputSchemaHash         string
	InputHash               string
	IdempotencyKey          string
	PlanHash                string
	ApprovalArtifactRef     string
	ApprovalArtifactHash    string
	ApprovalConsumptionRef  string
	ApprovalConsumptionHash string
	DispatchAdmissionRef    string
	DispatchAdmissionHash   string
	DependencySetRef        string
	DependencySetHash       string
	ConnectorID             string
	ConnectorContractHash   string
	ConnectorAuthorityRef   string
	ConnectorAuthorityHash  string
	ActionURN               string
	RequestBodyHash         string
	ArgsC14NHash            string
	PolicyEpoch             string
	EmergencyFenceEpoch     int64
	DispatchDeadline        time.Time
	SingleUse               bool
}

// LaunchEffectDispatchFinalization is the exact single-use permit and the
// exclusive wall-clock bound that a source-owned finalizer must enforce in
// the same atomic operation as its permit CAS.
type LaunchEffectDispatchFinalization struct {
	Permit           LaunchEffectPermitBinding
	MustCommitBefore time.Time
}

// LaunchEffectDispatchFinalizationResult records when the source-owned atomic
// finalization committed. The verifier rejects stale, backdated, or expired
// results before any network dispatch can be authorized.
type LaunchEffectDispatchFinalizationResult struct {
	CommittedAt       time.Time
	ObservedAuthority LaunchEffectPermitBinding
}

// LaunchEffectApprovalAuthority is independently loaded from the canonical
// approvalceremony boundary. Signatures are retained beside their canonical
// Grant and Consumption records because those portable contracts deliberately
// exclude transport/storage signature envelopes.
type LaunchEffectApprovalAuthority struct {
	Grant                         ApprovalGrant             `json:"grant"`
	GrantSignatureAlgorithm       string                    `json:"grant_signature_algorithm"`
	GrantSignature                string                    `json:"grant_signature"`
	Consumption                   ApprovalGrantConsumption  `json:"consumption"`
	ConsumptionSignatureAlgorithm string                    `json:"consumption_signature_algorithm"`
	ConsumptionSignature          string                    `json:"consumption_signature"`
	DispatchAdmission             ApprovalDispatchAdmission `json:"dispatch_admission"`
	DispatchSignatureAlgorithm    string                    `json:"dispatch_signature_algorithm"`
	DispatchSignature             string                    `json:"dispatch_signature"`
}

// LaunchEmergencyFenceSnapshot is source-owned state for every emergency stop
// applicable to one launch workspace. EffectiveEpoch MUST increase on both
// stop and clear transitions so a permit issued before a stop-clear cycle can
// never become dispatchable again.
type LaunchEmergencyFenceSnapshot struct {
	TenantID       string
	WorkspaceID    string
	EffectiveEpoch int64
	Active         bool
}

// LaunchEffectEnvelopeVerificationContext supplies independently resolved
// source truth. Values copied from the envelope are not valid inputs here.
type LaunchEffectEnvelopeVerificationContext struct {
	Now                      time.Time
	ResolveInputSchema       func(schemaRef string) ([]byte, error)
	ValidateInput            func(schemaRef, schemaHash string, input map[string]any) error
	ResolveRouteBinding      func(routeRef string) (LaunchRouteBinding, error)
	RouteArtifacts           LaunchRouteArtifactResolver
	ResolveApprovalAuthority func(grantRef, grantHash, consumptionRef, consumptionHash string) (LaunchEffectApprovalAuthority, error)
	VerifyApprovalAuthority  func(LaunchEffectApprovalAuthority) error
	VerifyDependencyState    func(dependencySetRef, dependencySetHash string) error
	ExpectedRequestBodyHash  string
	ExpectedArgsC14NHash     string
	ExpectedPolicyEpoch      string
	MaximumPermitTTL         time.Duration
	ResolveVerdictKey        func(kernelTrustRootID, signerKeyID string) (ed25519.PublicKey, error)
	ResolveEmergencyFence    func(tenantID, workspaceID string) (LaunchEmergencyFenceSnapshot, error)
	// FinalizeDispatch MUST atomically: read a source-owned wall clock, require
	// it to be strictly before expected.MustCommitBefore, re-read the canonical
	// scoped-stop state, deny an active or unavailable fence, require its
	// effective epoch to equal expected.Permit.EmergencyFenceEpoch, re-check
	// predecessor receipt state,
	// compare the canonical approval consumption and dispatch admission, verify
	// that the exact connector release remains current and non-revoked, and CAS
	// expected.Permit. A separate time or state pre-read is insufficient. The
	// returned CommittedAt MUST be the clock value read by that atomic operation;
	// ObservedAuthority MUST be rebuilt from those same independent source reads,
	// never copied from expected.Permit.
	// A successful return is still only pre-dispatch authority: the Data Plane
	// must use the exact DispatchAdmissionRef/Hash to persist or recover its
	// durable effect reservation and pass the start interlock before any network
	// sink. This callback does not replace that lifecycle boundary.
	FinalizeDispatch func(expected LaunchEffectDispatchFinalization) (LaunchEffectDispatchFinalizationResult, error)
	Permit           LaunchEffectPermitBinding
}

// LaunchEffectVerdictSigningBytes returns the RFC 8785 payload signed by the
// Kernel. The hash and signature fields are cleared to avoid self-reference.
func LaunchEffectVerdictSigningBytes(envelope LaunchEffectAuthorizationEnvelope) ([]byte, error) {
	envelope.KernelVerdictHash = ""
	envelope.KernelVerdictSignature = ""
	return canonicalize.JCS(envelope)
}

// SignLaunchEffectAuthorizationEnvelope is a deterministic preview helper for
// source-owned conformance fixtures. Production signing remains Kernel-owned.
func SignLaunchEffectAuthorizationEnvelope(envelope LaunchEffectAuthorizationEnvelope, privateKey ed25519.PrivateKey) (LaunchEffectAuthorizationEnvelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return envelope, errors.New("launch effect verdict private key has invalid size")
	}
	payload, err := LaunchEffectVerdictSigningBytes(envelope)
	if err != nil {
		return envelope, fmt.Errorf("canonicalize launch effect verdict: %w", err)
	}
	envelope.KernelVerdictHash = canonicalize.ComputeArtifactHash(payload)
	envelope.KernelVerdictSignature = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, payload))
	return envelope, nil
}

// VerifyLaunchEffectAuthorizationEnvelope fails closed unless the Kernel-signed
// envelope, source-owned schema bytes, canonical approval consumption, exact
// certified route, dependency state, and final atomic dispatch guard all agree.
func VerifyLaunchEffectAuthorizationEnvelope(envelope LaunchEffectAuthorizationEnvelope, ctx LaunchEffectEnvelopeVerificationContext) error {
	contract := LookupLaunchMissionEffectPreview(envelope.EffectID)
	if contract == nil {
		return fmt.Errorf("launch authorization envelope effect %q is not registered", envelope.EffectID)
	}
	if err := validateLaunchEnvelopeShape(envelope); err != nil {
		return err
	}
	if envelope.SchemaVersion != LaunchEffectEnvelopeSchemaVersion {
		return fmt.Errorf("launch authorization envelope schema_version must equal %q", LaunchEffectEnvelopeSchemaVersion)
	}
	if envelope.Verdict != "ALLOW" {
		return errors.New("launch authorization envelope verdict must be ALLOW")
	}
	if envelope.ReplayHint != "single_use_permit" {
		return errors.New("launch authorization envelope must require a single-use permit")
	}
	if envelope.InputSchemaRef != contract.InputSchema {
		return errors.New("launch authorization envelope input schema reference does not match effect contract")
	}
	if envelope.ConnectorID != contract.ConnectorID || envelope.ActionURN != contract.ActionURN {
		return errors.New("launch authorization envelope connector action is not admitted for effect")
	}
	if ctx.ExpectedRequestBodyHash == "" || !launchConstantEqual(envelope.RequestBodyHash, ctx.ExpectedRequestBodyHash) {
		return errors.New("launch authorization envelope request body hash does not match canonical request")
	}
	if ctx.ExpectedArgsC14NHash == "" || !launchConstantEqual(envelope.ArgsC14NHash, ctx.ExpectedArgsC14NHash) {
		return errors.New("launch authorization envelope canonical arguments hash does not match connector arguments")
	}
	if ctx.ExpectedPolicyEpoch == "" || envelope.PolicyEpoch != ctx.ExpectedPolicyEpoch {
		return errors.New("launch authorization envelope policy epoch is stale")
	}
	if err := verifyLaunchEnvelopeInputBindings(envelope); err != nil {
		return err
	}
	// Verify the Kernel signature before any source-owned route or registry
	// resolution to avoid unsigned tenancy probes and expensive-work oracles.
	if ctx.ResolveVerdictKey == nil {
		return errors.New("launch authorization envelope requires a verdict trust-root resolver")
	}
	verdictPublicKey, err := ctx.ResolveVerdictKey(envelope.KernelTrustRootID, envelope.KernelVerdictSignerKey)
	if err != nil {
		return fmt.Errorf("resolve launch authorization envelope verdict key: %w", err)
	}
	if err := verifyLaunchVerdictSignature(envelope, verdictPublicKey); err != nil {
		return err
	}
	if err := verifyLaunchEmergencyFence(envelope, ctx); err != nil {
		return err
	}
	if ctx.ResolveInputSchema == nil || ctx.ValidateInput == nil {
		return errors.New("launch authorization envelope requires source-owned schema bytes and validation")
	}
	schemaBytes, err := ctx.ResolveInputSchema(envelope.InputSchemaRef)
	if err != nil {
		return fmt.Errorf("resolve launch authorization envelope input schema: %w", err)
	}
	if schemaHash := canonicalize.ComputeArtifactHash(schemaBytes); !launchConstantEqual(envelope.InputSchemaHash, schemaHash) {
		return errors.New("launch authorization envelope input schema hash does not match source-owned bytes")
	}
	if err := ctx.ValidateInput(envelope.InputSchemaRef, envelope.InputSchemaHash, envelope.Input); err != nil {
		return fmt.Errorf("launch authorization envelope input schema validation failed: %w", err)
	}
	if err := verifyLaunchEnvelopeTimes(envelope, ctx); err != nil {
		return err
	}
	if err := verifyLaunchPermitBinding(envelope, ctx.Permit); err != nil {
		return err
	}
	if err := verifyLaunchCanonicalApproval(envelope, ctx); err != nil {
		return err
	}
	if launchEffectRequiresProviderRoute(envelope.EffectID) {
		if err := verifyLaunchProviderRouteBinding(envelope, ctx); err != nil {
			return fmt.Errorf("launch authorization envelope provider route validation failed: %w", err)
		}
	}
	if ctx.VerifyDependencyState == nil {
		return errors.New("launch authorization envelope requires source-owned dependency receipt verification")
	}
	if err := ctx.VerifyDependencyState(envelope.DependencySetRef, envelope.DependencySetHash); err != nil {
		return fmt.Errorf("launch authorization envelope dependency state is not dispatchable: %w", err)
	}
	if ctx.FinalizeDispatch == nil {
		return errors.New("launch authorization envelope requires atomic fence/dependency/permit finalization")
	}
	expectedFinalization, err := launchDispatchFinalization(envelope, ctx.Permit)
	if err != nil {
		return err
	}
	finalization, err := ctx.FinalizeDispatch(expectedFinalization)
	if err != nil {
		return fmt.Errorf("finalize launch authorization envelope dispatch: %w", err)
	}
	if finalization.CommittedAt.IsZero() || finalization.CommittedAt.Before(ctx.Now) {
		return errors.New("launch authorization envelope dispatch finalization time is missing or backdated")
	}
	if !finalization.CommittedAt.Before(expectedFinalization.MustCommitBefore) {
		return errors.New("launch authorization envelope expired before atomic dispatch finalization")
	}
	if finalization.ObservedAuthority != expectedFinalization.Permit {
		return errors.New("launch authorization envelope authority changed before atomic dispatch finalization")
	}
	return nil
}

func launchDispatchFinalization(envelope LaunchEffectAuthorizationEnvelope, permit LaunchEffectPermitBinding) (LaunchEffectDispatchFinalization, error) {
	mustCommitBefore := permit.DispatchDeadline
	if mustCommitBefore.IsZero() {
		return LaunchEffectDispatchFinalization{}, errors.New("launch authorization envelope dispatch finalization deadline is missing")
	}
	for _, expiry := range []time.Time{permit.PermitExpiry, permit.KernelVerdictExpiry} {
		if expiry.IsZero() {
			return LaunchEffectDispatchFinalization{}, errors.New("launch authorization envelope dispatch finalization expiry is missing")
		}
		if expiry.Before(mustCommitBefore) {
			mustCommitBefore = expiry
		}
	}
	if envelope.EffectID == EffectTypeDeployProductionActivate || envelope.EffectID == EffectTypeProviderRollback {
		rollbackExpiry, err := launchInputTime(envelope.Input, "rollback_permit_expiry")
		if err != nil {
			return LaunchEffectDispatchFinalization{}, errors.New("launch rollback preauthorization expiry is invalid")
		}
		if rollbackExpiry.Before(mustCommitBefore) {
			mustCommitBefore = rollbackExpiry
		}
	}
	if envelope.EffectID == EffectTypeSpendAuthorize {
		spendExpiry, err := launchInputTime(envelope.Input, "expires_at")
		if err != nil {
			return LaunchEffectDispatchFinalization{}, errors.New("launch spend authorization expiry is invalid")
		}
		if spendExpiry.Before(mustCommitBefore) {
			mustCommitBefore = spendExpiry
		}
	}
	return LaunchEffectDispatchFinalization{Permit: permit, MustCommitBefore: mustCommitBefore}, nil
}

func verifyLaunchEmergencyFence(envelope LaunchEffectAuthorizationEnvelope, ctx LaunchEffectEnvelopeVerificationContext) error {
	if ctx.ResolveEmergencyFence == nil {
		return errors.New("launch authorization envelope requires source-owned emergency fence state")
	}
	snapshot, err := ctx.ResolveEmergencyFence(envelope.TenantID, envelope.WorkspaceID)
	if err != nil {
		return fmt.Errorf("resolve launch authorization envelope emergency fence: %w", err)
	}
	if snapshot.TenantID != envelope.TenantID || snapshot.WorkspaceID != envelope.WorkspaceID {
		return errors.New("launch authorization envelope emergency fence scope does not match the dispatch")
	}
	if snapshot.EffectiveEpoch < 0 || snapshot.EffectiveEpoch != envelope.EmergencyFenceEpoch {
		return errors.New("launch authorization envelope emergency fence epoch is stale")
	}
	if snapshot.Active {
		return errors.New("launch authorization envelope emergency fence is active")
	}
	return nil
}

func verifyLaunchEnvelopeInputBindings(envelope LaunchEffectAuthorizationEnvelope) error {
	if envelope.Input == nil {
		return errors.New("launch authorization envelope canonical input is required")
	}
	bindings := []struct {
		field string
		outer string
	}{
		{"effect_id", envelope.EffectID},
		{"tenant_id", envelope.TenantID},
		{"workspace_id", envelope.WorkspaceID},
		{"mission_id", envelope.MissionID},
		{"plan_hash", envelope.PlanHash},
		{"connector_contract_hash", envelope.ConnectorContractHash},
	}
	for _, binding := range bindings {
		inner, ok := envelope.Input[binding.field].(string)
		if !ok || inner == "" || !launchConstantEqual(inner, binding.outer) {
			return fmt.Errorf("launch authorization envelope input binding mismatch for %s", binding.field)
		}
	}
	ordinal, err := launchInteger(envelope.Input, "effect_ordinal")
	if err != nil || ordinal != int64(envelope.EffectOrdinal) {
		return errors.New("launch authorization envelope input binding mismatch for effect_ordinal")
	}
	derived, err := DeriveLaunchEffectIdempotencyKey(envelope.EffectID, envelope.Input)
	if err != nil {
		return err
	}
	if !launchConstantEqual(envelope.InputHash, derived) {
		return errors.New("launch authorization envelope input hash does not match canonical input")
	}
	if err := ValidateLaunchEffectIdempotencyKey(envelope.EffectID, envelope.Input, envelope.IdempotencyKey); err != nil {
		return err
	}
	if err := ValidateLaunchEffectInputSemantics(envelope.EffectID, envelope.Input); err != nil {
		return err
	}
	return nil
}

func verifyLaunchCanonicalApproval(envelope LaunchEffectAuthorizationEnvelope, ctx LaunchEffectEnvelopeVerificationContext) error {
	if ctx.ResolveApprovalAuthority == nil || ctx.VerifyApprovalAuthority == nil {
		return errors.New("launch authorization envelope requires canonical approval authority resolution and signature verification")
	}
	authority, err := ctx.ResolveApprovalAuthority(envelope.ApprovalArtifactRef, envelope.ApprovalArtifactHash, envelope.ApprovalConsumptionRef, envelope.ApprovalConsumptionHash)
	if err != nil {
		return fmt.Errorf("resolve canonical launch approval authority: %w", err)
	}
	if err := authority.Grant.ValidateAt(ctx.Now); err != nil {
		return fmt.Errorf("canonical launch approval grant is invalid: %w", err)
	}
	if err := authority.Consumption.ValidateGrant(authority.Grant); err != nil {
		return fmt.Errorf("canonical launch approval consumption is invalid: %w", err)
	}
	if err := authority.DispatchAdmission.ValidateAt(ctx.Now); err != nil {
		return fmt.Errorf("canonical launch dispatch admission is invalid: %w", err)
	}
	if err := authority.DispatchAdmission.ValidateConsumption(authority.Consumption); err != nil {
		return fmt.Errorf("canonical launch dispatch admission does not bind its consumption: %w", err)
	}
	if err := ctx.VerifyApprovalAuthority(authority); err != nil {
		return fmt.Errorf("canonical launch approval or dispatch signatures are invalid: %w", err)
	}
	expectedAction, err := launchApprovalActionForEffect(envelope.EffectID)
	if err != nil {
		return err
	}
	grant := authority.Grant
	consumption := authority.Consumption
	admission := authority.DispatchAdmission
	if grant.GrantID != envelope.ApprovalArtifactRef || !launchConstantEqual(grant.GrantHash, envelope.ApprovalArtifactHash) ||
		!launchConstantEqual(consumption.ConsumptionHash, envelope.ApprovalConsumptionHash) ||
		admission.AdmissionID != envelope.DispatchAdmissionRef || !launchConstantEqual(admission.AdmissionHash, envelope.DispatchAdmissionHash) ||
		grant.TenantID != envelope.TenantID || grant.WorkspaceID != envelope.WorkspaceID || grant.Audience != envelope.Audience ||
		consumption.TenantID != envelope.TenantID || consumption.WorkspaceID != envelope.WorkspaceID || consumption.Audience != envelope.Audience || consumption.ConsumedBy != envelope.Principal ||
		admission.TenantID != envelope.TenantID || admission.WorkspaceID != envelope.WorkspaceID || admission.Audience != envelope.Audience || admission.AdmittedBy != envelope.Principal ||
		grant.KernelTrustRootID != envelope.KernelTrustRootID || consumption.KernelTrustRootID != envelope.KernelTrustRootID ||
		admission.KernelTrustRootID != envelope.KernelTrustRootID || admission.AttemptID != envelope.EffectPermitRef ||
		!launchConstantEqual(admission.IdempotencyKeyHash, envelope.IdempotencyKey) || !launchConstantEqual(admission.EffectHash, envelope.InputHash) ||
		grant.PackID != envelope.MissionID || grant.PackVersion != LaunchEffectCatalogVersion ||
		!launchConstantEqual(grant.PackManifestHash, envelope.PlanHash) || !launchConstantEqual(grant.IntentHash, envelope.PlanHash) ||
		!launchConstantEqual(grant.EffectHash, envelope.InputHash) || !launchConstantEqual(grant.PlanHash, envelope.PlanHash) ||
		grant.PolicyEpoch != envelope.PolicyEpoch || grant.Action != expectedAction {
		return errors.New("canonical launch approval grant, consumption, or dispatch admission does not bind the exact dispatch")
	}
	connectorAuthority := grant.ConnectorAuthority
	if connectorAuthority.BindingRef != envelope.ConnectorAuthorityRef || !launchConstantEqual(connectorAuthority.AuthorityHash, envelope.ConnectorAuthorityHash) {
		return errors.New("canonical launch approval connector authority does not match the dispatch envelope")
	}
	expectedConnectorID := envelope.ConnectorID
	expectedConnectorAction := envelope.ActionURN
	if launchEffectIsProviderMutation(envelope.EffectID) {
		providerConnectorID, ok := envelope.Input["provider_connector_id"].(string)
		if !ok || providerConnectorID == "" {
			return errors.New("launch provider mutation has no approval-bound provider connector")
		}
		expectedConnectorID = providerConnectorID
		providerConnectorAction, ok := envelope.Input["provider_action_urn"].(string)
		if !ok || providerConnectorAction == "" {
			return errors.New("launch provider mutation has no approval-bound provider connector action")
		}
		expectedConnectorAction = providerConnectorAction
		certificationRef, refOK := envelope.Input["provider_certification_ref"].(string)
		certificationHash, hashOK := envelope.Input["provider_certification_hash"].(string)
		if !refOK || !hashOK || connectorAuthority.CertificationRef != certificationRef || !launchConstantEqual(connectorAuthority.CertificationHash, certificationHash) {
			return errors.New("canonical launch approval connector authority does not match provider certification")
		}
	}
	if connectorAuthority.ConnectorID != expectedConnectorID {
		return errors.New("canonical launch approval connector release does not match the dispatched connector")
	}
	if connectorAuthority.ConnectorAction != expectedConnectorAction {
		return errors.New("canonical launch approval connector release does not match the dispatched connector action")
	}
	permitIssuedAt, err := time.Parse(time.RFC3339Nano, envelope.PermitIssuedAt)
	if err != nil {
		return errors.New("launch effect permit issue time is invalid during canonical approval verification")
	}
	permitExpiry, err := time.Parse(time.RFC3339Nano, envelope.PermitExpiry)
	if err != nil {
		return errors.New("launch effect permit expiry is invalid during canonical approval verification")
	}
	if permitIssuedAt.Before(admission.IssuedAt) || permitExpiry.After(admission.ExpiresAt) {
		return errors.New("launch effect permit escapes its canonical dispatch admission window")
	}
	if consumption.ConsumedAt.After(ctx.Now) {
		return errors.New("canonical launch approval consumption is in the future")
	}
	return nil
}

func launchApprovalActionForEffect(effectID string) (string, error) {
	switch effectID {
	case EffectTypeProviderProvision, EffectTypeSpendAuthorize:
		return ApprovalGrantActionInstall, nil
	case EffectTypeDeployProductionActivate, EffectTypeCompanyArtifactUpdate:
		return ApprovalGrantActionUpgrade, nil
	case EffectTypeProviderRollback:
		return ApprovalGrantActionRollback, nil
	case EffectTypeProviderTeardown:
		return ApprovalGrantActionUninstall, nil
	default:
		return "", fmt.Errorf("launch effect %s has no canonical approval action", effectID)
	}
}

func verifyLaunchProviderRouteBinding(envelope LaunchEffectAuthorizationEnvelope, ctx LaunchEffectEnvelopeVerificationContext) error {
	if ctx.ResolveRouteBinding == nil || ctx.RouteArtifacts == nil {
		return errors.New("source-owned route binding and artifact resolver are required")
	}
	routeRef, ok := envelope.Input["route_binding_ref"].(string)
	if !ok || routeRef == "" {
		return errors.New("launch provider input has no route binding reference")
	}
	routeHash, ok := envelope.Input["route_binding_hash"].(string)
	if !ok || !validLaunchSHA256(routeHash) {
		return errors.New("launch provider input has no canonical route binding hash")
	}
	route, err := ctx.ResolveRouteBinding(routeRef)
	if err != nil {
		return fmt.Errorf("resolve launch route binding: %w", err)
	}
	resolvedHash, err := DeriveLaunchRouteBindingHash(route)
	if err != nil || !launchConstantEqual(routeHash, resolvedHash) {
		return errors.New("launch provider input route binding hash does not match source-owned content")
	}
	// This verifier validates preview authority evidence without promoting the
	// preview effect IDs into the production execution catalog. A non-empty
	// certification is still resolved, signature-verified, and checked current
	// by ValidateLaunchRouteBinding; the Kernel boundary remains the separate
	// fail-closed execution interlock.
	if err := ValidateLaunchRouteBinding(route, ctx.RouteArtifacts, ctx.Now, false); err != nil {
		return err
	}
	if route.RouteID != routeRef || route.TenantID != envelope.TenantID || route.WorkspaceID != envelope.WorkspaceID || route.MissionID != envelope.MissionID {
		return errors.New("launch provider route identity does not match the dispatch envelope")
	}
	placementID, _ := envelope.Input["route_placement_id"].(string)
	var placement *LaunchRoutePlacement
	for index := range route.Placements {
		if route.Placements[index].PlacementID == placementID {
			placement = &route.Placements[index]
			break
		}
	}
	if placement == nil {
		return errors.New("launch provider input route placement is absent from route")
	}
	if placement.ProviderCertificationRef == "" || !validLaunchSHA256(placement.ProviderCertificationHash) {
		return errors.New("launch provider route placement has no certified connector authority")
	}
	for field, expected := range map[string]string{
		"provider":                         placement.ProviderID,
		"provider_account_ref":             placement.ProviderAccountRef,
		"provider_account_hash":            placement.ProviderAccountHash,
		"provider_capability_profile_ref":  placement.ProviderProfileRef,
		"provider_capability_profile_hash": placement.ProviderProfileHash,
		"provider_certification_ref":       placement.ProviderCertificationRef,
		"provider_certification_hash":      placement.ProviderCertificationHash,
		"workload_graph_ref":               route.WorkloadGraphRef,
		"workload_graph_hash":              route.WorkloadGraphHash,
	} {
		if !launchInputMatchesString(envelope.Input, field, expected) {
			return fmt.Errorf("launch provider input does not match route placement field %s", field)
		}
	}
	for field, expected := range map[string]string{
		"region":                           placement.RegionID,
		"jurisdiction":                     placement.Jurisdiction,
		"provider_connector_id":            placement.ProviderConnectorID,
		"provider_connector_contract_hash": placement.ProviderConnectorContractHash,
		"repository_analysis_ref":          route.RepositoryAnalysisRef,
		"repository_analysis_hash":         route.RepositoryAnalysisHash,
		"resource_graph_ref":               route.ResourceGraphRef,
		"resource_graph_hash":              route.ResourceGraphHash,
		"route_quote_ref":                  route.RouteQuoteRef,
		"route_quote_hash":                 route.RouteQuoteHash,
		"quote_hash":                       route.RouteQuoteHash,
		"constraint_set_hash":              route.ConstraintSetHash,
		"generated_spec_hash":              route.GeneratedSpecHash,
	} {
		if _, present := envelope.Input[field]; present && !launchInputMatchesString(envelope.Input, field, expected) {
			return fmt.Errorf("launch provider input does not match route field %s", field)
		}
	}
	if err := verifyLaunchRouteCommercialBindings(envelope, route, placement, ctx.RouteArtifacts); err != nil {
		return err
	}
	if launchEffectIsProviderMutation(envelope.EffectID) {
		var action *LaunchRouteActionBinding
		for index := range placement.ActionBindings {
			if placement.ActionBindings[index].EffectID == envelope.EffectID {
				action = &placement.ActionBindings[index]
				break
			}
		}
		if action == nil || !launchInputMatchesString(envelope.Input, "provider_action_urn", action.ProviderActionURN) || !launchInputMatchesString(envelope.Input, "provider_payload_hash", action.ProviderPayloadHash) {
			return errors.New("launch provider input action or payload is absent from route placement")
		}
	}
	return nil
}

func verifyLaunchRouteCommercialBindings(envelope LaunchEffectAuthorizationEnvelope, route LaunchRouteBinding, placement *LaunchRoutePlacement, resolver LaunchRouteArtifactResolver) error {
	quote, err := resolver.ResolveLaunchRouteQuote(route.RouteQuoteRef)
	if err != nil {
		return fmt.Errorf("resolve launch route quote for dispatch: %w", err)
	}
	constraints, err := resolver.ResolveLaunchConstraintSet(route.ConstraintSetRef)
	if err != nil {
		return fmt.Errorf("resolve launch constraint set for dispatch: %w", err)
	}
	if _, present := envelope.Input["gross_cap_minor"]; present && !launchInputMatchesInteger(envelope.Input, "gross_cap_minor", constraints.MaximumGrossMinor) {
		return errors.New("launch provider input gross cap does not match the approval-bound constraint set")
	}
	var placementCost *LaunchPlacementCost
	for index := range quote.PlacementCosts {
		if quote.PlacementCosts[index].PlacementID == placement.PlacementID {
			placementCost = &quote.PlacementCosts[index]
			break
		}
	}
	if placementCost == nil {
		return errors.New("launch provider input placement is absent from its route quote")
	}
	for field, expected := range map[string]int64{
		"base_provider_cost_minor": placementCost.BaseCostMinor,
		"tax_fx_reserve_minor":     placementCost.TaxFXReserveMinor,
		"gross_exposure_minor":     placementCost.GrossExposureMinor,
		"verified_credit_minor":    placementCost.VerifiedCreditMinor,
		"expected_cash_minor":      placementCost.ExpectedCashMinor,
	} {
		if _, present := envelope.Input[field]; present && !launchInputMatchesInteger(envelope.Input, field, expected) {
			return fmt.Errorf("launch provider input %s does not match the approval-bound route quote", field)
		}
	}
	for field, expected := range map[string]string{
		"currency":             quote.Currency,
		"gross_cap_currency":   constraints.MaximumGrossCurrency,
		"credit_status":        placementCost.CreditStatus,
		"credit_snapshot_hash": placementCost.OfferSnapshotHash,
		"fx_snapshot_hash":     quote.FXSnapshotHash,
		"tax_snapshot_hash":    quote.TaxSnapshotHash,
	} {
		if _, present := envelope.Input[field]; present && !launchInputMatchesString(envelope.Input, field, expected) {
			return fmt.Errorf("launch provider input %s does not match the approval-bound route quote", field)
		}
	}
	for field, expected := range map[string]string{
		"price_snapshot_hash":         placementCost.PriceEvidenceHash,
		"provider_terms_profile_hash": placementCost.TermsEvidenceHash,
	} {
		if _, present := envelope.Input[field]; present && !launchInputMatchesString(envelope.Input, field, expected) {
			return fmt.Errorf("launch provider input %s does not match its exact placement quote", field)
		}
	}
	return nil
}

func launchInputMatchesString(input map[string]any, field, expected string) bool {
	actual, ok := input[field].(string)
	return ok && actual != "" && launchConstantEqual(actual, expected)
}

func launchInputMatchesInteger(input map[string]any, field string, expected int64) bool {
	actual, err := launchInteger(input, field)
	return err == nil && actual == expected
}

func validateLaunchEnvelopeShape(envelope LaunchEffectAuthorizationEnvelope) error {
	if envelope.EffectOrdinal < 0 || envelope.EmergencyFenceEpoch < 0 {
		return errors.New("launch authorization envelope ordinal or emergency fence epoch is invalid")
	}
	required := map[string]string{
		"tenant_id":                    envelope.TenantID,
		"workspace_id":                 envelope.WorkspaceID,
		"mission_id":                   envelope.MissionID,
		"principal":                    envelope.Principal,
		"audience":                     envelope.Audience,
		"kernel_trust_root_id":         envelope.KernelTrustRootID,
		"approval_artifact_ref":        envelope.ApprovalArtifactRef,
		"approval_consumption_ref":     envelope.ApprovalConsumptionRef,
		"dispatch_admission_ref":       envelope.DispatchAdmissionRef,
		"dependency_set_ref":           envelope.DependencySetRef,
		"kernel_verdict_ref":           envelope.KernelVerdictRef,
		"kernel_verdict_signer_key_id": envelope.KernelVerdictSignerKey,
		"effect_permit_ref":            envelope.EffectPermitRef,
		"permit_nonce":                 envelope.PermitNonce,
		"proof_session_ref":            envelope.ProofSessionRef,
		"evidence_reservation_ref":     envelope.EvidenceReservationRef,
		"connector_authority_ref":      envelope.ConnectorAuthorityRef,
	}
	for field, value := range required {
		if value == "" {
			return fmt.Errorf("launch authorization envelope %s is required", field)
		}
	}
	if !validLaunchNonce(envelope.PermitNonce) {
		return errors.New("launch authorization envelope permit nonce is not canonical")
	}
	hashes := map[string]string{
		"input_schema_hash":         envelope.InputSchemaHash,
		"input_hash":                envelope.InputHash,
		"idempotency_key":           envelope.IdempotencyKey,
		"plan_hash":                 envelope.PlanHash,
		"approval_artifact_hash":    envelope.ApprovalArtifactHash,
		"approval_consumption_hash": envelope.ApprovalConsumptionHash,
		"dispatch_admission_hash":   envelope.DispatchAdmissionHash,
		"dependency_set_hash":       envelope.DependencySetHash,
		"kernel_verdict_hash":       envelope.KernelVerdictHash,
		"effect_permit_hash":        envelope.EffectPermitHash,
		"connector_contract_hash":   envelope.ConnectorContractHash,
		"connector_authority_hash":  envelope.ConnectorAuthorityHash,
		"request_body_hash":         envelope.RequestBodyHash,
		"args_c14n_hash":            envelope.ArgsC14NHash,
	}
	for field, value := range hashes {
		if !validLaunchSHA256(value) {
			return fmt.Errorf("launch authorization envelope %s is not a canonical SHA-256 reference", field)
		}
	}
	return nil
}

func verifyLaunchEnvelopeTimes(envelope LaunchEffectAuthorizationEnvelope, ctx LaunchEffectEnvelopeVerificationContext) error {
	if ctx.Now.IsZero() {
		return errors.New("launch authorization envelope verification time is required")
	}
	verdictIssuedAt, err := time.Parse(time.RFC3339Nano, envelope.KernelVerdictIssuedAt)
	if err != nil {
		return errors.New("launch authorization envelope verdict issue time is invalid")
	}
	verdictExpiry, err := time.Parse(time.RFC3339Nano, envelope.KernelVerdictExpiry)
	if err != nil {
		return errors.New("launch authorization envelope verdict expiry is invalid")
	}
	permitIssuedAt, err := time.Parse(time.RFC3339Nano, envelope.PermitIssuedAt)
	if err != nil {
		return errors.New("launch authorization envelope permit issue time is invalid")
	}
	permitExpiry, err := time.Parse(time.RFC3339Nano, envelope.PermitExpiry)
	if err != nil {
		return errors.New("launch authorization envelope permit expiry is invalid")
	}
	deadline, err := time.Parse(time.RFC3339Nano, envelope.DispatchDeadline)
	if err != nil {
		return errors.New("launch authorization envelope dispatch deadline is invalid")
	}
	if verdictIssuedAt.After(ctx.Now) || permitIssuedAt.After(ctx.Now) {
		return errors.New("launch authorization envelope verdict or permit is not yet valid")
	}
	if !verdictIssuedAt.Before(verdictExpiry) || !permitIssuedAt.Before(permitExpiry) {
		return errors.New("launch authorization envelope verdict or permit validity window is empty")
	}
	if permitIssuedAt.Before(verdictIssuedAt) || permitExpiry.After(verdictExpiry) {
		return errors.New("launch authorization envelope permit escapes its verdict validity window")
	}
	if !ctx.Now.Before(verdictExpiry) || !ctx.Now.Before(permitExpiry) || !ctx.Now.Before(deadline) {
		return errors.New("launch authorization envelope verdict, permit, or dispatch deadline has expired")
	}
	if deadline.After(permitExpiry) {
		return errors.New("launch authorization envelope dispatch deadline exceeds permit expiry")
	}
	if ctx.MaximumPermitTTL <= 0 || permitExpiry.Sub(permitIssuedAt) > ctx.MaximumPermitTTL {
		return errors.New("launch authorization envelope permit lifetime exceeds the source-owned maximum")
	}
	if envelope.EffectID == EffectTypeDeployProductionActivate || envelope.EffectID == EffectTypeProviderRollback {
		rollbackExpiry, err := launchInputTime(envelope.Input, "rollback_permit_expiry")
		if err != nil || !ctx.Now.Before(rollbackExpiry) {
			return errors.New("launch rollback preauthorization is invalid or expired")
		}
	}
	if envelope.EffectID == EffectTypeSpendAuthorize {
		spendAuthorizedAt, err := launchInputTime(envelope.Input, "authorized_at")
		if err != nil || spendAuthorizedAt.After(ctx.Now) {
			return errors.New("launch spend authorization is not yet valid")
		}
		spendExpiry, err := launchInputTime(envelope.Input, "expires_at")
		if err != nil || !ctx.Now.Before(spendExpiry) {
			return errors.New("launch spend authorization is invalid or expired")
		}
	}
	return nil
}

func verifyLaunchPermitBinding(envelope LaunchEffectAuthorizationEnvelope, permit LaunchEffectPermitBinding) error {
	if !permit.SingleUse {
		return errors.New("launch authorization envelope permit is not single-use")
	}
	deadline, err := time.Parse(time.RFC3339Nano, envelope.DispatchDeadline)
	if err != nil {
		return errors.New("launch authorization envelope dispatch deadline is invalid")
	}
	expiry, err := time.Parse(time.RFC3339Nano, envelope.PermitExpiry)
	if err != nil {
		return errors.New("launch authorization envelope permit expiry is invalid")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, envelope.PermitIssuedAt)
	if err != nil {
		return errors.New("launch authorization envelope permit issue time is invalid")
	}
	verdictIssuedAt, err := time.Parse(time.RFC3339Nano, envelope.KernelVerdictIssuedAt)
	if err != nil {
		return errors.New("launch authorization envelope verdict issue time is invalid")
	}
	verdictExpiry, err := time.Parse(time.RFC3339Nano, envelope.KernelVerdictExpiry)
	if err != nil {
		return errors.New("launch authorization envelope verdict expiry is invalid")
	}
	stringBindings := []struct {
		name string
		a    string
		b    string
	}{
		{"effect_permit_ref", envelope.EffectPermitRef, permit.EffectPermitRef},
		{"effect_permit_hash", envelope.EffectPermitHash, permit.EffectPermitHash},
		{"permit_nonce", envelope.PermitNonce, permit.PermitNonce},
		{"proof_session_ref", envelope.ProofSessionRef, permit.ProofSessionRef},
		{"evidence_reservation_ref", envelope.EvidenceReservationRef, permit.EvidenceReservationRef},
		{"effect_id", envelope.EffectID, permit.EffectID},
		{"tenant_id", envelope.TenantID, permit.TenantID},
		{"workspace_id", envelope.WorkspaceID, permit.WorkspaceID},
		{"mission_id", envelope.MissionID, permit.MissionID},
		{"principal", envelope.Principal, permit.Principal},
		{"audience", envelope.Audience, permit.Audience},
		{"kernel_trust_root_id", envelope.KernelTrustRootID, permit.KernelTrustRootID},
		{"input_schema_hash", envelope.InputSchemaHash, permit.InputSchemaHash},
		{"input_hash", envelope.InputHash, permit.InputHash},
		{"idempotency_key", envelope.IdempotencyKey, permit.IdempotencyKey},
		{"plan_hash", envelope.PlanHash, permit.PlanHash},
		{"approval_artifact_ref", envelope.ApprovalArtifactRef, permit.ApprovalArtifactRef},
		{"approval_artifact_hash", envelope.ApprovalArtifactHash, permit.ApprovalArtifactHash},
		{"approval_consumption_ref", envelope.ApprovalConsumptionRef, permit.ApprovalConsumptionRef},
		{"approval_consumption_hash", envelope.ApprovalConsumptionHash, permit.ApprovalConsumptionHash},
		{"dispatch_admission_ref", envelope.DispatchAdmissionRef, permit.DispatchAdmissionRef},
		{"dispatch_admission_hash", envelope.DispatchAdmissionHash, permit.DispatchAdmissionHash},
		{"dependency_set_ref", envelope.DependencySetRef, permit.DependencySetRef},
		{"dependency_set_hash", envelope.DependencySetHash, permit.DependencySetHash},
		{"kernel_verdict_ref", envelope.KernelVerdictRef, permit.KernelVerdictRef},
		{"kernel_verdict_hash", envelope.KernelVerdictHash, permit.KernelVerdictHash},
		{"connector_id", envelope.ConnectorID, permit.ConnectorID},
		{"connector_contract_hash", envelope.ConnectorContractHash, permit.ConnectorContractHash},
		{"connector_authority_ref", envelope.ConnectorAuthorityRef, permit.ConnectorAuthorityRef},
		{"connector_authority_hash", envelope.ConnectorAuthorityHash, permit.ConnectorAuthorityHash},
		{"action_urn", envelope.ActionURN, permit.ActionURN},
		{"request_body_hash", envelope.RequestBodyHash, permit.RequestBodyHash},
		{"args_c14n_hash", envelope.ArgsC14NHash, permit.ArgsC14NHash},
		{"policy_epoch", envelope.PolicyEpoch, permit.PolicyEpoch},
	}
	for _, binding := range stringBindings {
		if binding.a == "" || !launchConstantEqual(binding.a, binding.b) {
			return fmt.Errorf("launch authorization envelope permit binding mismatch for %s", binding.name)
		}
	}
	if envelope.EffectOrdinal != permit.EffectOrdinal {
		return errors.New("launch authorization envelope permit binding mismatch for effect_ordinal")
	}
	if envelope.EmergencyFenceEpoch != permit.EmergencyFenceEpoch {
		return errors.New("launch authorization envelope permit binding mismatch for emergency_fence_epoch")
	}
	if !issuedAt.Equal(permit.PermitIssuedAt) || !expiry.Equal(permit.PermitExpiry) ||
		!verdictIssuedAt.Equal(permit.KernelVerdictIssuedAt) || !verdictExpiry.Equal(permit.KernelVerdictExpiry) ||
		!deadline.Equal(permit.DispatchDeadline) {
		return errors.New("launch authorization envelope permit time binding mismatch")
	}
	return nil
}

func verifyLaunchVerdictSignature(envelope LaunchEffectAuthorizationEnvelope, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("launch authorization envelope verdict public key has invalid size")
	}
	payload, err := LaunchEffectVerdictSigningBytes(envelope)
	if err != nil {
		return fmt.Errorf("canonicalize launch authorization envelope verdict: %w", err)
	}
	expectedHash := canonicalize.ComputeArtifactHash(payload)
	if !launchConstantEqual(envelope.KernelVerdictHash, expectedHash) {
		return errors.New("launch authorization envelope verdict hash mismatch")
	}
	signature, err := parseLaunchEd25519Signature(envelope.KernelVerdictSignature)
	if err != nil {
		return fmt.Errorf("launch authorization envelope verdict signature is invalid: %w", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("launch authorization envelope verdict signature verification failed")
	}
	return nil
}

func parseLaunchEd25519Signature(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, errors.New("signature algorithm is invalid")
	}
	encoded := strings.TrimPrefix(value, "ed25519:")
	if len(encoded) != ed25519.SignatureSize*2 || encoded != strings.ToLower(encoded) {
		return nil, errors.New("signature encoding is not canonical lowercase hex")
	}
	signature, err := hex.DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("signature encoding is invalid")
	}
	return signature, nil
}

func validLaunchNonce(value string) bool {
	if len(value) < 22 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}
