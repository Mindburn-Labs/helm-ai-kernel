package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const LaunchEffectEnvelopeSchemaVersion = "launch_effect_envelope.v1"

// LaunchEffectAuthorizationEnvelope is the preview dispatch contract. Merely
// constructing this value grants no authority: VerifyLaunchEffectAuthorizationEnvelope
// must resolve and bind the single-use permit immediately before dispatch.
type LaunchEffectAuthorizationEnvelope struct {
	SchemaVersion          string         `json:"schema_version"`
	EffectID               string         `json:"effect_id"`
	TenantID               string         `json:"tenant_id"`
	WorkspaceID            string         `json:"workspace_id"`
	MissionID              string         `json:"mission_id"`
	EffectOrdinal          int            `json:"effect_ordinal"`
	InputSchemaRef         string         `json:"input_schema_ref"`
	InputSchemaHash        string         `json:"input_schema_hash"`
	Input                  map[string]any `json:"input"`
	InputHash              string         `json:"input_hash"`
	IdempotencyKey         string         `json:"idempotency_key"`
	PlanHash               string         `json:"plan_hash"`
	ApprovalArtifactRef    string         `json:"approval_artifact_ref"`
	ApprovalArtifactHash   string         `json:"approval_artifact_hash"`
	PolicyEpoch            string         `json:"policy_epoch"`
	EmergencyFenceEpoch    int64          `json:"emergency_fence_epoch"`
	Verdict                string         `json:"verdict"`
	KernelVerdictRef       string         `json:"kernel_verdict_ref"`
	KernelVerdictIssuedAt  string         `json:"kernel_verdict_issued_at"`
	KernelVerdictExpiry    string         `json:"kernel_verdict_expiry"`
	KernelVerdictSignerKey string         `json:"kernel_verdict_signer_key_id"`
	KernelVerdictHash      string         `json:"kernel_verdict_hash"`
	KernelVerdictSignature string         `json:"kernel_verdict_signature"`
	EffectPermitRef        string         `json:"effect_permit_ref"`
	EffectPermitHash       string         `json:"effect_permit_hash"`
	PermitNonce            string         `json:"permit_nonce"`
	PermitIssuedAt         string         `json:"permit_issued_at"`
	PermitExpiry           string         `json:"permit_expiry"`
	ProofSessionRef        string         `json:"proof_session_ref"`
	EvidenceReservationRef string         `json:"evidence_reservation_ref"`
	ConnectorID            string         `json:"connector_id"`
	ConnectorContractHash  string         `json:"connector_contract_hash"`
	ActionURN              string         `json:"action_urn"`
	RequestBodyHash        string         `json:"request_body_hash"`
	ArgsC14NHash           string         `json:"args_c14n_hash"`
	DispatchDeadline       string         `json:"dispatch_deadline"`
	ReplayHint             string         `json:"replay_hint"`
}

// LaunchEffectPermitBinding is the authoritative, server-side permit record
// resolved by reference. Every field is compared to the signed envelope.
type LaunchEffectPermitBinding struct {
	EffectPermitRef       string
	EffectPermitHash      string
	PermitNonce           string
	PermitIssuedAt        time.Time
	PermitExpiry          time.Time
	KernelVerdictRef      string
	KernelVerdictHash     string
	KernelVerdictIssuedAt time.Time
	KernelVerdictExpiry   time.Time
	EffectID              string
	TenantID              string
	WorkspaceID           string
	MissionID             string
	EffectOrdinal         int
	InputSchemaHash       string
	InputHash             string
	IdempotencyKey        string
	PlanHash              string
	ApprovalArtifactRef   string
	ApprovalArtifactHash  string
	ConnectorID           string
	ConnectorContractHash string
	ActionURN             string
	RequestBodyHash       string
	ArgsC14NHash          string
	PolicyEpoch           string
	EmergencyFenceEpoch   int64
	DispatchDeadline      time.Time
	SingleUse             bool
}

// LaunchEffectEnvelopeVerificationContext supplies independently resolved
// source truth. Values copied from the envelope are not valid inputs here.
type LaunchEffectEnvelopeVerificationContext struct {
	Now           time.Time
	ValidateInput func(schemaRef, schemaHash string, input map[string]any) error
	// ValidateProviderRoute independently resolves the RouteBinding, provider
	// capability profile, quote, constraint set, and connector certification.
	// It is mandatory for provider and spend effects; values copied only from
	// the signed envelope do not satisfy this source-truth check.
	ValidateProviderRoute   func(effectID string, input map[string]any) error
	ExpectedInputSchemaHash string
	ExpectedRequestBodyHash string
	ExpectedArgsC14NHash    string
	ExpectedPolicyEpoch     string
	CurrentEmergencyFence   int64
	MaximumPermitTTL        time.Duration
	ResolveVerdictKey       func(signerKeyID string) (ed25519.PublicKey, error)
	// ConsumePermit MUST atomically compare every binding and transition the
	// permit from fresh to consumed. It is invoked only after schema, semantic,
	// temporal, fence, binding, and signature verification all succeed.
	ConsumePermit func(expected LaunchEffectPermitBinding) error
	Permit        LaunchEffectPermitBinding
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

// VerifyLaunchEffectAuthorizationEnvelope fails closed unless the signed
// envelope, canonical effect input, independently resolved permit, current
// policy epoch, and emergency fence all describe the same one-shot dispatch.
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
	if ctx.ExpectedInputSchemaHash == "" || !launchConstantEqual(envelope.InputSchemaHash, ctx.ExpectedInputSchemaHash) {
		return errors.New("launch authorization envelope input schema hash is stale or untrusted")
	}
	if ctx.ValidateInput == nil {
		return errors.New("launch authorization envelope requires source-owned input schema validation")
	}
	if err := ctx.ValidateInput(envelope.InputSchemaRef, envelope.InputSchemaHash, envelope.Input); err != nil {
		return fmt.Errorf("launch authorization envelope input schema validation failed: %w", err)
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
	if ctx.CurrentEmergencyFence < 0 || envelope.EmergencyFenceEpoch != ctx.CurrentEmergencyFence {
		return errors.New("launch authorization envelope emergency fence epoch does not equal the current dispatch fence")
	}
	if err := verifyLaunchEnvelopeInputBindings(envelope); err != nil {
		return err
	}
	if launchEffectRequiresProviderRoute(envelope.EffectID) {
		if ctx.ValidateProviderRoute == nil {
			return errors.New("launch authorization envelope requires source-owned provider route validation")
		}
		if err := ctx.ValidateProviderRoute(envelope.EffectID, envelope.Input); err != nil {
			return fmt.Errorf("launch authorization envelope provider route validation failed: %w", err)
		}
	}
	if err := verifyLaunchApprovalArtifactBinding(envelope); err != nil {
		return err
	}
	if err := verifyLaunchEnvelopeTimes(envelope, ctx); err != nil {
		return err
	}
	if err := verifyLaunchPermitBinding(envelope, ctx.Permit); err != nil {
		return err
	}
	if ctx.ResolveVerdictKey == nil {
		return errors.New("launch authorization envelope requires a verdict trust-root resolver")
	}
	verdictPublicKey, err := ctx.ResolveVerdictKey(envelope.KernelVerdictSignerKey)
	if err != nil {
		return fmt.Errorf("resolve launch authorization envelope verdict key: %w", err)
	}
	if err := verifyLaunchVerdictSignature(envelope, verdictPublicKey); err != nil {
		return err
	}
	if ctx.ConsumePermit == nil {
		return errors.New("launch authorization envelope requires atomic permit consumption")
	}
	if err := ctx.ConsumePermit(ctx.Permit); err != nil {
		return fmt.Errorf("consume launch authorization envelope permit: %w", err)
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

func verifyLaunchApprovalArtifactBinding(envelope LaunchEffectAuthorizationEnvelope) error {
	var refField, hashField string
	switch envelope.EffectID {
	case EffectTypeDeployProductionActivate:
		refField, hashField = "promotion_permit_ref", "promotion_permit_hash"
	case EffectTypeProviderRollback:
		refField, hashField = "rollback_permit_ref", "rollback_permit_hash"
	case EffectTypeProviderTeardown:
		refField, hashField = "fresh_teardown_approval_ref", "fresh_teardown_approval_hash"
	default:
		return nil
	}
	ref, refOK := envelope.Input[refField].(string)
	hash, hashOK := envelope.Input[hashField].(string)
	if !refOK || !hashOK || !launchConstantEqual(ref, envelope.ApprovalArtifactRef) || !launchConstantEqual(hash, envelope.ApprovalArtifactHash) {
		return fmt.Errorf("launch authorization envelope approval artifact does not bind %s/%s", refField, hashField)
	}
	return nil
}

func validateLaunchEnvelopeShape(envelope LaunchEffectAuthorizationEnvelope) error {
	if envelope.EffectOrdinal < 0 || envelope.EmergencyFenceEpoch < 0 {
		return errors.New("launch authorization envelope ordinal or emergency fence epoch is invalid")
	}
	required := map[string]string{
		"tenant_id":                 envelope.TenantID,
		"workspace_id":              envelope.WorkspaceID,
		"mission_id":                envelope.MissionID,
		"approval_artifact_ref":     envelope.ApprovalArtifactRef,
		"kernel_verdict_ref":        envelope.KernelVerdictRef,
		"kernel_verdict_signer_key": envelope.KernelVerdictSignerKey,
		"effect_permit_ref":         envelope.EffectPermitRef,
		"permit_nonce":              envelope.PermitNonce,
		"proof_session_ref":         envelope.ProofSessionRef,
		"evidence_reservation_ref":  envelope.EvidenceReservationRef,
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
		"input_schema_hash":       envelope.InputSchemaHash,
		"input_hash":              envelope.InputHash,
		"idempotency_key":         envelope.IdempotencyKey,
		"plan_hash":               envelope.PlanHash,
		"approval_artifact_hash":  envelope.ApprovalArtifactHash,
		"kernel_verdict_hash":     envelope.KernelVerdictHash,
		"effect_permit_hash":      envelope.EffectPermitHash,
		"connector_contract_hash": envelope.ConnectorContractHash,
		"request_body_hash":       envelope.RequestBodyHash,
		"args_c14n_hash":          envelope.ArgsC14NHash,
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
		{"effect_id", envelope.EffectID, permit.EffectID},
		{"tenant_id", envelope.TenantID, permit.TenantID},
		{"workspace_id", envelope.WorkspaceID, permit.WorkspaceID},
		{"mission_id", envelope.MissionID, permit.MissionID},
		{"input_schema_hash", envelope.InputSchemaHash, permit.InputSchemaHash},
		{"input_hash", envelope.InputHash, permit.InputHash},
		{"idempotency_key", envelope.IdempotencyKey, permit.IdempotencyKey},
		{"plan_hash", envelope.PlanHash, permit.PlanHash},
		{"approval_artifact_ref", envelope.ApprovalArtifactRef, permit.ApprovalArtifactRef},
		{"approval_artifact_hash", envelope.ApprovalArtifactHash, permit.ApprovalArtifactHash},
		{"kernel_verdict_ref", envelope.KernelVerdictRef, permit.KernelVerdictRef},
		{"kernel_verdict_hash", envelope.KernelVerdictHash, permit.KernelVerdictHash},
		{"connector_id", envelope.ConnectorID, permit.ConnectorID},
		{"connector_contract_hash", envelope.ConnectorContractHash, permit.ConnectorContractHash},
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

func launchConstantEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func validLaunchSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	digest := strings.TrimPrefix(value, "sha256:")
	if digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
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

func validateLaunchEffectFixedSemantics(typeID string, input map[string]any) error {
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

func launchEffectIsProviderMutation(effectID string) bool {
	switch effectID {
	case EffectTypeProviderProvision, EffectTypeDeployProductionActivate, EffectTypeProviderRollback, EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}

func validateLaunchPrimaryEndpoint(input map[string]any) error {
	targetKind, _ := input["activation_target_kind"].(string)
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
