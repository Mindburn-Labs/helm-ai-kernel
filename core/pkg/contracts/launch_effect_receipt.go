package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	LaunchEffectReceiptSchemaVersion = "launch_effect_receipt.v1"
	LaunchEffectReceiptVersion       = "1.0"
	LaunchEffectReceiptProfile       = "launch_effect_receipt.v1"
)

// LaunchEffectReceiptMetadata is intentionally closed and secret-free. Raw
// provider transcripts and arbitrary metadata are not admitted into receipts.
type LaunchEffectReceiptMetadata struct {
	Profile              string `json:"profile"`
	RedactionProfileHash string `json:"redaction_profile_hash"`
}

// LaunchEffectReceipt is the Receipt Format v1 profile for one preview Launch
// Mission effect. ReceiptID is content-addressed, Signature is Ed25519 over the
// ReceiptID, and revisions form an append-only chain through PreviousReceiptID.
type LaunchEffectReceipt struct {
	SchemaVersion          string                      `json:"schema_version"`
	ReceiptVersion         string                      `json:"receipt_version"`
	Kind                   string                      `json:"kind"`
	ReceiptID              string                      `json:"receipt_id"`
	ReceiptChainID         string                      `json:"receipt_chain_id"`
	ReceiptRevision        int                         `json:"receipt_revision"`
	ReconciliationRevision int                         `json:"reconciliation_revision"`
	DecisionID             string                      `json:"decision_id"`
	EffectID               string                      `json:"effect_id"`
	Verdict                string                      `json:"verdict"`
	Principal              string                      `json:"principal"`
	Tool                   string                      `json:"tool"`
	Action                 string                      `json:"action"`
	Timestamp              string                      `json:"timestamp"`
	Lamport                uint64                      `json:"lamport"`
	ProofGraphNode         string                      `json:"proofgraph_node"`
	SignerKeyID            string                      `json:"signer_key_id"`
	PayloadHash            string                      `json:"payload_hash"`
	Metadata               LaunchEffectReceiptMetadata `json:"metadata"`
	TenantID               string                      `json:"tenant_id"`
	WorkspaceID            string                      `json:"workspace_id"`
	MissionID              string                      `json:"mission_id"`
	EffectOrdinal          int                         `json:"effect_ordinal"`
	InputSchemaHash        string                      `json:"input_schema_hash"`
	InputHash              string                      `json:"input_hash"`
	IdempotencyKey         string                      `json:"idempotency_key"`
	RequestHash            string                      `json:"request_hash"`
	ResultHash             string                      `json:"result_hash"`
	KernelVerdictRef       string                      `json:"kernel_verdict_ref"`
	KernelVerdictHash      string                      `json:"kernel_verdict_hash"`
	ApprovalArtifactRef    string                      `json:"approval_artifact_ref"`
	ApprovalArtifactHash   string                      `json:"approval_artifact_hash"`
	EffectPermitRef        string                      `json:"effect_permit_ref"`
	EffectPermitHash       string                      `json:"effect_permit_hash"`
	PermitNonce            string                      `json:"permit_nonce"`
	PermitConsumptionRef   string                      `json:"permit_consumption_ref"`
	PermitConsumptionHash  string                      `json:"permit_consumption_hash"`
	PolicyEpoch            string                      `json:"policy_epoch"`
	EmergencyFenceEpoch    int64                       `json:"emergency_fence_epoch"`
	ConnectorContractHash  string                      `json:"connector_contract_hash"`
	ReconciliationLocator  string                      `json:"reconciliation_locator_hash"`
	ProviderOperationRef   string                      `json:"provider_operation_ref,omitempty"`
	ProviderResourceRefs   []string                    `json:"provider_resource_refs,omitempty"`
	Outcome                string                      `json:"outcome"`
	ReconciliationStatus   string                      `json:"reconciliation_status"`
	DependencyState        string                      `json:"dependency_state"`
	DependencySetHash      string                      `json:"dependency_set_hash"`
	DependencyStateHash    string                      `json:"dependency_state_hash"`
	EvidencePackRef        string                      `json:"evidence_pack_ref,omitempty"`
	EvidencePackHash       string                      `json:"evidence_pack_hash,omitempty"`
	PreviousReceiptID      string                      `json:"previous_receipt_id,omitempty"`
	Signature              string                      `json:"signature"`
}

// LaunchEffectReceiptVerificationContext supplies trust-root and ProofGraph
// source truth; neither may be copied from the receipt being verified.
type LaunchEffectReceiptVerificationContext struct {
	MinimumLamport       uint64
	ResolveSignerKey     func(signerKeyID string) (ed25519.PublicKey, error)
	VerifyProofGraphNode func(nodeHash string) error
}

// LaunchEffectReceiptSigningBytes returns the RFC 8785 content-addressing
// preimage. ReceiptID and Signature are cleared to break the required signing
// cycle: the signature is subsequently computed over the derived ReceiptID.
func LaunchEffectReceiptSigningBytes(receipt LaunchEffectReceipt) ([]byte, error) {
	receipt.ReceiptID = ""
	receipt.Signature = ""
	return canonicalize.JCS(receipt)
}

// DeriveLaunchEffectReceiptChainID binds every revision to the exact immutable
// dispatch identity while allowing reconciliation material to evolve.
func DeriveLaunchEffectReceiptChainID(receipt LaunchEffectReceipt) (string, error) {
	binding := struct {
		EffectID              string `json:"effect_id"`
		TenantID              string `json:"tenant_id"`
		WorkspaceID           string `json:"workspace_id"`
		MissionID             string `json:"mission_id"`
		EffectOrdinal         int    `json:"effect_ordinal"`
		InputSchemaHash       string `json:"input_schema_hash"`
		InputHash             string `json:"input_hash"`
		IdempotencyKey        string `json:"idempotency_key"`
		RequestHash           string `json:"request_hash"`
		KernelVerdictRef      string `json:"kernel_verdict_ref"`
		KernelVerdictHash     string `json:"kernel_verdict_hash"`
		ApprovalArtifactRef   string `json:"approval_artifact_ref"`
		ApprovalArtifactHash  string `json:"approval_artifact_hash"`
		EffectPermitRef       string `json:"effect_permit_ref"`
		EffectPermitHash      string `json:"effect_permit_hash"`
		PermitNonce           string `json:"permit_nonce"`
		PermitConsumptionRef  string `json:"permit_consumption_ref"`
		PermitConsumptionHash string `json:"permit_consumption_hash"`
		PolicyEpoch           string `json:"policy_epoch"`
		EmergencyFenceEpoch   int64  `json:"emergency_fence_epoch"`
		ConnectorContractHash string `json:"connector_contract_hash"`
	}{
		EffectID: receipt.EffectID, TenantID: receipt.TenantID, WorkspaceID: receipt.WorkspaceID,
		MissionID: receipt.MissionID, EffectOrdinal: receipt.EffectOrdinal, InputSchemaHash: receipt.InputSchemaHash, InputHash: receipt.InputHash,
		IdempotencyKey: receipt.IdempotencyKey, RequestHash: receipt.RequestHash,
		KernelVerdictRef: receipt.KernelVerdictRef, KernelVerdictHash: receipt.KernelVerdictHash,
		ApprovalArtifactRef: receipt.ApprovalArtifactRef, ApprovalArtifactHash: receipt.ApprovalArtifactHash,
		EffectPermitRef: receipt.EffectPermitRef, EffectPermitHash: receipt.EffectPermitHash, PermitNonce: receipt.PermitNonce,
		PermitConsumptionRef: receipt.PermitConsumptionRef, PermitConsumptionHash: receipt.PermitConsumptionHash,
		PolicyEpoch: receipt.PolicyEpoch, EmergencyFenceEpoch: receipt.EmergencyFenceEpoch,
		ConnectorContractHash: receipt.ConnectorContractHash,
	}
	hash, err := canonicalize.CanonicalHash(binding)
	if err != nil {
		return "", fmt.Errorf("derive launch effect receipt chain ID: %w", err)
	}
	return "sha256:" + hash, nil
}

// SignLaunchEffectReceipt seals one immutable receipt revision using Receipt
// Format v1 content addressing and an Ed25519 signature over ReceiptID.
func SignLaunchEffectReceipt(receipt LaunchEffectReceipt, privateKey ed25519.PrivateKey) (LaunchEffectReceipt, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return receipt, errors.New("launch effect receipt private key has invalid size")
	}
	chainID, err := DeriveLaunchEffectReceiptChainID(receipt)
	if err != nil {
		return receipt, err
	}
	if receipt.ReceiptChainID == "" {
		receipt.ReceiptChainID = chainID
	} else if !launchConstantEqual(receipt.ReceiptChainID, chainID) {
		return receipt, errors.New("launch effect receipt chain ID does not match immutable dispatch identity")
	}
	receipt.ReceiptID = ""
	receipt.Signature = ""
	if err := ValidateLaunchEffectReceiptSemantics(receipt); err != nil {
		return receipt, err
	}
	payload, err := LaunchEffectReceiptSigningBytes(receipt)
	if err != nil {
		return receipt, fmt.Errorf("canonicalize launch effect receipt: %w", err)
	}
	digest := sha256.Sum256(payload)
	receipt.ReceiptID = hex.EncodeToString(digest[:])
	receipt.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(receipt.ReceiptID)))
	return receipt, nil
}

// VerifyLaunchEffectReceipt verifies content addressing, trust-root key
// resolution, the Ed25519 signature, Lamport bounds, and ProofGraph existence.
func VerifyLaunchEffectReceipt(receipt LaunchEffectReceipt, ctx LaunchEffectReceiptVerificationContext) error {
	if err := ValidateLaunchEffectReceiptSemantics(receipt); err != nil {
		return err
	}
	if ctx.MinimumLamport == 0 || receipt.Lamport < ctx.MinimumLamport {
		return errors.New("launch effect receipt Lamport clock is outside source-owned bounds")
	}
	if ctx.ResolveSignerKey == nil {
		return errors.New("launch effect receipt requires a trust-root key resolver")
	}
	publicKey, err := ctx.ResolveSignerKey(receipt.SignerKeyID)
	if err != nil {
		return fmt.Errorf("resolve launch effect receipt signer key: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("launch effect receipt resolved public key has invalid size")
	}
	payload, err := LaunchEffectReceiptSigningBytes(receipt)
	if err != nil {
		return fmt.Errorf("canonicalize launch effect receipt: %w", err)
	}
	digest := sha256.Sum256(payload)
	expectedID := hex.EncodeToString(digest[:])
	if !launchConstantEqual(receipt.ReceiptID, expectedID) {
		return errors.New("launch effect receipt content-addressed ID mismatch")
	}
	signature, err := parseLaunchReceiptSignature(receipt.Signature)
	if err != nil {
		return fmt.Errorf("launch effect receipt signature is invalid: %w", err)
	}
	if !ed25519.Verify(publicKey, []byte(receipt.ReceiptID), signature) {
		return errors.New("launch effect receipt signature verification failed")
	}
	if ctx.VerifyProofGraphNode == nil {
		return errors.New("launch effect receipt requires ProofGraph verification")
	}
	if err := ctx.VerifyProofGraphNode(receipt.ProofGraphNode); err != nil {
		return fmt.Errorf("verify launch effect receipt ProofGraph node: %w", err)
	}
	return nil
}

// VerifyLaunchEffectReceiptRevision verifies one append-only reconciliation
// transition against the exact signed predecessor.
func VerifyLaunchEffectReceiptRevision(current, previous LaunchEffectReceipt, ctx LaunchEffectReceiptVerificationContext) error {
	if err := VerifyLaunchEffectReceipt(previous, ctx); err != nil {
		return fmt.Errorf("verify previous launch effect receipt: %w", err)
	}
	if err := VerifyLaunchEffectReceipt(current, ctx); err != nil {
		return fmt.Errorf("verify current launch effect receipt: %w", err)
	}
	if current.ReceiptRevision != previous.ReceiptRevision+1 || !launchConstantEqual(current.PreviousReceiptID, previous.ReceiptID) {
		return errors.New("launch effect receipt revision does not extend the signed predecessor")
	}
	immutable := []struct {
		name string
		a    string
		b    string
	}{
		{"schema_version", current.SchemaVersion, previous.SchemaVersion},
		{"receipt_version", current.ReceiptVersion, previous.ReceiptVersion},
		{"kind", current.Kind, previous.Kind},
		{"receipt_chain_id", current.ReceiptChainID, previous.ReceiptChainID},
		{"decision_id", current.DecisionID, previous.DecisionID},
		{"effect_id", current.EffectID, previous.EffectID},
		{"verdict", current.Verdict, previous.Verdict},
		{"principal", current.Principal, previous.Principal},
		{"tool", current.Tool, previous.Tool},
		{"action", current.Action, previous.Action},
		{"signer_key_id", current.SignerKeyID, previous.SignerKeyID},
		{"payload_hash", current.PayloadHash, previous.PayloadHash},
		{"tenant_id", current.TenantID, previous.TenantID},
		{"workspace_id", current.WorkspaceID, previous.WorkspaceID},
		{"mission_id", current.MissionID, previous.MissionID},
		{"input_schema_hash", current.InputSchemaHash, previous.InputSchemaHash},
		{"input_hash", current.InputHash, previous.InputHash},
		{"idempotency_key", current.IdempotencyKey, previous.IdempotencyKey},
		{"request_hash", current.RequestHash, previous.RequestHash},
		{"kernel_verdict_ref", current.KernelVerdictRef, previous.KernelVerdictRef},
		{"kernel_verdict_hash", current.KernelVerdictHash, previous.KernelVerdictHash},
		{"approval_artifact_ref", current.ApprovalArtifactRef, previous.ApprovalArtifactRef},
		{"approval_artifact_hash", current.ApprovalArtifactHash, previous.ApprovalArtifactHash},
		{"effect_permit_ref", current.EffectPermitRef, previous.EffectPermitRef},
		{"effect_permit_hash", current.EffectPermitHash, previous.EffectPermitHash},
		{"permit_nonce", current.PermitNonce, previous.PermitNonce},
		{"permit_consumption_ref", current.PermitConsumptionRef, previous.PermitConsumptionRef},
		{"permit_consumption_hash", current.PermitConsumptionHash, previous.PermitConsumptionHash},
		{"policy_epoch", current.PolicyEpoch, previous.PolicyEpoch},
		{"connector_contract_hash", current.ConnectorContractHash, previous.ConnectorContractHash},
		{"reconciliation_locator_hash", current.ReconciliationLocator, previous.ReconciliationLocator},
		{"dependency_set_hash", current.DependencySetHash, previous.DependencySetHash},
		{"metadata.profile", current.Metadata.Profile, previous.Metadata.Profile},
		{"metadata.redaction_profile_hash", current.Metadata.RedactionProfileHash, previous.Metadata.RedactionProfileHash},
	}
	for _, binding := range immutable {
		if !launchConstantEqual(binding.a, binding.b) {
			return fmt.Errorf("launch effect receipt revision changed immutable %s", binding.name)
		}
	}
	if current.EffectOrdinal != previous.EffectOrdinal || current.EmergencyFenceEpoch != previous.EmergencyFenceEpoch || current.ReconciliationRevision < previous.ReconciliationRevision {
		return errors.New("launch effect receipt revision changed ordinal or regressed reconciliation revision")
	}
	if current.Lamport <= previous.Lamport {
		return errors.New("launch effect receipt revision Lamport clock must advance")
	}
	previousTime, _ := time.Parse(time.RFC3339Nano, previous.Timestamp)
	currentTime, _ := time.Parse(time.RFC3339Nano, current.Timestamp)
	if !currentTime.After(previousTime) {
		return errors.New("launch effect receipt revision timestamp must advance")
	}
	materialChanged := launchReceiptReconciliationMaterialChanged(current, previous)
	if materialChanged && current.ReconciliationRevision <= previous.ReconciliationRevision {
		return errors.New("launch effect receipt reconciliation material changed without a new reconciliation revision")
	}
	if previous.Outcome != "UNKNOWN" && materialChanged {
		return errors.New("terminal launch effect receipt reconciliation material cannot change")
	}
	return nil
}

// ValidateLaunchEffectReceiptSemantics validates both unsigned signing inputs
// and sealed receipts. Cryptographic verification remains separate.
func ValidateLaunchEffectReceiptSemantics(receipt LaunchEffectReceipt) error {
	if receipt.SchemaVersion != LaunchEffectReceiptSchemaVersion || receipt.ReceiptVersion != LaunchEffectReceiptVersion || receipt.Kind != "helm_native_receipt" {
		return errors.New("launch effect receipt version or kind is invalid")
	}
	contract := LookupLaunchMissionEffectPreview(receipt.EffectID)
	if contract == nil {
		return errors.New("launch effect receipt effect is not registered")
	}
	if receipt.DecisionID == "" || receipt.Principal == "" || receipt.TenantID == "" || receipt.WorkspaceID == "" || receipt.MissionID == "" ||
		receipt.KernelVerdictRef == "" || receipt.ApprovalArtifactRef == "" || receipt.EffectPermitRef == "" || receipt.PermitConsumptionRef == "" ||
		receipt.PolicyEpoch == "" || receipt.SignerKeyID == "" {
		return errors.New("launch effect receipt is missing an identity, authority, or signer reference")
	}
	if receipt.Verdict != "ALLOW" || receipt.DecisionID != receipt.KernelVerdictRef {
		return errors.New("launch effect receipt must bind its ALLOW decision to the Kernel verdict")
	}
	if receipt.Tool != contract.ConnectorID || receipt.Action != contract.ActionURN {
		return errors.New("launch effect receipt tool or action does not match the effect contract")
	}
	if !launchConstantEqual(receipt.PayloadHash, receipt.RequestHash) {
		return errors.New("launch effect receipt payload hash must bind the exact connector request")
	}
	if receipt.Metadata.Profile != LaunchEffectReceiptProfile || !validLaunchSHA256(receipt.Metadata.RedactionProfileHash) {
		return errors.New("launch effect receipt metadata profile or redaction binding is invalid")
	}
	if !validLaunchNonce(receipt.PermitNonce) {
		return errors.New("launch effect receipt permit nonce is not canonical")
	}
	if receipt.EffectOrdinal < 0 || receipt.EmergencyFenceEpoch < 0 || receipt.ReceiptRevision < 1 || receipt.ReconciliationRevision < 0 || receipt.ReconciliationRevision > receipt.ReceiptRevision || receipt.Lamport == 0 {
		return errors.New("launch effect receipt revision, ordinal, or Lamport clock is invalid")
	}
	if receipt.ReceiptRevision == 1 && receipt.PreviousReceiptID != "" {
		return errors.New("initial launch effect receipt cannot reference a previous revision")
	}
	if receipt.ReceiptRevision > 1 && !validLaunchReceiptID(receipt.PreviousReceiptID) {
		return errors.New("revised launch effect receipt must bind the previous content-addressed receipt ID")
	}
	if receipt.ReceiptID != "" && !validLaunchReceiptID(receipt.ReceiptID) {
		return errors.New("launch effect receipt ID is not canonical lowercase SHA-256 hex")
	}
	if receipt.Signature != "" {
		if _, err := parseLaunchReceiptSignature(receipt.Signature); err != nil {
			return fmt.Errorf("launch effect receipt signature is invalid: %w", err)
		}
	}
	for field, value := range map[string]string{
		"receipt_chain_id":            receipt.ReceiptChainID,
		"input_schema_hash":           receipt.InputSchemaHash,
		"input_hash":                  receipt.InputHash,
		"idempotency_key":             receipt.IdempotencyKey,
		"request_hash":                receipt.RequestHash,
		"result_hash":                 receipt.ResultHash,
		"kernel_verdict_hash":         receipt.KernelVerdictHash,
		"approval_artifact_hash":      receipt.ApprovalArtifactHash,
		"effect_permit_hash":          receipt.EffectPermitHash,
		"permit_consumption_hash":     receipt.PermitConsumptionHash,
		"connector_contract_hash":     receipt.ConnectorContractHash,
		"reconciliation_locator_hash": receipt.ReconciliationLocator,
		"proofgraph_node":             receipt.ProofGraphNode,
		"payload_hash":                receipt.PayloadHash,
		"dependency_set_hash":         receipt.DependencySetHash,
		"dependency_state_hash":       receipt.DependencyStateHash,
	} {
		if !validLaunchSHA256(value) {
			return fmt.Errorf("launch effect receipt %s is not a canonical SHA-256 reference", field)
		}
	}
	chainID, err := DeriveLaunchEffectReceiptChainID(receipt)
	if err != nil || !launchConstantEqual(receipt.ReceiptChainID, chainID) {
		return errors.New("launch effect receipt chain ID does not match immutable dispatch identity")
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.Timestamp); err != nil {
		return errors.New("launch effect receipt timestamp is invalid")
	}
	if !launchProviderResourceRefsCanonical(receipt.ProviderResourceRefs) {
		return errors.New("launch effect receipt provider resource references must be strictly sorted and unique")
	}
	if err := validateLaunchReceiptState(receipt); err != nil {
		return err
	}
	return nil
}

func validateLaunchReceiptState(receipt LaunchEffectReceipt) error {
	switch receipt.Outcome {
	case "UNKNOWN":
		if receipt.ReconciliationStatus != "PENDING" || receipt.DependencyState != "FROZEN" {
			return errors.New("UNKNOWN launch effect receipt must remain PENDING with dependants FROZEN")
		}
		if receipt.EvidencePackRef != "" || receipt.EvidencePackHash != "" {
			return errors.New("UNKNOWN launch effect receipt cannot claim a finalized EvidencePack")
		}
	case "SUCCEEDED":
		if receipt.ReconciliationStatus != "PROVEN_APPLIED" || receipt.DependencyState != "RELEASED" || receipt.ReconciliationRevision < 1 {
			return errors.New("SUCCEEDED launch effect receipt requires PROVEN_APPLIED reconciliation before releasing dependants")
		}
		if receipt.EvidencePackRef == "" || !validLaunchSHA256(receipt.EvidencePackHash) {
			return errors.New("SUCCEEDED launch effect receipt requires a finalized EvidencePack")
		}
	case "FAILED":
		if receipt.DependencyState != "FROZEN" || receipt.ReconciliationRevision < 1 {
			return errors.New("FAILED launch effect receipt must remain reconciled and FROZEN")
		}
		switch receipt.ReconciliationStatus {
		case "PROVEN_APPLIED", "PROVEN_NOT_APPLIED", "CONFLICT":
		default:
			return errors.New("FAILED launch effect receipt has no terminal reconciliation proof")
		}
		if receipt.EvidencePackRef == "" || !validLaunchSHA256(receipt.EvidencePackHash) {
			return errors.New("FAILED launch effect receipt requires a finalized EvidencePack")
		}
	default:
		return errors.New("launch effect receipt outcome is invalid")
	}
	if launchProviderEffect(receipt.EffectID) && receipt.ReconciliationStatus == "PROVEN_APPLIED" &&
		(receipt.ProviderOperationRef == "" || len(receipt.ProviderResourceRefs) == 0) {
		return errors.New("applied provider launch receipt is missing provider operation or resource references")
	}
	return nil
}

func launchReceiptReconciliationMaterialChanged(current, previous LaunchEffectReceipt) bool {
	return current.Outcome != previous.Outcome ||
		current.ReconciliationStatus != previous.ReconciliationStatus ||
		current.DependencyState != previous.DependencyState ||
		!launchConstantEqual(current.DependencyStateHash, previous.DependencyStateHash) ||
		!launchConstantEqual(current.ResultHash, previous.ResultHash) ||
		!launchConstantEqual(current.ProofGraphNode, previous.ProofGraphNode) ||
		!launchConstantEqual(current.ProviderOperationRef, previous.ProviderOperationRef) ||
		!launchConstantEqual(current.EvidencePackRef, previous.EvidencePackRef) ||
		!launchConstantEqual(current.EvidencePackHash, previous.EvidencePackHash) ||
		!launchStringSlicesEqual(current.ProviderResourceRefs, previous.ProviderResourceRefs)
}

func launchProviderResourceRefsCanonical(refs []string) bool {
	if len(refs) == 0 {
		return true
	}
	if !sort.StringsAreSorted(refs) {
		return false
	}
	for index, ref := range refs {
		if ref == "" || (index > 0 && refs[index-1] == ref) {
			return false
		}
	}
	return true
}

func launchStringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !launchConstantEqual(left[index], right[index]) {
			return false
		}
	}
	return true
}

func validLaunchReceiptID(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	return value == hex.EncodeToString(decoded)
}

func parseLaunchReceiptSignature(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("signature must be canonical base64 Ed25519 bytes")
	}
	return decoded, nil
}

func launchProviderEffect(effectID string) bool {
	switch effectID {
	case EffectTypeProviderProvision, EffectTypeDeployProductionActivate, EffectTypeProviderRollback, EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}
