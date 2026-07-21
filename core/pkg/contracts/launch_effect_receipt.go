// quantum_posture: launch receipts use classical Ed25519 signatures and make
// no hybrid or post-quantum protection claim.
package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	LaunchEffectReceiptSchemaVersion  = "launch_effect_receipt.v1"
	LaunchEffectReceiptVersion        = "1.0"
	LaunchEffectReceiptProfile        = "launch_effect_receipt.v1"
	launchEffectReceiptMaxSafeInteger = uint64(1<<53 - 1)
)

// LaunchEffectReceiptMetadata is intentionally closed and secret-free. Raw
// provider transcripts and arbitrary metadata are not admitted into receipts.
type LaunchEffectReceiptMetadata struct {
	Profile              string `json:"profile"`
	RedactionProfileHash string `json:"redaction_profile_hash"`
}

// LaunchEffectReceiptAuthorityBinding is source-owned dispatch truth resolved
// from the durable effect reservation. Receipt producers cannot satisfy this
// contract by reflecting fields from the receipt under verification.
type LaunchEffectReceiptAuthorityBinding struct {
	EffectReservationRef          string `json:"effect_reservation_ref"`
	EffectReservationHash         string `json:"effect_reservation_hash"`
	EffectID                      string `json:"effect_id"`
	TenantID                      string `json:"tenant_id"`
	WorkspaceID                   string `json:"workspace_id"`
	MissionID                     string `json:"mission_id"`
	Principal                     string `json:"principal"`
	Audience                      string `json:"audience"`
	KernelTrustRootID             string `json:"kernel_trust_root_id"`
	EffectOrdinal                 int    `json:"effect_ordinal"`
	InputSchemaHash               string `json:"input_schema_hash"`
	InputHash                     string `json:"input_hash"`
	IdempotencyKey                string `json:"idempotency_key"`
	PlanHash                      string `json:"plan_hash"`
	RequestHash                   string `json:"request_hash"`
	ArgsC14NHash                  string `json:"args_c14n_hash"`
	KernelVerdictRef              string `json:"kernel_verdict_ref"`
	KernelVerdictHash             string `json:"kernel_verdict_hash"`
	ApprovalArtifactRef           string `json:"approval_artifact_ref"`
	ApprovalArtifactHash          string `json:"approval_artifact_hash"`
	ApprovalConsumptionRef        string `json:"approval_consumption_ref"`
	ApprovalConsumptionHash       string `json:"approval_consumption_hash"`
	DispatchAdmissionRef          string `json:"dispatch_admission_ref"`
	DispatchAdmissionHash         string `json:"dispatch_admission_hash"`
	EffectPermitRef               string `json:"effect_permit_ref"`
	EffectPermitHash              string `json:"effect_permit_hash"`
	PermitNonce                   string `json:"permit_nonce"`
	PermitConsumptionRef          string `json:"permit_consumption_ref"`
	PermitConsumptionHash         string `json:"permit_consumption_hash"`
	ProofSessionRef               string `json:"proof_session_ref"`
	EvidenceReservationRef        string `json:"evidence_reservation_ref"`
	PolicyEpoch                   string `json:"policy_epoch"`
	EmergencyFenceEpoch           int64  `json:"emergency_fence_epoch"`
	ConnectorID                   string `json:"connector_id"`
	ConnectorContractHash         string `json:"connector_contract_hash"`
	ConnectorAuthorityRef         string `json:"connector_authority_ref"`
	ConnectorAuthorityHash        string `json:"connector_authority_hash"`
	ActionURN                     string `json:"action_urn"`
	DependencySetRef              string `json:"dependency_set_ref"`
	DependencySetHash             string `json:"dependency_set_hash"`
	RouteBindingRef               string `json:"route_binding_ref,omitempty"`
	RouteBindingHash              string `json:"route_binding_hash,omitempty"`
	RoutePlacementID              string `json:"route_placement_id,omitempty"`
	ProviderID                    string `json:"provider_id,omitempty"`
	ProviderAccountRef            string `json:"provider_account_ref,omitempty"`
	ProviderAccountHash           string `json:"provider_account_hash,omitempty"`
	RegionID                      string `json:"region_id,omitempty"`
	OfferingID                    string `json:"offering_id,omitempty"`
	ProviderConnectorID           string `json:"provider_connector_id,omitempty"`
	ProviderConnectorContractHash string `json:"provider_connector_contract_hash,omitempty"`
	ProviderActionURN             string `json:"provider_action_urn,omitempty"`
	ProviderPayloadHash           string `json:"provider_payload_hash,omitempty"`
	ProviderProfileRef            string `json:"provider_capability_profile_ref,omitempty"`
	ProviderProfileHash           string `json:"provider_capability_profile_hash,omitempty"`
	ProviderCertificationRef      string `json:"provider_certification_ref,omitempty"`
	ProviderCertificationHash     string `json:"provider_certification_hash,omitempty"`
	OfferSnapshotRef              string `json:"offer_snapshot_ref,omitempty"`
	OfferSnapshotHash             string `json:"offer_snapshot_hash,omitempty"`
	PriceEvidenceHash             string `json:"price_evidence_hash,omitempty"`
	TermsEvidenceHash             string `json:"terms_evidence_hash,omitempty"`
}

// LaunchEffectEvidenceNode is the minimal source-owned projection needed to
// verify that effect evidence precedes receipts and EvidencePacks. ArtifactRefs
// must never contain a receipt or EvidencePack dependency.
type LaunchEffectEvidenceNode struct {
	NodeHash               string   `json:"node_hash"`
	ParentHashes           []string `json:"parent_hashes"`
	ArtifactRefs           []string `json:"artifact_refs"`
	ProofSessionRef        string   `json:"proof_session_ref"`
	EvidenceReservationRef string   `json:"evidence_reservation_ref"`
	Lamport                uint64   `json:"lamport"`
}

type LaunchEffectEvidenceDAG struct {
	Nodes []LaunchEffectEvidenceNode `json:"nodes"`
}

// LaunchEffectReceipt is the Receipt Format v1 profile for one preview Launch
// Mission effect. ReceiptID is content-addressed, Signature is Ed25519 over the
// ReceiptID, and revisions form an append-only chain through PreviousReceiptID.
type LaunchEffectReceipt struct {
	SchemaVersion                 string                      `json:"schema_version"`
	ReceiptVersion                string                      `json:"receipt_version"`
	Kind                          string                      `json:"kind"`
	ReceiptID                     string                      `json:"receipt_id"`
	ReceiptChainID                string                      `json:"receipt_chain_id"`
	ReceiptRevision               int                         `json:"receipt_revision"`
	ReconciliationRevision        int                         `json:"reconciliation_revision"`
	DecisionID                    string                      `json:"decision_id"`
	EffectID                      string                      `json:"effect_id"`
	Verdict                       string                      `json:"verdict"`
	Principal                     string                      `json:"principal"`
	Audience                      string                      `json:"audience"`
	KernelTrustRootID             string                      `json:"kernel_trust_root_id"`
	Tool                          string                      `json:"tool"`
	Action                        string                      `json:"action"`
	Timestamp                     string                      `json:"timestamp"`
	Lamport                       uint64                      `json:"lamport"`
	ProofGraphNode                string                      `json:"proofgraph_node"`
	SignerKeyID                   string                      `json:"signer_key_id"`
	PayloadHash                   string                      `json:"payload_hash"`
	Metadata                      LaunchEffectReceiptMetadata `json:"metadata"`
	TenantID                      string                      `json:"tenant_id"`
	WorkspaceID                   string                      `json:"workspace_id"`
	MissionID                     string                      `json:"mission_id"`
	EffectOrdinal                 int                         `json:"effect_ordinal"`
	InputSchemaHash               string                      `json:"input_schema_hash"`
	InputHash                     string                      `json:"input_hash"`
	IdempotencyKey                string                      `json:"idempotency_key"`
	PlanHash                      string                      `json:"plan_hash"`
	RequestHash                   string                      `json:"request_hash"`
	ArgsC14NHash                  string                      `json:"args_c14n_hash"`
	ResultHash                    string                      `json:"result_hash"`
	KernelVerdictRef              string                      `json:"kernel_verdict_ref"`
	KernelVerdictHash             string                      `json:"kernel_verdict_hash"`
	ApprovalArtifactRef           string                      `json:"approval_artifact_ref"`
	ApprovalArtifactHash          string                      `json:"approval_artifact_hash"`
	ApprovalConsumptionRef        string                      `json:"approval_consumption_ref"`
	ApprovalConsumptionHash       string                      `json:"approval_consumption_hash"`
	DispatchAdmissionRef          string                      `json:"dispatch_admission_ref"`
	DispatchAdmissionHash         string                      `json:"dispatch_admission_hash"`
	EffectReservationRef          string                      `json:"effect_reservation_ref"`
	EffectReservationHash         string                      `json:"effect_reservation_hash"`
	EffectPermitRef               string                      `json:"effect_permit_ref"`
	EffectPermitHash              string                      `json:"effect_permit_hash"`
	PermitNonce                   string                      `json:"permit_nonce"`
	PermitConsumptionRef          string                      `json:"permit_consumption_ref"`
	PermitConsumptionHash         string                      `json:"permit_consumption_hash"`
	ProofSessionRef               string                      `json:"proof_session_ref"`
	EvidenceReservationRef        string                      `json:"evidence_reservation_ref"`
	PolicyEpoch                   string                      `json:"policy_epoch"`
	EmergencyFenceEpoch           int64                       `json:"emergency_fence_epoch"`
	ConnectorContractHash         string                      `json:"connector_contract_hash"`
	ConnectorAuthorityRef         string                      `json:"connector_authority_ref"`
	ConnectorAuthorityHash        string                      `json:"connector_authority_hash"`
	ReconciliationLocator         string                      `json:"reconciliation_locator_hash"`
	ProviderOperationRef          string                      `json:"provider_operation_ref,omitempty"`
	ProviderResourceRefs          []string                    `json:"provider_resource_refs,omitempty"`
	Outcome                       string                      `json:"outcome"`
	ReconciliationStatus          string                      `json:"reconciliation_status"`
	DependencyState               string                      `json:"dependency_state"`
	DependencySetRef              string                      `json:"dependency_set_ref"`
	DependencySetHash             string                      `json:"dependency_set_hash"`
	DependencyStateHash           string                      `json:"dependency_state_hash"`
	RouteBindingRef               string                      `json:"route_binding_ref,omitempty"`
	RouteBindingHash              string                      `json:"route_binding_hash,omitempty"`
	RoutePlacementID              string                      `json:"route_placement_id,omitempty"`
	ProviderID                    string                      `json:"provider_id,omitempty"`
	ProviderAccountRef            string                      `json:"provider_account_ref,omitempty"`
	ProviderAccountHash           string                      `json:"provider_account_hash,omitempty"`
	RegionID                      string                      `json:"region_id,omitempty"`
	OfferingID                    string                      `json:"offering_id,omitempty"`
	ProviderConnectorID           string                      `json:"provider_connector_id,omitempty"`
	ProviderConnectorContractHash string                      `json:"provider_connector_contract_hash,omitempty"`
	ProviderActionURN             string                      `json:"provider_action_urn,omitempty"`
	ProviderPayloadHash           string                      `json:"provider_payload_hash,omitempty"`
	ProviderProfileRef            string                      `json:"provider_capability_profile_ref,omitempty"`
	ProviderProfileHash           string                      `json:"provider_capability_profile_hash,omitempty"`
	ProviderCertificationRef      string                      `json:"provider_certification_ref,omitempty"`
	ProviderCertificationHash     string                      `json:"provider_certification_hash,omitempty"`
	OfferSnapshotRef              string                      `json:"offer_snapshot_ref,omitempty"`
	OfferSnapshotHash             string                      `json:"offer_snapshot_hash,omitempty"`
	PriceEvidenceHash             string                      `json:"price_evidence_hash,omitempty"`
	TermsEvidenceHash             string                      `json:"terms_evidence_hash,omitempty"`
	EvidencePackRef               string                      `json:"evidence_pack_ref,omitempty"`
	EvidencePackHash              string                      `json:"evidence_pack_hash,omitempty"`
	PreviousReceiptID             string                      `json:"previous_receipt_id,omitempty"`
	Signature                     string                      `json:"signature"`
}

// LaunchEffectReceiptVerificationContext supplies trust-root, durable effect
// reservation, and ProofGraph source truth. None may be copied from the
// receipt being verified.
type LaunchEffectReceiptVerificationContext struct {
	MinimumLamport         uint64
	ResolveSignerKey       func(signerKeyID string) (ed25519.PublicKey, error)
	ResolveAuthority       func(reservationRef, reservationHash string) (LaunchEffectReceiptAuthorityBinding, error)
	ResolveEvidenceDAG     func(nodeHash string) (LaunchEffectEvidenceDAG, error)
	ResolvePreviousReceipt func(previousReceiptID string) (LaunchEffectReceipt, error)
	VerifyEvidencePack     func(evidencePackRef, evidencePackHash, previousReceiptID string) error
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
		EffectID                  string `json:"effect_id"`
		TenantID                  string `json:"tenant_id"`
		WorkspaceID               string `json:"workspace_id"`
		MissionID                 string `json:"mission_id"`
		EffectOrdinal             int    `json:"effect_ordinal"`
		InputSchemaHash           string `json:"input_schema_hash"`
		InputHash                 string `json:"input_hash"`
		IdempotencyKey            string `json:"idempotency_key"`
		PlanHash                  string `json:"plan_hash"`
		RequestHash               string `json:"request_hash"`
		ArgsC14NHash              string `json:"args_c14n_hash"`
		KernelVerdictRef          string `json:"kernel_verdict_ref"`
		KernelVerdictHash         string `json:"kernel_verdict_hash"`
		Principal                 string `json:"principal"`
		Audience                  string `json:"audience"`
		KernelTrustRootID         string `json:"kernel_trust_root_id"`
		ApprovalArtifactRef       string `json:"approval_artifact_ref"`
		ApprovalArtifactHash      string `json:"approval_artifact_hash"`
		ApprovalConsumptionRef    string `json:"approval_consumption_ref"`
		ApprovalConsumptionHash   string `json:"approval_consumption_hash"`
		DispatchAdmissionRef      string `json:"dispatch_admission_ref"`
		DispatchAdmissionHash     string `json:"dispatch_admission_hash"`
		EffectReservationRef      string `json:"effect_reservation_ref"`
		EffectReservationHash     string `json:"effect_reservation_hash"`
		EffectPermitRef           string `json:"effect_permit_ref"`
		EffectPermitHash          string `json:"effect_permit_hash"`
		PermitNonce               string `json:"permit_nonce"`
		PermitConsumptionRef      string `json:"permit_consumption_ref"`
		PermitConsumptionHash     string `json:"permit_consumption_hash"`
		ProofSessionRef           string `json:"proof_session_ref"`
		EvidenceReservationRef    string `json:"evidence_reservation_ref"`
		PolicyEpoch               string `json:"policy_epoch"`
		EmergencyFenceEpoch       int64  `json:"emergency_fence_epoch"`
		ConnectorContractHash     string `json:"connector_contract_hash"`
		ConnectorAuthorityRef     string `json:"connector_authority_ref"`
		ConnectorAuthorityHash    string `json:"connector_authority_hash"`
		DependencySetRef          string `json:"dependency_set_ref"`
		DependencySetHash         string `json:"dependency_set_hash"`
		RouteBindingRef           string `json:"route_binding_ref,omitempty"`
		RouteBindingHash          string `json:"route_binding_hash,omitempty"`
		RoutePlacementID          string `json:"route_placement_id,omitempty"`
		ProviderID                string `json:"provider_id,omitempty"`
		ProviderAccountRef        string `json:"provider_account_ref,omitempty"`
		ProviderAccountHash       string `json:"provider_account_hash,omitempty"`
		RegionID                  string `json:"region_id,omitempty"`
		OfferingID                string `json:"offering_id,omitempty"`
		ProviderConnectorID       string `json:"provider_connector_id,omitempty"`
		ProviderConnectorHash     string `json:"provider_connector_contract_hash,omitempty"`
		ProviderActionURN         string `json:"provider_action_urn,omitempty"`
		ProviderPayloadHash       string `json:"provider_payload_hash,omitempty"`
		ProviderProfileRef        string `json:"provider_capability_profile_ref,omitempty"`
		ProviderProfileHash       string `json:"provider_capability_profile_hash,omitempty"`
		ProviderCertificationRef  string `json:"provider_certification_ref,omitempty"`
		ProviderCertificationHash string `json:"provider_certification_hash,omitempty"`
		OfferSnapshotRef          string `json:"offer_snapshot_ref,omitempty"`
		OfferSnapshotHash         string `json:"offer_snapshot_hash,omitempty"`
		PriceEvidenceHash         string `json:"price_evidence_hash,omitempty"`
		TermsEvidenceHash         string `json:"terms_evidence_hash,omitempty"`
	}{
		EffectID: receipt.EffectID, TenantID: receipt.TenantID, WorkspaceID: receipt.WorkspaceID,
		MissionID: receipt.MissionID, EffectOrdinal: receipt.EffectOrdinal, InputSchemaHash: receipt.InputSchemaHash, InputHash: receipt.InputHash,
		IdempotencyKey: receipt.IdempotencyKey, PlanHash: receipt.PlanHash, RequestHash: receipt.RequestHash, ArgsC14NHash: receipt.ArgsC14NHash,
		KernelVerdictRef: receipt.KernelVerdictRef, KernelVerdictHash: receipt.KernelVerdictHash,
		Principal: receipt.Principal, Audience: receipt.Audience, KernelTrustRootID: receipt.KernelTrustRootID,
		ApprovalArtifactRef: receipt.ApprovalArtifactRef, ApprovalArtifactHash: receipt.ApprovalArtifactHash,
		ApprovalConsumptionRef: receipt.ApprovalConsumptionRef, ApprovalConsumptionHash: receipt.ApprovalConsumptionHash,
		DispatchAdmissionRef: receipt.DispatchAdmissionRef, DispatchAdmissionHash: receipt.DispatchAdmissionHash,
		EffectReservationRef: receipt.EffectReservationRef, EffectReservationHash: receipt.EffectReservationHash,
		EffectPermitRef: receipt.EffectPermitRef, EffectPermitHash: receipt.EffectPermitHash, PermitNonce: receipt.PermitNonce,
		PermitConsumptionRef: receipt.PermitConsumptionRef, PermitConsumptionHash: receipt.PermitConsumptionHash,
		ProofSessionRef: receipt.ProofSessionRef, EvidenceReservationRef: receipt.EvidenceReservationRef,
		PolicyEpoch: receipt.PolicyEpoch, EmergencyFenceEpoch: receipt.EmergencyFenceEpoch,
		ConnectorContractHash: receipt.ConnectorContractHash, ConnectorAuthorityRef: receipt.ConnectorAuthorityRef, ConnectorAuthorityHash: receipt.ConnectorAuthorityHash,
		DependencySetRef: receipt.DependencySetRef, DependencySetHash: receipt.DependencySetHash,
		RouteBindingRef: receipt.RouteBindingRef, RouteBindingHash: receipt.RouteBindingHash, RoutePlacementID: receipt.RoutePlacementID,
		ProviderID: receipt.ProviderID, ProviderAccountRef: receipt.ProviderAccountRef, ProviderAccountHash: receipt.ProviderAccountHash,
		RegionID: receipt.RegionID, OfferingID: receipt.OfferingID, ProviderConnectorID: receipt.ProviderConnectorID,
		ProviderConnectorHash: receipt.ProviderConnectorContractHash, ProviderActionURN: receipt.ProviderActionURN, ProviderPayloadHash: receipt.ProviderPayloadHash,
		ProviderProfileRef: receipt.ProviderProfileRef, ProviderProfileHash: receipt.ProviderProfileHash,
		ProviderCertificationRef: receipt.ProviderCertificationRef, ProviderCertificationHash: receipt.ProviderCertificationHash,
		OfferSnapshotRef: receipt.OfferSnapshotRef, OfferSnapshotHash: receipt.OfferSnapshotHash,
		PriceEvidenceHash: receipt.PriceEvidenceHash, TermsEvidenceHash: receipt.TermsEvidenceHash,
	}
	hash, err := canonicalize.CanonicalHash(binding)
	if err != nil {
		return "", fmt.Errorf("derive launch effect receipt chain ID: %w", err)
	}
	return "sha256:" + hash, nil
}

// SignLaunchEffectReceipt seals a non-terminal immutable receipt revision using
// Receipt Format v1 content addressing and an Ed25519 signature over ReceiptID.
// Terminal revisions must use SignLaunchEffectReceiptRevision so they cannot be
// created without presenting the exact sealed predecessor they close.
func SignLaunchEffectReceipt(receipt LaunchEffectReceipt, privateKey ed25519.PrivateKey) (LaunchEffectReceipt, error) {
	if receipt.Outcome != "UNKNOWN" {
		return receipt, errors.New("terminal launch effect receipt must be signed as a verified revision")
	}
	return signLaunchEffectReceipt(receipt, privateKey)
}

// SignLaunchEffectReceiptRevision seals a revision only after its exact
// content-addressed predecessor and immutable transition have been supplied.
// Cryptographic predecessor verification remains mandatory at verification
// time because receipt signer keys may rotate between revisions.
func SignLaunchEffectReceiptRevision(current, previous LaunchEffectReceipt, privateKey ed25519.PrivateKey) (LaunchEffectReceipt, error) {
	if err := validateSealedLaunchEffectReceipt(previous); err != nil {
		return current, fmt.Errorf("validate launch effect receipt predecessor for signing: %w", err)
	}
	signed, err := signLaunchEffectReceipt(current, privateKey)
	if err != nil {
		return current, err
	}
	if err := validateLaunchEffectReceiptRevision(signed, previous); err != nil {
		return current, fmt.Errorf("validate launch effect receipt revision for signing: %w", err)
	}
	return signed, nil
}

func signLaunchEffectReceipt(receipt LaunchEffectReceipt, privateKey ed25519.PrivateKey) (LaunchEffectReceipt, error) {
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

func validateSealedLaunchEffectReceipt(receipt LaunchEffectReceipt) error {
	if err := ValidateLaunchEffectReceiptSemantics(receipt); err != nil {
		return err
	}
	if receipt.ReceiptID == "" || receipt.Signature == "" {
		return errors.New("launch effect receipt predecessor is not sealed")
	}
	payload, err := LaunchEffectReceiptSigningBytes(receipt)
	if err != nil {
		return fmt.Errorf("canonicalize launch effect receipt predecessor: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !launchConstantEqual(receipt.ReceiptID, hex.EncodeToString(digest[:])) {
		return errors.New("launch effect receipt predecessor content-addressed ID mismatch")
	}
	if _, err := parseLaunchReceiptSignature(receipt.Signature); err != nil {
		return fmt.Errorf("launch effect receipt predecessor signature is invalid: %w", err)
	}
	return nil
}

// VerifyLaunchEffectReceipt verifies content addressing, trust-root key
// resolution, the Ed25519 signature, the source-owned dispatch reservation,
// pre-receipt evidence DAG, and non-circular EvidencePack closure.
func VerifyLaunchEffectReceipt(receipt LaunchEffectReceipt, ctx LaunchEffectReceiptVerificationContext) error {
	if err := verifyLaunchEffectReceiptBase(receipt, ctx); err != nil {
		return err
	}
	if receipt.Outcome == "UNKNOWN" {
		return nil
	}
	if ctx.ResolvePreviousReceipt == nil {
		return errors.New("terminal launch effect receipt requires source-owned predecessor resolution")
	}
	previous, err := ctx.ResolvePreviousReceipt(receipt.PreviousReceiptID)
	if err != nil {
		return fmt.Errorf("resolve terminal launch effect receipt predecessor: %w", err)
	}
	if err := validateLaunchEffectReceiptPredecessorLink(receipt, previous); err != nil {
		return err
	}
	if err := VerifyLaunchEffectReceipt(previous, ctx); err != nil {
		return fmt.Errorf("verify terminal launch effect receipt predecessor: %w", err)
	}
	if err := validateLaunchEffectReceiptRevision(receipt, previous); err != nil {
		return err
	}
	return verifyLaunchEffectReceiptEvidencePack(receipt, previous, ctx)
}

func verifyLaunchEffectReceiptBase(receipt LaunchEffectReceipt, ctx LaunchEffectReceiptVerificationContext) error {
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
	if ctx.ResolveAuthority == nil {
		return errors.New("launch effect receipt requires durable authority resolution")
	}
	authority, err := ctx.ResolveAuthority(receipt.EffectReservationRef, receipt.EffectReservationHash)
	if err != nil {
		return fmt.Errorf("resolve launch effect receipt durable authority: %w", err)
	}
	if err := verifyLaunchReceiptAuthority(receipt, authority); err != nil {
		return err
	}
	if ctx.ResolveEvidenceDAG == nil {
		return errors.New("launch effect receipt requires source-owned evidence DAG resolution")
	}
	dag, err := ctx.ResolveEvidenceDAG(receipt.ProofGraphNode)
	if err != nil {
		return fmt.Errorf("resolve launch effect receipt evidence DAG: %w", err)
	}
	if err := verifyLaunchReceiptEvidenceDAG(receipt, dag); err != nil {
		return err
	}
	return nil
}

func verifyLaunchEffectReceiptEvidencePack(receipt, previous LaunchEffectReceipt, ctx LaunchEffectReceiptVerificationContext) error {
	if ctx.VerifyEvidencePack == nil {
		return errors.New("terminal launch effect receipt requires source-owned EvidencePack verification")
	}
	if err := ctx.VerifyEvidencePack(receipt.EvidencePackRef, receipt.EvidencePackHash, previous.ReceiptID); err != nil {
		return fmt.Errorf("verify terminal launch effect receipt EvidencePack: %w", err)
	}
	return nil
}

func verifyLaunchReceiptAuthority(receipt LaunchEffectReceipt, authority LaunchEffectReceiptAuthorityBinding) error {
	immutable := []struct {
		name     string
		receipt  string
		expected string
	}{
		{"effect_reservation_ref", receipt.EffectReservationRef, authority.EffectReservationRef},
		{"effect_reservation_hash", receipt.EffectReservationHash, authority.EffectReservationHash},
		{"effect_id", receipt.EffectID, authority.EffectID},
		{"tenant_id", receipt.TenantID, authority.TenantID},
		{"workspace_id", receipt.WorkspaceID, authority.WorkspaceID},
		{"mission_id", receipt.MissionID, authority.MissionID},
		{"principal", receipt.Principal, authority.Principal},
		{"audience", receipt.Audience, authority.Audience},
		{"kernel_trust_root_id", receipt.KernelTrustRootID, authority.KernelTrustRootID},
		{"input_schema_hash", receipt.InputSchemaHash, authority.InputSchemaHash},
		{"input_hash", receipt.InputHash, authority.InputHash},
		{"idempotency_key", receipt.IdempotencyKey, authority.IdempotencyKey},
		{"plan_hash", receipt.PlanHash, authority.PlanHash},
		{"request_hash", receipt.RequestHash, authority.RequestHash},
		{"args_c14n_hash", receipt.ArgsC14NHash, authority.ArgsC14NHash},
		{"kernel_verdict_ref", receipt.KernelVerdictRef, authority.KernelVerdictRef},
		{"kernel_verdict_hash", receipt.KernelVerdictHash, authority.KernelVerdictHash},
		{"approval_artifact_ref", receipt.ApprovalArtifactRef, authority.ApprovalArtifactRef},
		{"approval_artifact_hash", receipt.ApprovalArtifactHash, authority.ApprovalArtifactHash},
		{"approval_consumption_ref", receipt.ApprovalConsumptionRef, authority.ApprovalConsumptionRef},
		{"approval_consumption_hash", receipt.ApprovalConsumptionHash, authority.ApprovalConsumptionHash},
		{"dispatch_admission_ref", receipt.DispatchAdmissionRef, authority.DispatchAdmissionRef},
		{"dispatch_admission_hash", receipt.DispatchAdmissionHash, authority.DispatchAdmissionHash},
		{"effect_permit_ref", receipt.EffectPermitRef, authority.EffectPermitRef},
		{"effect_permit_hash", receipt.EffectPermitHash, authority.EffectPermitHash},
		{"permit_nonce", receipt.PermitNonce, authority.PermitNonce},
		{"permit_consumption_ref", receipt.PermitConsumptionRef, authority.PermitConsumptionRef},
		{"permit_consumption_hash", receipt.PermitConsumptionHash, authority.PermitConsumptionHash},
		{"proof_session_ref", receipt.ProofSessionRef, authority.ProofSessionRef},
		{"evidence_reservation_ref", receipt.EvidenceReservationRef, authority.EvidenceReservationRef},
		{"policy_epoch", receipt.PolicyEpoch, authority.PolicyEpoch},
		{"tool", receipt.Tool, authority.ConnectorID},
		{"connector_contract_hash", receipt.ConnectorContractHash, authority.ConnectorContractHash},
		{"connector_authority_ref", receipt.ConnectorAuthorityRef, authority.ConnectorAuthorityRef},
		{"connector_authority_hash", receipt.ConnectorAuthorityHash, authority.ConnectorAuthorityHash},
		{"action", receipt.Action, authority.ActionURN},
		{"dependency_set_ref", receipt.DependencySetRef, authority.DependencySetRef},
		{"dependency_set_hash", receipt.DependencySetHash, authority.DependencySetHash},
		{"route_binding_ref", receipt.RouteBindingRef, authority.RouteBindingRef},
		{"route_binding_hash", receipt.RouteBindingHash, authority.RouteBindingHash},
		{"route_placement_id", receipt.RoutePlacementID, authority.RoutePlacementID},
		{"provider_id", receipt.ProviderID, authority.ProviderID},
		{"provider_account_ref", receipt.ProviderAccountRef, authority.ProviderAccountRef},
		{"provider_account_hash", receipt.ProviderAccountHash, authority.ProviderAccountHash},
		{"region_id", receipt.RegionID, authority.RegionID},
		{"offering_id", receipt.OfferingID, authority.OfferingID},
		{"provider_connector_id", receipt.ProviderConnectorID, authority.ProviderConnectorID},
		{"provider_connector_contract_hash", receipt.ProviderConnectorContractHash, authority.ProviderConnectorContractHash},
		{"provider_action_urn", receipt.ProviderActionURN, authority.ProviderActionURN},
		{"provider_payload_hash", receipt.ProviderPayloadHash, authority.ProviderPayloadHash},
		{"provider_capability_profile_ref", receipt.ProviderProfileRef, authority.ProviderProfileRef},
		{"provider_capability_profile_hash", receipt.ProviderProfileHash, authority.ProviderProfileHash},
		{"provider_certification_ref", receipt.ProviderCertificationRef, authority.ProviderCertificationRef},
		{"provider_certification_hash", receipt.ProviderCertificationHash, authority.ProviderCertificationHash},
		{"offer_snapshot_ref", receipt.OfferSnapshotRef, authority.OfferSnapshotRef},
		{"offer_snapshot_hash", receipt.OfferSnapshotHash, authority.OfferSnapshotHash},
		{"price_evidence_hash", receipt.PriceEvidenceHash, authority.PriceEvidenceHash},
		{"terms_evidence_hash", receipt.TermsEvidenceHash, authority.TermsEvidenceHash},
	}
	for _, binding := range immutable {
		if !launchConstantEqual(binding.receipt, binding.expected) {
			return fmt.Errorf("launch effect receipt does not match source-owned authority field %s", binding.name)
		}
	}
	if receipt.EffectOrdinal != authority.EffectOrdinal || receipt.EmergencyFenceEpoch != authority.EmergencyFenceEpoch {
		return errors.New("launch effect receipt does not match source-owned authority ordinal or emergency fence")
	}
	return nil
}

func verifyLaunchReceiptEvidenceDAG(receipt LaunchEffectReceipt, dag LaunchEffectEvidenceDAG) error {
	if len(dag.Nodes) == 0 {
		return errors.New("launch effect receipt evidence DAG is empty")
	}
	nodes := make(map[string]LaunchEffectEvidenceNode, len(dag.Nodes))
	for _, node := range dag.Nodes {
		if !validLaunchSHA256(node.NodeHash) {
			return errors.New("launch effect receipt evidence DAG contains a noncanonical node hash")
		}
		if _, exists := nodes[node.NodeHash]; exists {
			return errors.New("launch effect receipt evidence DAG contains a duplicate node")
		}
		if node.ProofSessionRef != receipt.ProofSessionRef || node.EvidenceReservationRef != receipt.EvidenceReservationRef {
			return errors.New("launch effect receipt evidence DAG escaped its proof session or evidence reservation")
		}
		if node.Lamport == 0 || node.Lamport > launchEffectReceiptMaxSafeInteger {
			return errors.New("launch effect receipt evidence DAG Lamport clock exceeds the JCS safe-integer range")
		}
		if node.Lamport >= receipt.Lamport {
			return errors.New("launch effect receipt evidence DAG does not strictly precede the receipt")
		}
		if !launchStringRefsCanonical(node.ParentHashes) || !launchStringRefsCanonical(node.ArtifactRefs) {
			return errors.New("launch effect receipt evidence DAG references must be strictly sorted and unique")
		}
		for _, parentHash := range node.ParentHashes {
			if !validLaunchSHA256(parentHash) {
				return errors.New("launch effect receipt evidence DAG contains a noncanonical parent hash")
			}
		}
		for _, artifactRef := range node.ArtifactRefs {
			if launchEvidenceRefDependsOnReceipt(receipt, artifactRef) {
				return errors.New("launch effect receipt evidence DAG depends on a receipt or EvidencePack")
			}
		}
		nodes[node.NodeHash] = node
	}
	if _, ok := nodes[receipt.ProofGraphNode]; !ok {
		return errors.New("launch effect receipt ProofGraph node is absent from the resolved evidence DAG")
	}
	state := make(map[string]uint8, len(nodes))
	var visit func(string) error
	visit = func(nodeHash string) error {
		switch state[nodeHash] {
		case 1:
			return errors.New("launch effect receipt evidence DAG contains a cycle")
		case 2:
			return nil
		}
		node, ok := nodes[nodeHash]
		if !ok {
			return errors.New("launch effect receipt evidence DAG omits a parent from the resolved closure")
		}
		state[nodeHash] = 1
		for _, parentHash := range node.ParentHashes {
			parent, ok := nodes[parentHash]
			if !ok {
				return errors.New("launch effect receipt evidence DAG omits a parent from the resolved closure")
			}
			if parent.Lamport >= node.Lamport {
				return errors.New("launch effect receipt evidence DAG parent Lamport clock does not precede its child")
			}
			if err := visit(parentHash); err != nil {
				return err
			}
		}
		state[nodeHash] = 2
		return nil
	}
	if err := visit(receipt.ProofGraphNode); err != nil {
		return err
	}
	return nil
}

func launchEvidenceRefDependsOnReceipt(receipt LaunchEffectReceipt, ref string) bool {
	lower := strings.ToLower(ref)
	if strings.HasPrefix(lower, "receipt:") || strings.HasPrefix(lower, "evidencepack:") || validLaunchReceiptID(ref) {
		return true
	}
	for _, forbidden := range []string{
		receipt.ReceiptID,
		receipt.PreviousReceiptID,
		receipt.ReceiptChainID,
		receipt.EvidencePackRef,
		receipt.EvidencePackHash,
		"sha256:" + receipt.ReceiptID,
		"sha256:" + receipt.PreviousReceiptID,
	} {
		if forbidden != "" && launchConstantEqual(ref, forbidden) {
			return true
		}
	}
	return false
}

// VerifyLaunchEffectReceiptRevision verifies one append-only reconciliation
// transition against the exact signed predecessor.
func VerifyLaunchEffectReceiptRevision(current, previous LaunchEffectReceipt, ctx LaunchEffectReceiptVerificationContext) error {
	if err := VerifyLaunchEffectReceipt(previous, ctx); err != nil {
		return fmt.Errorf("verify previous launch effect receipt: %w", err)
	}
	if err := verifyLaunchEffectReceiptBase(current, ctx); err != nil {
		return fmt.Errorf("verify current launch effect receipt: %w", err)
	}
	if err := validateLaunchEffectReceiptRevision(current, previous); err != nil {
		return err
	}
	if current.Outcome != "UNKNOWN" {
		return verifyLaunchEffectReceiptEvidencePack(current, previous, ctx)
	}
	return nil
}

func validateLaunchEffectReceiptPredecessorLink(current, previous LaunchEffectReceipt) error {
	if current.ReceiptRevision != previous.ReceiptRevision+1 || !launchConstantEqual(current.PreviousReceiptID, previous.ReceiptID) {
		return errors.New("launch effect receipt revision does not extend the signed predecessor")
	}
	if previous.Outcome != "UNKNOWN" {
		return errors.New("terminal launch effect receipt cannot be revised")
	}
	return nil
}

func validateLaunchEffectReceiptRevision(current, previous LaunchEffectReceipt) error {
	if err := validateLaunchEffectReceiptPredecessorLink(current, previous); err != nil {
		return err
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
		{"audience", current.Audience, previous.Audience},
		{"kernel_trust_root_id", current.KernelTrustRootID, previous.KernelTrustRootID},
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
		{"plan_hash", current.PlanHash, previous.PlanHash},
		{"request_hash", current.RequestHash, previous.RequestHash},
		{"args_c14n_hash", current.ArgsC14NHash, previous.ArgsC14NHash},
		{"kernel_verdict_ref", current.KernelVerdictRef, previous.KernelVerdictRef},
		{"kernel_verdict_hash", current.KernelVerdictHash, previous.KernelVerdictHash},
		{"approval_artifact_ref", current.ApprovalArtifactRef, previous.ApprovalArtifactRef},
		{"approval_artifact_hash", current.ApprovalArtifactHash, previous.ApprovalArtifactHash},
		{"approval_consumption_ref", current.ApprovalConsumptionRef, previous.ApprovalConsumptionRef},
		{"approval_consumption_hash", current.ApprovalConsumptionHash, previous.ApprovalConsumptionHash},
		{"dispatch_admission_ref", current.DispatchAdmissionRef, previous.DispatchAdmissionRef},
		{"dispatch_admission_hash", current.DispatchAdmissionHash, previous.DispatchAdmissionHash},
		{"effect_reservation_ref", current.EffectReservationRef, previous.EffectReservationRef},
		{"effect_reservation_hash", current.EffectReservationHash, previous.EffectReservationHash},
		{"effect_permit_ref", current.EffectPermitRef, previous.EffectPermitRef},
		{"effect_permit_hash", current.EffectPermitHash, previous.EffectPermitHash},
		{"permit_nonce", current.PermitNonce, previous.PermitNonce},
		{"permit_consumption_ref", current.PermitConsumptionRef, previous.PermitConsumptionRef},
		{"permit_consumption_hash", current.PermitConsumptionHash, previous.PermitConsumptionHash},
		{"proof_session_ref", current.ProofSessionRef, previous.ProofSessionRef},
		{"evidence_reservation_ref", current.EvidenceReservationRef, previous.EvidenceReservationRef},
		{"policy_epoch", current.PolicyEpoch, previous.PolicyEpoch},
		{"connector_contract_hash", current.ConnectorContractHash, previous.ConnectorContractHash},
		{"connector_authority_ref", current.ConnectorAuthorityRef, previous.ConnectorAuthorityRef},
		{"connector_authority_hash", current.ConnectorAuthorityHash, previous.ConnectorAuthorityHash},
		{"reconciliation_locator_hash", current.ReconciliationLocator, previous.ReconciliationLocator},
		{"dependency_set_hash", current.DependencySetHash, previous.DependencySetHash},
		{"dependency_set_ref", current.DependencySetRef, previous.DependencySetRef},
		{"route_binding_ref", current.RouteBindingRef, previous.RouteBindingRef},
		{"route_binding_hash", current.RouteBindingHash, previous.RouteBindingHash},
		{"route_placement_id", current.RoutePlacementID, previous.RoutePlacementID},
		{"provider_id", current.ProviderID, previous.ProviderID},
		{"provider_account_ref", current.ProviderAccountRef, previous.ProviderAccountRef},
		{"provider_account_hash", current.ProviderAccountHash, previous.ProviderAccountHash},
		{"region_id", current.RegionID, previous.RegionID},
		{"offering_id", current.OfferingID, previous.OfferingID},
		{"provider_connector_id", current.ProviderConnectorID, previous.ProviderConnectorID},
		{"provider_connector_contract_hash", current.ProviderConnectorContractHash, previous.ProviderConnectorContractHash},
		{"provider_action_urn", current.ProviderActionURN, previous.ProviderActionURN},
		{"provider_payload_hash", current.ProviderPayloadHash, previous.ProviderPayloadHash},
		{"provider_capability_profile_ref", current.ProviderProfileRef, previous.ProviderProfileRef},
		{"provider_capability_profile_hash", current.ProviderProfileHash, previous.ProviderProfileHash},
		{"provider_certification_ref", current.ProviderCertificationRef, previous.ProviderCertificationRef},
		{"provider_certification_hash", current.ProviderCertificationHash, previous.ProviderCertificationHash},
		{"offer_snapshot_ref", current.OfferSnapshotRef, previous.OfferSnapshotRef},
		{"offer_snapshot_hash", current.OfferSnapshotHash, previous.OfferSnapshotHash},
		{"price_evidence_hash", current.PriceEvidenceHash, previous.PriceEvidenceHash},
		{"terms_evidence_hash", current.TermsEvidenceHash, previous.TermsEvidenceHash},
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
	previousTime, err := time.Parse(time.RFC3339Nano, previous.Timestamp)
	if err != nil {
		return errors.New("previous launch effect receipt timestamp is invalid")
	}
	currentTime, err := time.Parse(time.RFC3339Nano, current.Timestamp)
	if err != nil {
		return errors.New("current launch effect receipt timestamp is invalid")
	}
	if !currentTime.After(previousTime) {
		return errors.New("launch effect receipt revision timestamp must advance")
	}
	materialChanged := launchReceiptReconciliationMaterialChanged(current, previous)
	if materialChanged && current.ReconciliationRevision <= previous.ReconciliationRevision {
		return errors.New("launch effect receipt reconciliation material changed without a new reconciliation revision")
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
	if receipt.DecisionID == "" || receipt.Principal == "" || receipt.Audience == "" || receipt.KernelTrustRootID == "" || receipt.TenantID == "" || receipt.WorkspaceID == "" || receipt.MissionID == "" ||
		receipt.KernelVerdictRef == "" || receipt.ApprovalArtifactRef == "" || receipt.ApprovalConsumptionRef == "" || receipt.DispatchAdmissionRef == "" || receipt.EffectReservationRef == "" || receipt.EffectPermitRef == "" || receipt.PermitConsumptionRef == "" || receipt.DependencySetRef == "" ||
		receipt.ProofSessionRef == "" || receipt.EvidenceReservationRef == "" || receipt.ConnectorAuthorityRef == "" ||
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
	if receipt.EffectOrdinal < 0 || receipt.EmergencyFenceEpoch < 0 || receipt.ReceiptRevision < 1 || receipt.ReconciliationRevision < 0 || receipt.Lamport == 0 {
		return errors.New("launch effect receipt revision, ordinal, or Lamport clock is invalid")
	}
	if uint64(receipt.EffectOrdinal) > launchEffectReceiptMaxSafeInteger ||
		uint64(receipt.EmergencyFenceEpoch) > launchEffectReceiptMaxSafeInteger ||
		uint64(receipt.ReceiptRevision) > launchEffectReceiptMaxSafeInteger ||
		uint64(receipt.ReconciliationRevision) > launchEffectReceiptMaxSafeInteger ||
		receipt.Lamport > launchEffectReceiptMaxSafeInteger {
		return errors.New("launch effect receipt numeric field exceeds the JCS safe-integer range")
	}
	if receipt.ReconciliationRevision > receipt.ReceiptRevision {
		return errors.New("launch effect receipt reconciliation revision exceeds its receipt revision")
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
		"plan_hash":                   receipt.PlanHash,
		"request_hash":                receipt.RequestHash,
		"args_c14n_hash":              receipt.ArgsC14NHash,
		"result_hash":                 receipt.ResultHash,
		"kernel_verdict_hash":         receipt.KernelVerdictHash,
		"approval_artifact_hash":      receipt.ApprovalArtifactHash,
		"approval_consumption_hash":   receipt.ApprovalConsumptionHash,
		"dispatch_admission_hash":     receipt.DispatchAdmissionHash,
		"effect_reservation_hash":     receipt.EffectReservationHash,
		"effect_permit_hash":          receipt.EffectPermitHash,
		"permit_consumption_hash":     receipt.PermitConsumptionHash,
		"connector_contract_hash":     receipt.ConnectorContractHash,
		"connector_authority_hash":    receipt.ConnectorAuthorityHash,
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
	if launchEffectRequiresProviderRoute(receipt.EffectID) {
		if receipt.RouteBindingRef == "" || receipt.RoutePlacementID == "" || receipt.ProviderID == "" || receipt.ProviderAccountRef == "" || receipt.RegionID == "" || receipt.OfferingID == "" || receipt.ProviderConnectorID == "" ||
			receipt.ProviderProfileRef == "" || receipt.ProviderCertificationRef == "" || receipt.OfferSnapshotRef == "" {
			return errors.New("provider launch receipt is missing exact route or certification lineage")
		}
		for field, value := range map[string]string{
			"route_binding_hash":               receipt.RouteBindingHash,
			"provider_account_hash":            receipt.ProviderAccountHash,
			"provider_connector_contract_hash": receipt.ProviderConnectorContractHash,
			"provider_capability_profile_hash": receipt.ProviderProfileHash,
			"provider_certification_hash":      receipt.ProviderCertificationHash,
			"offer_snapshot_hash":              receipt.OfferSnapshotHash,
			"price_evidence_hash":              receipt.PriceEvidenceHash,
			"terms_evidence_hash":              receipt.TermsEvidenceHash,
		} {
			if !validLaunchSHA256(value) {
				return fmt.Errorf("provider launch receipt %s is not a canonical SHA-256 reference", field)
			}
		}
		if launchEffectIsProviderMutation(receipt.EffectID) {
			if receipt.ProviderActionURN == "" || !validLaunchSHA256(receipt.ProviderPayloadHash) {
				return errors.New("provider mutation receipt is missing its exact provider action or payload hash")
			}
		} else if receipt.ProviderActionURN != "" || receipt.ProviderPayloadHash != "" {
			return errors.New("non-mutating provider receipt cannot claim provider mutation authority")
		}
	} else if receipt.RouteBindingRef != "" || receipt.RouteBindingHash != "" || receipt.RoutePlacementID != "" || receipt.ProviderID != "" || receipt.ProviderAccountRef != "" || receipt.ProviderAccountHash != "" ||
		receipt.RegionID != "" || receipt.OfferingID != "" || receipt.ProviderConnectorID != "" || receipt.ProviderConnectorContractHash != "" || receipt.ProviderActionURN != "" || receipt.ProviderPayloadHash != "" ||
		receipt.ProviderProfileRef != "" || receipt.ProviderProfileHash != "" || receipt.ProviderCertificationRef != "" || receipt.ProviderCertificationHash != "" || receipt.OfferSnapshotRef != "" || receipt.OfferSnapshotHash != "" || receipt.PriceEvidenceHash != "" || receipt.TermsEvidenceHash != "" {
		return errors.New("non-provider launch receipt cannot claim provider route authority")
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
		if (receipt.ReconciliationStatus != "PENDING" && receipt.ReconciliationStatus != "CONFLICT") || receipt.DependencyState != "FROZEN" {
			return errors.New("UNKNOWN launch effect receipt must remain PENDING or CONFLICT with dependants FROZEN")
		}
		if receipt.EvidencePackRef != "" || receipt.EvidencePackHash != "" {
			return errors.New("UNKNOWN launch effect receipt cannot claim a finalized EvidencePack")
		}
	case "SUCCEEDED":
		if receipt.ReconciliationStatus != "PROVEN_APPLIED" || receipt.DependencyState != "RELEASED" || receipt.ReconciliationRevision < 1 {
			return errors.New("SUCCEEDED launch effect receipt requires PROVEN_APPLIED reconciliation before releasing dependants")
		}
		if receipt.ReceiptRevision < 2 || !validLaunchReceiptID(receipt.PreviousReceiptID) {
			return errors.New("SUCCEEDED launch effect receipt must close a prior signed reconciliation receipt")
		}
		if receipt.EvidencePackRef == "" || !validLaunchSHA256(receipt.EvidencePackHash) {
			return errors.New("SUCCEEDED launch effect receipt requires a finalized EvidencePack")
		}
	case "FAILED":
		if receipt.DependencyState != "FROZEN" || receipt.ReconciliationRevision < 1 {
			return errors.New("FAILED launch effect receipt must remain reconciled and FROZEN")
		}
		switch receipt.ReconciliationStatus {
		case "PROVEN_APPLIED", "PROVEN_NOT_APPLIED":
		default:
			return errors.New("FAILED launch effect receipt has no terminal reconciliation proof")
		}
		if receipt.ReceiptRevision < 2 || !validLaunchReceiptID(receipt.PreviousReceiptID) {
			return errors.New("FAILED launch effect receipt must close a prior signed reconciliation receipt")
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
	return launchStringRefsCanonical(refs)
}

func launchStringRefsCanonical(refs []string) bool {
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
