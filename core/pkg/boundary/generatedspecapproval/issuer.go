package generatedspecapproval

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// IssuerConfig names the Kernel signing identity and bounds a grant lifetime.
// The service that uses this helper must provide IDs/nonces from cryptographic
// randomness and persist the ceremony before returning the signed grant.
type IssuerConfig struct {
	GrantTTL          time.Duration
	ServerIdentity    string
	KernelTrustRootID string
	SigningKeyRef     string
}

// IssueGrant turns a verifier-derived quorum into a short-lived signed
// GeneratedSpec approval grant. It cannot issue execution authority and it
// does not persist replay state; the durable ceremony owns those concerns.
func IssueGrant(
	challenge contracts.GeneratedSpecApprovalChallenge,
	verified VerifiedApprovalRef,
	grantID, nonce string,
	signer crypto.Signer,
	config IssuerConfig,
	now time.Time,
) (SignedGrant, error) {
	if signer == nil {
		return SignedGrant{}, errors.New("generated spec approval issuer requires a signer")
	}
	if config.GrantTTL <= 0 || !validToken(config.ServerIdentity) || !validToken(config.KernelTrustRootID) || !validToken(config.SigningKeyRef) {
		return SignedGrant{}, errors.New("generated spec approval issuer config is invalid")
	}
	now = now.UTC().Truncate(time.Microsecond)
	if err := challenge.ValidateAt(now); err != nil {
		return SignedGrant{}, fmt.Errorf("validate generated spec approval challenge: %w", err)
	}
	if err := validateVerifiedApproval(challenge, verified); err != nil {
		return SignedGrant{}, err
	}
	// Compare at the grant's canonical microsecond precision: the verifier
	// preserves nanoseconds in VerifiedAt, so a mixed-precision comparison
	// would reject same-instant verification followed by issuance.
	if now.Before(verified.VerifiedAt.UTC().Truncate(time.Microsecond)) {
		return SignedGrant{}, errors.New("grant issuance precedes verified quorum")
	}
	if challenge.ServerIdentity != config.ServerIdentity {
		return SignedGrant{}, errors.New("issuer server identity does not match challenge")
	}
	if !validToken(grantID) || len(nonce) != 64 {
		return SignedGrant{}, errors.New("grant id and nonce are required")
	}
	ceremonyHash, err := CeremonyCommitment(challenge, verified)
	if err != nil {
		return SignedGrant{}, err
	}
	expiresAt := now.Add(config.GrantTTL)
	if expiresAt.After(challenge.ExpiresAt) {
		expiresAt = challenge.ExpiresAt
	}
	if !expiresAt.After(now) {
		return SignedGrant{}, errors.New("grant lifetime is exhausted")
	}
	approvers := make([]string, len(verified.Signers))
	for index, signer := range verified.Signers {
		approvers[index] = signer.PrincipalID
	}
	sort.Strings(approvers)
	grant, err := (contracts.GeneratedSpecApprovalGrant{
		Domain: contracts.GeneratedSpecApprovalGrantDomainV1, SchemaVersion: contracts.GeneratedSpecApprovalGrantSchemaV1,
		ContractVersion: contracts.GeneratedSpecApprovalGrantContractV1,
		GrantID:         grantID, TenantID: challenge.TenantID, WorkspaceID: challenge.WorkspaceID, Audience: challenge.Audience,
		GeneratedSpecID: challenge.GeneratedSpecID, GeneratedSpecHash: challenge.GeneratedSpecHash,
		ExecutionPlanHash: challenge.ExecutionPlanHash, PlanTransactionHash: challenge.PlanTransactionHash,
		WriteSetHash: challenge.WriteSetHash, VerificationScopeHash: challenge.VerificationScopeHash,
		PolicyEnvelopeHash: challenge.PolicyEnvelopeHash, PolicyVersion: challenge.PolicyVersion,
		PolicyEpoch: challenge.PolicyEpoch, Action: challenge.Action, RequestingPrincipalID: challenge.RequestingPrincipalID,
		ApproverPrincipalIDs: approvers, ApprovalID: challenge.ApprovalID, ChallengeHash: challenge.ChallengeHash,
		CeremonyHash: ceremonyHash, SignerSetHash: verified.SignerSetHash, AuthoritySource: challenge.AuthoritySource,
		AuthorityVersion: challenge.AuthorityVersion, AuthoritySnapshotHash: challenge.AuthoritySnapshotHash,
		ServerIdentity: config.ServerIdentity, KernelTrustRootID: config.KernelTrustRootID, SigningKeyRef: config.SigningKeyRef,
		IssuedAt: now, ExpiresAt: expiresAt, Nonce: nonce,
	}).Seal()
	if err != nil {
		return SignedGrant{}, fmt.Errorf("seal generated spec approval grant: %w", err)
	}
	return SignGrant(grant, signer)
}

// NewConsumption deterministically projects one grant onto the verified
// workload that atomically consumed it. The caller must persist this sealed
// value, sign it, and move the durable grant state in one transaction.
func NewConsumption(grant contracts.GeneratedSpecApprovalGrant, consumedBy string, consumedAt time.Time) (contracts.GeneratedSpecApprovalConsumption, error) {
	consumedAt = consumedAt.UTC().Truncate(time.Microsecond)
	if !validToken(consumedBy) {
		return contracts.GeneratedSpecApprovalConsumption{}, errors.New("consuming workload identity is required")
	}
	if err := grant.ValidateAt(consumedAt); err != nil {
		return contracts.GeneratedSpecApprovalConsumption{}, fmt.Errorf("consume generated spec approval grant: %w", err)
	}
	consumption, err := (contracts.GeneratedSpecApprovalConsumption{
		Domain: contracts.GeneratedSpecApprovalConsumptionDomainV1, SchemaVersion: contracts.GeneratedSpecApprovalConsumptionSchemaV1,
		ContractVersion: contracts.GeneratedSpecApprovalConsumptionContractV1,
		ApprovalID:      grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash,
		TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience, ConsumedBy: consumedBy,
		GeneratedSpecID: grant.GeneratedSpecID, GeneratedSpecHash: grant.GeneratedSpecHash,
		ExecutionPlanHash: grant.ExecutionPlanHash, PlanTransactionHash: grant.PlanTransactionHash,
		WriteSetHash: grant.WriteSetHash, VerificationScopeHash: grant.VerificationScopeHash,
		PolicyEnvelopeHash: grant.PolicyEnvelopeHash, PolicyVersion: grant.PolicyVersion,
		PolicyEpoch: grant.PolicyEpoch, Action: grant.Action, RequestingPrincipalID: grant.RequestingPrincipalID,
		ApproverPrincipalIDs: append([]string(nil), grant.ApproverPrincipalIDs...), ChallengeHash: grant.ChallengeHash,
		CeremonyHash: grant.CeremonyHash, SignerSetHash: grant.SignerSetHash, AuthoritySource: grant.AuthoritySource,
		AuthorityVersion: grant.AuthorityVersion, AuthoritySnapshotHash: grant.AuthoritySnapshotHash,
		ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
		GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: consumedAt,
	}).Seal()
	if err != nil {
		return contracts.GeneratedSpecApprovalConsumption{}, fmt.Errorf("seal generated spec approval consumption: %w", err)
	}
	return consumption, nil
}

// CeremonyCommitment is the deterministic link between the source-owned
// challenge and independently verified human quorum. A durable service should
// persist this exact commitment before issuing the grant that references it.
func CeremonyCommitment(challenge contracts.GeneratedSpecApprovalChallenge, verified VerifiedApprovalRef) (string, error) {
	if err := validateVerifiedApproval(challenge, verified); err != nil {
		return "", err
	}
	payload, err := canonicalize.JCS(struct {
		Domain                string    `json:"domain"`
		ApprovalID            string    `json:"approval_id"`
		TenantID              string    `json:"tenant_id"`
		WorkspaceID           string    `json:"workspace_id"`
		ChallengeHash         string    `json:"challenge_hash"`
		GeneratedSpecHash     string    `json:"generated_spec_hash"`
		ExecutionPlanHash     string    `json:"execution_plan_hash"`
		PlanTransactionHash   string    `json:"plan_transaction_hash"`
		WriteSetHash          string    `json:"write_set_hash"`
		VerificationScopeHash string    `json:"verification_scope_hash"`
		PolicyEnvelopeHash    string    `json:"policy_envelope_hash"`
		AuthoritySnapshotHash string    `json:"authority_snapshot_hash"`
		SignerSetHash         string    `json:"signer_set_hash"`
		VerifiedAt            time.Time `json:"verified_at"`
	}{
		Domain: "HELM/GeneratedSpecApprovalCeremonyCommitment/v1", ApprovalID: challenge.ApprovalID,
		TenantID: challenge.TenantID, WorkspaceID: challenge.WorkspaceID, ChallengeHash: challenge.ChallengeHash,
		GeneratedSpecHash: challenge.GeneratedSpecHash, ExecutionPlanHash: challenge.ExecutionPlanHash,
		PlanTransactionHash: challenge.PlanTransactionHash, WriteSetHash: challenge.WriteSetHash,
		VerificationScopeHash: challenge.VerificationScopeHash, PolicyEnvelopeHash: challenge.PolicyEnvelopeHash,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash, SignerSetHash: verified.SignerSetHash,
		VerifiedAt: verified.VerifiedAt,
	})
	if err != nil {
		return "", fmt.Errorf("commit generated spec approval ceremony: %w", err)
	}
	hash := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func validateVerifiedApproval(challenge contracts.GeneratedSpecApprovalChallenge, verified VerifiedApprovalRef) error {
	if !verified.verified || verified.integrityHash == "" {
		return errors.New("verified approval capability is missing")
	}
	integrityHash, err := verifiedApprovalIntegrityHash(verified)
	if err != nil || integrityHash != verified.integrityHash {
		return errors.New("verified approval integrity mismatch")
	}
	if verified.ApprovalID != challenge.ApprovalID || verified.ChallengeID != challenge.ChallengeID ||
		verified.ChallengeHash != challenge.ChallengeHash || verified.TenantID != challenge.TenantID ||
		verified.WorkspaceID != challenge.WorkspaceID || verified.Audience != challenge.Audience ||
		verified.GeneratedSpecID != challenge.GeneratedSpecID || verified.GeneratedSpecHash != challenge.GeneratedSpecHash ||
		verified.ExecutionPlanHash != challenge.ExecutionPlanHash || verified.PlanTransactionHash != challenge.PlanTransactionHash ||
		verified.WriteSetHash != challenge.WriteSetHash || verified.VerificationScopeHash != challenge.VerificationScopeHash ||
		verified.PolicyEnvelopeHash != challenge.PolicyEnvelopeHash || verified.PolicyVersion != challenge.PolicyVersion ||
		verified.PolicyEpoch != challenge.PolicyEpoch || verified.Action != challenge.Action ||
		verified.RequestingPrincipalID != challenge.RequestingPrincipalID || verified.AuthoritySource != challenge.AuthoritySource ||
		verified.AuthorityVersion != challenge.AuthorityVersion || verified.AuthoritySnapshotHash != challenge.AuthoritySnapshotHash ||
		verified.RequiredRole != challenge.RequiredRole || verified.Quorum != challenge.Quorum || verified.ServerIdentity != challenge.ServerIdentity {
		return errors.New("verified approval binding mismatch")
	}
	if len(verified.Signers) < challenge.Quorum || verified.SignerSetHash == "" || verified.VerifiedAt.IsZero() || verified.VerifiedAt.Before(challenge.IssuedAt) || !verified.VerifiedAt.Before(challenge.ExpiresAt) {
		return errors.New("verified approval quorum evidence is invalid")
	}
	return nil
}
