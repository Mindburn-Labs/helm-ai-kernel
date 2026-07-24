// quantum_posture: GeneratedSpec approval grants and consumption records use
// classical Ed25519 signatures and SHA-256 content binding in this contract;
// no hybrid or post-quantum approval assurance is claimed.
package generatedspecapproval

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var (
	ErrVerificationFailed = errors.New("generated spec approval verification failed")
	ErrAuthorityRejected  = errors.New("generated spec approval authority rejected")
	ErrAssertionRejected  = errors.New("generated spec approval assertion rejected")
	ErrDuplicateSigner    = errors.New("generated spec approval duplicate signer")
	ErrQuorumNotMet       = errors.New("generated spec approval quorum not met")
)

// ExpectedBinding is independently loaded policy and source state. The route
// that owns a ceremony constructs it; submitted assertions never define it.
type ExpectedBinding struct {
	ChallengeID   string
	ChallengeHash string
	ApprovalID    string
	TenantID      string
	WorkspaceID   string
	Audience      string

	GeneratedSpecID       string
	GeneratedSpecHash     string
	ExecutionPlanHash     string
	PlanTransactionHash   string
	WriteSetHash          string
	VerificationScopeHash string
	PolicyEnvelopeHash    string
	PolicyVersion         string
	PolicyEpoch           string
	Action                string
	RequestingPrincipalID string

	AuthoritySource       string
	AuthorityVersion      string
	AuthoritySnapshotHash string
	RequiredRole          string
	Quorum                int
	ServerIdentity        string
}

type VerifyOptions struct {
	Expected        ExpectedBinding
	MinHoldDuration time.Duration
	MaxChallengeTTL time.Duration
	MaxAssertions   int
}

// VerifiedApprovalRef is the verifier-derived human approval evidence that a
// durable generated-spec ceremony may commit before issuing a signed grant.
// It is not itself approval authority and cannot be client constructed into a
// grant issuance path: Issuer validates every bound value again.
type VerifiedApprovalRef struct {
	ApprovalID    string
	ChallengeID   string
	ChallengeHash string
	TenantID      string
	WorkspaceID   string
	Audience      string

	GeneratedSpecID       string
	GeneratedSpecHash     string
	ExecutionPlanHash     string
	PlanTransactionHash   string
	WriteSetHash          string
	VerificationScopeHash string
	PolicyEnvelopeHash    string
	PolicyVersion         string
	PolicyEpoch           string
	Action                string
	RequestingPrincipalID string

	AuthoritySource       string
	AuthorityVersion      string
	AuthoritySnapshotHash string
	RequiredRole          string
	Quorum                int
	ServerIdentity        string
	Signers               []approvalverify.VerifiedSigner
	SignerSetHash         string
	VerifiedAt            time.Time

	// verified and integrityHash form an in-package capability. They prevent a
	// future issuer from accepting a caller-assembled projection in place of
	// the result of VerifyGeneratedSpecQuorum. Durable stores must re-verify
	// assertions (or use an in-package verified reconstruction), never decode
	// an untrusted JSON projection into issuance authority.
	verified      bool
	integrityHash string
}

// VerifyGeneratedSpecQuorum verifies distinct human assertions over one typed
// GeneratedSpec challenge. It intentionally does not call the pack lifecycle
// verifier or accept a union contract: a successful result is suitable only
// for a later GeneratedSpec ceremony commitment and signed approval grant.
func VerifyGeneratedSpecQuorum(
	challenge contracts.GeneratedSpecApprovalChallenge,
	assertions []contracts.GeneratedSpecApprovalAssertion,
	store approvalverify.TrustStore,
	opts VerifyOptions,
	now time.Time,
) (VerifiedApprovalRef, error) {
	if err := validateVerifyOptions(opts); err != nil {
		return VerifiedApprovalRef{}, err
	}
	if err := challenge.ValidateAt(now); err != nil {
		return VerifiedApprovalRef{}, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}
	if challenge.EligibleAt.Sub(challenge.HoldStartedAt) < opts.MinHoldDuration {
		return VerifiedApprovalRef{}, verificationFailed("challenge hold duration is below policy minimum")
	}
	if challenge.ExpiresAt.Sub(challenge.HoldStartedAt) > opts.MaxChallengeTTL {
		return VerifiedApprovalRef{}, verificationFailed("challenge ttl exceeds maximum")
	}
	if err := verifyExpectedBinding(challenge, opts.Expected); err != nil {
		return VerifiedApprovalRef{}, err
	}
	if err := validateTrustStore(store, challenge); err != nil {
		return VerifiedApprovalRef{}, err
	}
	if len(assertions) < challenge.Quorum {
		return VerifiedApprovalRef{}, fmt.Errorf("%w: got %d assertions, need %d", ErrQuorumNotMet, len(assertions), challenge.Quorum)
	}
	if len(assertions) > opts.MaxAssertions {
		return VerifiedApprovalRef{}, verificationFailed("assertion count exceeds policy maximum")
	}

	seenKeys := make(map[string]struct{}, len(assertions))
	seenPrincipals := make(map[string]struct{}, len(assertions))
	seenCredentials := make(map[string]struct{}, len(assertions))
	seenDevices := make(map[string]struct{}, len(assertions))
	seenPublicKeys := make(map[string]struct{}, len(assertions))
	verified := make([]approvalverify.VerifiedSigner, 0, len(assertions))

	for _, assertion := range assertions {
		if err := assertion.Validate(); err != nil {
			return VerifiedApprovalRef{}, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}
		if assertion.ChallengeID != challenge.ChallengeID || assertion.ChallengeHash != challenge.ChallengeHash {
			return VerifiedApprovalRef{}, verificationFailed("assertion challenge binding mismatch")
		}
		if _, duplicate := seenKeys[assertion.KeyID]; duplicate {
			return VerifiedApprovalRef{}, duplicateSigner("key_id", assertion.KeyID)
		}
		key, ok := store.Keys[assertion.KeyID]
		if !ok {
			return VerifiedApprovalRef{}, authorityRejected("unknown key")
		}
		if err := validateTrustedKey(key, assertion.KeyID, challenge, now); err != nil {
			return VerifiedApprovalRef{}, err
		}
		if key.PrincipalID == challenge.RequestingPrincipalID {
			return VerifiedApprovalRef{}, authorityRejected("requester cannot approve its own generated spec")
		}
		digest, err := assertion.SigningDigest()
		if err != nil {
			return VerifiedApprovalRef{}, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}
		signature, err := assertion.SignatureBytes()
		if err != nil {
			return VerifiedApprovalRef{}, fmt.Errorf("%w: %w", ErrAssertionRejected, err)
		}
		if !ed25519.Verify(key.PublicKey, digest, signature) {
			return VerifiedApprovalRef{}, fmt.Errorf("%w: bad ed25519 signature for key %s", ErrAssertionRejected, assertion.KeyID)
		}
		if _, duplicate := seenPrincipals[key.PrincipalID]; duplicate {
			return VerifiedApprovalRef{}, duplicateSigner("principal_id", key.PrincipalID)
		}
		if _, duplicate := seenCredentials[key.CredentialID]; duplicate {
			return VerifiedApprovalRef{}, duplicateSigner("credential_id", key.CredentialID)
		}
		if _, duplicate := seenDevices[key.DeviceID]; duplicate {
			return VerifiedApprovalRef{}, duplicateSigner("device_id", key.DeviceID)
		}
		publicKeyIdentity := string(key.PublicKey)
		if _, duplicate := seenPublicKeys[publicKeyIdentity]; duplicate {
			return VerifiedApprovalRef{}, duplicateSigner("public_key", assertion.KeyID)
		}
		assertionHash, err := canonicalize.CanonicalHash(assertion)
		if err != nil {
			return VerifiedApprovalRef{}, verificationFailed("assertion canonicalization failed")
		}
		seenKeys[assertion.KeyID] = struct{}{}
		seenPrincipals[key.PrincipalID] = struct{}{}
		seenCredentials[key.CredentialID] = struct{}{}
		seenDevices[key.DeviceID] = struct{}{}
		seenPublicKeys[publicKeyIdentity] = struct{}{}
		verified = append(verified, approvalverify.VerifiedSigner{
			PrincipalID: key.PrincipalID, CredentialID: key.CredentialID, DeviceID: key.DeviceID,
			KeyID: key.KeyID, Role: challenge.RequiredRole, AssertionHash: "sha256:" + assertionHash,
		})
	}
	if len(verified) < challenge.Quorum {
		return VerifiedApprovalRef{}, fmt.Errorf("%w: got %d unique signers, need %d", ErrQuorumNotMet, len(verified), challenge.Quorum)
	}
	sort.Slice(verified, func(i, j int) bool {
		if verified[i].PrincipalID != verified[j].PrincipalID {
			return verified[i].PrincipalID < verified[j].PrincipalID
		}
		if verified[i].CredentialID != verified[j].CredentialID {
			return verified[i].CredentialID < verified[j].CredentialID
		}
		if verified[i].DeviceID != verified[j].DeviceID {
			return verified[i].DeviceID < verified[j].DeviceID
		}
		return verified[i].KeyID < verified[j].KeyID
	})
	signerSetHash, err := canonicalize.CanonicalHash(struct {
		Domain                string                          `json:"domain"`
		ChallengeHash         string                          `json:"challenge_hash"`
		AuthoritySnapshotHash string                          `json:"authority_snapshot_hash"`
		Signers               []approvalverify.VerifiedSigner `json:"signers"`
	}{
		Domain: "HELM/GeneratedSpecApprovalSignerSet/v1", ChallengeHash: challenge.ChallengeHash,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash, Signers: verified,
	})
	if err != nil {
		return VerifiedApprovalRef{}, verificationFailed("signer set canonicalization failed")
	}
	result := VerifiedApprovalRef{
		ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID, ChallengeHash: challenge.ChallengeHash,
		TenantID: challenge.TenantID, WorkspaceID: challenge.WorkspaceID, Audience: challenge.Audience,
		GeneratedSpecID: challenge.GeneratedSpecID, GeneratedSpecHash: challenge.GeneratedSpecHash,
		ExecutionPlanHash: challenge.ExecutionPlanHash, PlanTransactionHash: challenge.PlanTransactionHash,
		WriteSetHash: challenge.WriteSetHash, VerificationScopeHash: challenge.VerificationScopeHash,
		PolicyEnvelopeHash: challenge.PolicyEnvelopeHash, PolicyVersion: challenge.PolicyVersion,
		PolicyEpoch: challenge.PolicyEpoch, Action: challenge.Action, RequestingPrincipalID: challenge.RequestingPrincipalID,
		AuthoritySource: challenge.AuthoritySource, AuthorityVersion: challenge.AuthorityVersion,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash, RequiredRole: challenge.RequiredRole,
		Quorum: challenge.Quorum, ServerIdentity: challenge.ServerIdentity, Signers: verified,
		SignerSetHash: "sha256:" + signerSetHash, VerifiedAt: now.UTC(), verified: true,
	}
	integrityHash, err := verifiedApprovalIntegrityHash(result)
	if err != nil {
		return VerifiedApprovalRef{}, verificationFailed("verified approval canonicalization failed")
	}
	result.integrityHash = integrityHash
	return result, nil
}

func validateVerifyOptions(opts VerifyOptions) error {
	if opts.MinHoldDuration <= 0 || opts.MaxChallengeTTL <= opts.MinHoldDuration || opts.MaxAssertions <= 0 {
		return verificationFailed("invalid verification policy limits")
	}
	if opts.MaxAssertions < opts.Expected.Quorum || opts.Expected.Quorum <= 0 {
		return verificationFailed("maximum assertions must cover a positive quorum")
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "challenge_id", value: opts.Expected.ChallengeID}, {field: "challenge_hash", value: opts.Expected.ChallengeHash},
		{field: "approval_id", value: opts.Expected.ApprovalID}, {field: "tenant_id", value: opts.Expected.TenantID},
		{field: "workspace_id", value: opts.Expected.WorkspaceID}, {field: "audience", value: opts.Expected.Audience},
		{field: "generated_spec_id", value: opts.Expected.GeneratedSpecID}, {field: "generated_spec_hash", value: opts.Expected.GeneratedSpecHash},
		{field: "execution_plan_hash", value: opts.Expected.ExecutionPlanHash}, {field: "plan_transaction_hash", value: opts.Expected.PlanTransactionHash},
		{field: "write_set_hash", value: opts.Expected.WriteSetHash}, {field: "verification_scope_hash", value: opts.Expected.VerificationScopeHash},
		{field: "policy_envelope_hash", value: opts.Expected.PolicyEnvelopeHash}, {field: "policy_version", value: opts.Expected.PolicyVersion},
		{field: "policy_epoch", value: opts.Expected.PolicyEpoch}, {field: "action", value: opts.Expected.Action},
		{field: "requesting_principal_id", value: opts.Expected.RequestingPrincipalID}, {field: "authority_source", value: opts.Expected.AuthoritySource},
		{field: "authority_version", value: opts.Expected.AuthorityVersion}, {field: "authority_snapshot_hash", value: opts.Expected.AuthoritySnapshotHash},
		{field: "required_role", value: opts.Expected.RequiredRole}, {field: "server_identity", value: opts.Expected.ServerIdentity},
	} {
		if strings.TrimSpace(item.value) == "" {
			return verificationFailed("expected " + item.field + " is required")
		}
	}
	return nil
}

func verifyExpectedBinding(challenge contracts.GeneratedSpecApprovalChallenge, expected ExpectedBinding) error {
	actual := []struct{ field, actual, expected string }{
		{"challenge_id", challenge.ChallengeID, expected.ChallengeID}, {"challenge_hash", challenge.ChallengeHash, expected.ChallengeHash},
		{"approval_id", challenge.ApprovalID, expected.ApprovalID}, {"tenant_id", challenge.TenantID, expected.TenantID},
		{"workspace_id", challenge.WorkspaceID, expected.WorkspaceID}, {"audience", challenge.Audience, expected.Audience},
		{"generated_spec_id", challenge.GeneratedSpecID, expected.GeneratedSpecID}, {"generated_spec_hash", challenge.GeneratedSpecHash, expected.GeneratedSpecHash},
		{"execution_plan_hash", challenge.ExecutionPlanHash, expected.ExecutionPlanHash}, {"plan_transaction_hash", challenge.PlanTransactionHash, expected.PlanTransactionHash},
		{"write_set_hash", challenge.WriteSetHash, expected.WriteSetHash}, {"verification_scope_hash", challenge.VerificationScopeHash, expected.VerificationScopeHash},
		{"policy_envelope_hash", challenge.PolicyEnvelopeHash, expected.PolicyEnvelopeHash}, {"policy_version", challenge.PolicyVersion, expected.PolicyVersion},
		{"policy_epoch", challenge.PolicyEpoch, expected.PolicyEpoch}, {"action", challenge.Action, expected.Action},
		{"requesting_principal_id", challenge.RequestingPrincipalID, expected.RequestingPrincipalID}, {"authority_source", challenge.AuthoritySource, expected.AuthoritySource},
		{"authority_version", challenge.AuthorityVersion, expected.AuthorityVersion}, {"authority_snapshot_hash", challenge.AuthoritySnapshotHash, expected.AuthoritySnapshotHash},
		{"required_role", challenge.RequiredRole, expected.RequiredRole}, {"server_identity", challenge.ServerIdentity, expected.ServerIdentity},
	}
	for _, item := range actual {
		if item.actual != item.expected {
			return verificationFailed(item.field + " binding mismatch")
		}
	}
	if challenge.Quorum != expected.Quorum {
		return verificationFailed("quorum binding mismatch")
	}
	return nil
}

func validateTrustStore(store approvalverify.TrustStore, challenge contracts.GeneratedSpecApprovalChallenge) error {
	if store.AuthoritySource != challenge.AuthoritySource || store.AuthorityVersion != challenge.AuthorityVersion || store.AuthoritySnapshotHash != challenge.AuthoritySnapshotHash || len(store.Keys) == 0 {
		return authorityRejected("authority snapshot mismatch or empty")
	}
	return nil
}

func validateTrustedKey(key approvalverify.TrustedApproverKey, assertionKeyID string, challenge contracts.GeneratedSpecApprovalChallenge, now time.Time) error {
	if !key.Enabled || key.KeyID == "" || key.KeyID != assertionKeyID || key.TenantID == "" || key.TenantID != challenge.TenantID {
		return authorityRejected("key identity is invalid")
	}
	if !contains(key.WorkspaceIDs, challenge.WorkspaceID) || !validToken(key.PrincipalID) || !validToken(key.CredentialID) || !validToken(key.DeviceID) || len(key.PublicKey) != ed25519.PublicKeySize {
		return authorityRejected("key scope or authority identity is invalid")
	}
	if key.NotBefore.IsZero() || key.NotAfter.IsZero() || !key.NotAfter.After(key.NotBefore) || now.Before(key.NotBefore) || !now.Before(key.NotAfter) {
		return authorityRejected("key is outside its validity window")
	}
	if !contains(key.Roles, challenge.RequiredRole) || !contains(key.Actions, challenge.Action) || !contains(key.Audiences, challenge.Audience) {
		return authorityRejected("key lacks required role, action, or audience")
	}
	return nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func validToken(value string) bool {
	return value != "" && strings.IndexFunc(value, unicode.IsSpace) == -1
}

func verificationFailed(message string) error {
	return fmt.Errorf("%w: %s", ErrVerificationFailed, message)
}
func authorityRejected(message string) error {
	return fmt.Errorf("%w: %s", ErrAuthorityRejected, message)
}
func duplicateSigner(field, value string) error {
	return fmt.Errorf("%w: duplicate %s %s", ErrDuplicateSigner, field, value)
}

func verifiedApprovalIntegrityHash(verified VerifiedApprovalRef) (string, error) {
	hash, err := canonicalize.CanonicalHash(struct {
		Domain                string                          `json:"domain"`
		ApprovalID            string                          `json:"approval_id"`
		ChallengeID           string                          `json:"challenge_id"`
		ChallengeHash         string                          `json:"challenge_hash"`
		TenantID              string                          `json:"tenant_id"`
		WorkspaceID           string                          `json:"workspace_id"`
		Audience              string                          `json:"audience"`
		GeneratedSpecID       string                          `json:"generated_spec_id"`
		GeneratedSpecHash     string                          `json:"generated_spec_hash"`
		ExecutionPlanHash     string                          `json:"execution_plan_hash"`
		PlanTransactionHash   string                          `json:"plan_transaction_hash"`
		WriteSetHash          string                          `json:"write_set_hash"`
		VerificationScopeHash string                          `json:"verification_scope_hash"`
		PolicyEnvelopeHash    string                          `json:"policy_envelope_hash"`
		PolicyVersion         string                          `json:"policy_version"`
		PolicyEpoch           string                          `json:"policy_epoch"`
		Action                string                          `json:"action"`
		RequestingPrincipalID string                          `json:"requesting_principal_id"`
		AuthoritySource       string                          `json:"authority_source"`
		AuthorityVersion      string                          `json:"authority_version"`
		AuthoritySnapshotHash string                          `json:"authority_snapshot_hash"`
		RequiredRole          string                          `json:"required_role"`
		Quorum                int                             `json:"quorum"`
		ServerIdentity        string                          `json:"server_identity"`
		Signers               []approvalverify.VerifiedSigner `json:"signers"`
		SignerSetHash         string                          `json:"signer_set_hash"`
		VerifiedAt            time.Time                       `json:"verified_at"`
	}{
		Domain: "HELM/GeneratedSpecVerifiedApproval/v1", ApprovalID: verified.ApprovalID,
		ChallengeID: verified.ChallengeID, ChallengeHash: verified.ChallengeHash,
		TenantID: verified.TenantID, WorkspaceID: verified.WorkspaceID, Audience: verified.Audience,
		GeneratedSpecID: verified.GeneratedSpecID, GeneratedSpecHash: verified.GeneratedSpecHash,
		ExecutionPlanHash: verified.ExecutionPlanHash, PlanTransactionHash: verified.PlanTransactionHash,
		WriteSetHash: verified.WriteSetHash, VerificationScopeHash: verified.VerificationScopeHash,
		PolicyEnvelopeHash: verified.PolicyEnvelopeHash, PolicyVersion: verified.PolicyVersion,
		PolicyEpoch: verified.PolicyEpoch, Action: verified.Action, RequestingPrincipalID: verified.RequestingPrincipalID,
		AuthoritySource: verified.AuthoritySource, AuthorityVersion: verified.AuthorityVersion,
		AuthoritySnapshotHash: verified.AuthoritySnapshotHash, RequiredRole: verified.RequiredRole,
		Quorum: verified.Quorum, ServerIdentity: verified.ServerIdentity, Signers: verified.Signers,
		SignerSetHash: verified.SignerSetHash, VerifiedAt: verified.VerifiedAt,
	})
	if err != nil {
		return "", err
	}
	return "sha256:" + hash, nil
}
