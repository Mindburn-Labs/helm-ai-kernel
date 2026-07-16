// quantum_posture: approval quorum verification uses classical Ed25519
// assertions; this package does not claim hybrid or post-quantum support.
// Package approvalverify verifies cryptographic human assertions over a
// server-issued approval challenge. It is a pure verification layer: it does
// not persist challenges, consume replay state, issue effect permits, or
// authorize mutations.
package approvalverify

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var (
	ErrVerificationFailed = errors.New("approval assertion verification failed")
	ErrAuthorityRejected  = errors.New("approval assertion authority rejected")
	ErrSignatureRejected  = errors.New("approval assertion signature rejected")
	ErrDuplicateSigner    = errors.New("approval assertion duplicate signer")
	ErrQuorumNotMet       = errors.New("approval assertion quorum not met")
)

// TrustedApproverKey is an authority-registry snapshot. Tenant, principal,
// credential, device, workspace, role, and action authority come from this
// record, never from the submitted assertion.
type TrustedApproverKey struct {
	KeyID        string
	TenantID     string
	PrincipalID  string
	CredentialID string
	DeviceID     string
	PublicKey    ed25519.PublicKey
	WorkspaceIDs []string
	Roles        []string
	Actions      []string
	Audiences    []string
	Enabled      bool
	NotBefore    time.Time
	NotAfter     time.Time
}

// TrustStore carries a pinned authority-registry snapshot. Its metadata and
// keys MUST be loaded and snapshot-validated by the owning server-side
// registry. VerifyQuorum exact-binds that metadata but does not rederive a
// registry-specific snapshot hash from this generic projection.
type TrustStore struct {
	AuthoritySource       string
	AuthorityVersion      string
	AuthoritySnapshotHash string
	Keys                  map[string]TrustedApproverKey
}

// ExpectedBinding is the caller's exact, policy-owned effect context. A route
// must build it independently of the submitted assertion and challenge body.
type ExpectedBinding struct {
	ChallengeID           string
	ChallengeHash         string
	ApprovalID            string
	TenantID              string
	WorkspaceID           string
	Audience              string
	PackID                string
	PackVersion           string
	PackManifestHash      string
	Action                string
	IntentHash            string
	EffectHash            string
	PlanHash              string
	Decision              string
	PolicyVersion         string
	PolicyEpoch           string
	PolicyHash            string
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

// VerifiedSigner is verifier-derived evidence. It intentionally excludes the
// public key and cannot be used to authorize a later effect by itself.
type VerifiedSigner struct {
	PrincipalID   string `json:"principal_id"`
	CredentialID  string `json:"credential_id"`
	DeviceID      string `json:"device_id"`
	KeyID         string `json:"key_id"`
	Role          string `json:"role"`
	AssertionHash string `json:"assertion_hash"`
}

// VerifiedApprovalRef is a deterministic quorum projection suitable as input
// to a later durable ceremony commitment. It provides ApprovalID and
// SignerSetHash, but it is not an ApprovalGrant and it does not provide the
// ApprovalGrant.CeremonyHash. The owning ceremony MUST durably commit and hash
// the complete record before the Kernel issues a signed, single-use effect
// permit.
type VerifiedApprovalRef struct {
	ApprovalID            string           `json:"approval_id"`
	ChallengeID           string           `json:"challenge_id"`
	ChallengeHash         string           `json:"challenge_hash"`
	TenantID              string           `json:"tenant_id"`
	WorkspaceID           string           `json:"workspace_id"`
	Audience              string           `json:"audience"`
	PackID                string           `json:"pack_id"`
	PackVersion           string           `json:"pack_version"`
	PackManifestHash      string           `json:"pack_manifest_hash"`
	Action                string           `json:"action"`
	IntentHash            string           `json:"intent_hash"`
	EffectHash            string           `json:"effect_hash"`
	PlanHash              string           `json:"plan_hash"`
	Decision              string           `json:"decision"`
	PolicyVersion         string           `json:"policy_version"`
	PolicyEpoch           string           `json:"policy_epoch"`
	PolicyHash            string           `json:"policy_hash"`
	AuthoritySource       string           `json:"authority_source"`
	AuthorityVersion      string           `json:"authority_version"`
	AuthoritySnapshotHash string           `json:"authority_snapshot_hash"`
	ServerIdentity        string           `json:"server_identity"`
	RequiredRole          string           `json:"required_role"`
	Quorum                int              `json:"quorum"`
	Signers               []VerifiedSigner `json:"signers"`
	SignerSetHash         string           `json:"signer_set_hash"`
	VerifiedAt            time.Time        `json:"verified_at"`
}

// VerifyQuorum verifies every supplied assertion and requires distinct
// principal, credential, device, key, and public-key identities. It accepts at
// least Quorum and at most MaxAssertions; every valid supplied signer is
// committed into SignerSetHash. The challenge and authority snapshot MUST be
// loaded from their owning durable stores. This function does not provide
// replay prevention or mutation authority.
func VerifyQuorum(
	challenge contracts.ApprovalChallenge,
	assertions []contracts.ApprovalAssertion,
	store TrustStore,
	opts VerifyOptions,
	now time.Time,
) (VerifiedApprovalRef, error) {
	if err := validateOptions(opts); err != nil {
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
	verified := make([]VerifiedSigner, 0, len(assertions))

	for _, assertion := range assertions {
		if err := assertion.Validate(); err != nil {
			return VerifiedApprovalRef{}, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}
		if assertion.ChallengeID != challenge.ChallengeID || assertion.ChallengeHash != challenge.ChallengeHash {
			return VerifiedApprovalRef{}, verificationFailed("assertion challenge binding mismatch")
		}
		digest, err := assertion.SigningDigest()
		if err != nil {
			return VerifiedApprovalRef{}, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
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

		signature, err := assertion.SignatureBytes()
		if err != nil {
			return VerifiedApprovalRef{}, fmt.Errorf("%w: %w", ErrSignatureRejected, err)
		}
		if !ed25519.Verify(key.PublicKey, digest, signature) {
			return VerifiedApprovalRef{}, fmt.Errorf("%w: bad ed25519 signature for key %s", ErrSignatureRejected, assertion.KeyID)
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
		verified = append(verified, VerifiedSigner{
			PrincipalID:   key.PrincipalID,
			CredentialID:  key.CredentialID,
			DeviceID:      key.DeviceID,
			KeyID:         key.KeyID,
			Role:          challenge.RequiredRole,
			AssertionHash: "sha256:" + assertionHash,
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
		Domain                string           `json:"domain"`
		ChallengeHash         string           `json:"challenge_hash"`
		AuthoritySnapshotHash string           `json:"authority_snapshot_hash"`
		Signers               []VerifiedSigner `json:"signers"`
	}{
		Domain:                "HELM/ApprovalSignerSet/v1",
		ChallengeHash:         challenge.ChallengeHash,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash,
		Signers:               verified,
	})
	if err != nil {
		return VerifiedApprovalRef{}, verificationFailed("signer set canonicalization failed")
	}

	return VerifiedApprovalRef{
		ApprovalID:            challenge.ApprovalID,
		ChallengeID:           challenge.ChallengeID,
		ChallengeHash:         challenge.ChallengeHash,
		TenantID:              challenge.TenantID,
		WorkspaceID:           challenge.WorkspaceID,
		Audience:              challenge.Audience,
		PackID:                challenge.PackID,
		PackVersion:           challenge.PackVersion,
		PackManifestHash:      challenge.PackManifestHash,
		Action:                challenge.Action,
		IntentHash:            challenge.IntentHash,
		EffectHash:            challenge.EffectHash,
		PlanHash:              challenge.PlanHash,
		Decision:              challenge.Decision,
		PolicyVersion:         challenge.PolicyVersion,
		PolicyEpoch:           challenge.PolicyEpoch,
		PolicyHash:            challenge.PolicyHash,
		AuthoritySource:       challenge.AuthoritySource,
		AuthorityVersion:      challenge.AuthorityVersion,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash,
		ServerIdentity:        challenge.ServerIdentity,
		RequiredRole:          challenge.RequiredRole,
		Quorum:                challenge.Quorum,
		Signers:               verified,
		SignerSetHash:         "sha256:" + signerSetHash,
		VerifiedAt:            now.UTC(),
	}, nil
}

func validateOptions(opts VerifyOptions) error {
	if opts.MinHoldDuration <= 0 {
		return verificationFailed("minimum hold duration is required")
	}
	if opts.MaxChallengeTTL <= 0 {
		return verificationFailed("max challenge ttl is required")
	}
	if opts.MaxChallengeTTL <= opts.MinHoldDuration {
		return verificationFailed("max challenge ttl must exceed minimum hold duration")
	}
	if opts.MaxAssertions <= 0 {
		return verificationFailed("maximum assertion count is required")
	}
	if opts.MaxAssertions < opts.Expected.Quorum {
		return verificationFailed("maximum assertion count must cover expected quorum")
	}
	required := []struct {
		field string
		value string
	}{
		{field: "challenge_id", value: opts.Expected.ChallengeID},
		{field: "challenge_hash", value: opts.Expected.ChallengeHash},
		{field: "approval_id", value: opts.Expected.ApprovalID},
		{field: "tenant_id", value: opts.Expected.TenantID},
		{field: "workspace_id", value: opts.Expected.WorkspaceID},
		{field: "audience", value: opts.Expected.Audience},
		{field: "pack_id", value: opts.Expected.PackID},
		{field: "pack_version", value: opts.Expected.PackVersion},
		{field: "pack_manifest_hash", value: opts.Expected.PackManifestHash},
		{field: "action", value: opts.Expected.Action},
		{field: "intent_hash", value: opts.Expected.IntentHash},
		{field: "effect_hash", value: opts.Expected.EffectHash},
		{field: "plan_hash", value: opts.Expected.PlanHash},
		{field: "decision", value: opts.Expected.Decision},
		{field: "policy_version", value: opts.Expected.PolicyVersion},
		{field: "policy_epoch", value: opts.Expected.PolicyEpoch},
		{field: "policy_hash", value: opts.Expected.PolicyHash},
		{field: "authority_source", value: opts.Expected.AuthoritySource},
		{field: "authority_version", value: opts.Expected.AuthorityVersion},
		{field: "authority_snapshot_hash", value: opts.Expected.AuthoritySnapshotHash},
		{field: "required_role", value: opts.Expected.RequiredRole},
		{field: "server_identity", value: opts.Expected.ServerIdentity},
	}
	for _, item := range required {
		if strings.TrimSpace(item.value) == "" {
			return verificationFailed("expected " + item.field + " is required")
		}
	}
	if opts.Expected.Quorum <= 0 {
		return verificationFailed("expected quorum must be positive")
	}
	return nil
}

func verifyExpectedBinding(challenge contracts.ApprovalChallenge, expected ExpectedBinding) error {
	matches := []struct {
		field    string
		actual   string
		expected string
	}{
		{field: "challenge_id", actual: challenge.ChallengeID, expected: expected.ChallengeID},
		{field: "challenge_hash", actual: challenge.ChallengeHash, expected: expected.ChallengeHash},
		{field: "approval_id", actual: challenge.ApprovalID, expected: expected.ApprovalID},
		{field: "tenant_id", actual: challenge.TenantID, expected: expected.TenantID},
		{field: "workspace_id", actual: challenge.WorkspaceID, expected: expected.WorkspaceID},
		{field: "audience", actual: challenge.Audience, expected: expected.Audience},
		{field: "pack_id", actual: challenge.PackID, expected: expected.PackID},
		{field: "pack_version", actual: challenge.PackVersion, expected: expected.PackVersion},
		{field: "pack_manifest_hash", actual: challenge.PackManifestHash, expected: expected.PackManifestHash},
		{field: "action", actual: challenge.Action, expected: expected.Action},
		{field: "intent_hash", actual: challenge.IntentHash, expected: expected.IntentHash},
		{field: "effect_hash", actual: challenge.EffectHash, expected: expected.EffectHash},
		{field: "plan_hash", actual: challenge.PlanHash, expected: expected.PlanHash},
		{field: "decision", actual: challenge.Decision, expected: expected.Decision},
		{field: "policy_version", actual: challenge.PolicyVersion, expected: expected.PolicyVersion},
		{field: "policy_epoch", actual: challenge.PolicyEpoch, expected: expected.PolicyEpoch},
		{field: "policy_hash", actual: challenge.PolicyHash, expected: expected.PolicyHash},
		{field: "authority_source", actual: challenge.AuthoritySource, expected: expected.AuthoritySource},
		{field: "authority_version", actual: challenge.AuthorityVersion, expected: expected.AuthorityVersion},
		{field: "authority_snapshot_hash", actual: challenge.AuthoritySnapshotHash, expected: expected.AuthoritySnapshotHash},
		{field: "required_role", actual: challenge.RequiredRole, expected: expected.RequiredRole},
		{field: "server_identity", actual: challenge.ServerIdentity, expected: expected.ServerIdentity},
	}
	for _, item := range matches {
		if item.actual != item.expected {
			return verificationFailed(item.field + " binding mismatch")
		}
	}
	if challenge.Quorum != expected.Quorum {
		return verificationFailed("quorum binding mismatch")
	}
	return nil
}

func validateTrustStore(store TrustStore, challenge contracts.ApprovalChallenge) error {
	if store.AuthoritySource != challenge.AuthoritySource {
		return authorityRejected("authority source mismatch")
	}
	if store.AuthorityVersion != challenge.AuthorityVersion {
		return authorityRejected("authority version mismatch")
	}
	if store.AuthoritySnapshotHash != challenge.AuthoritySnapshotHash {
		return authorityRejected("authority snapshot mismatch")
	}
	if len(store.Keys) == 0 {
		return authorityRejected("authority snapshot has no keys")
	}
	return nil
}

func validateTrustedKey(key TrustedApproverKey, assertionKeyID string, challenge contracts.ApprovalChallenge, now time.Time) error {
	if !key.Enabled {
		return authorityRejected("key is disabled")
	}
	if !contracts.IsApprovalSignerIdentifier(key.KeyID) || key.KeyID != assertionKeyID {
		return authorityRejected("key identity mismatch")
	}
	if key.TenantID == "" || key.TenantID != challenge.TenantID {
		return authorityRejected("key tenant mismatch")
	}
	if !containsExactAuthority(key.WorkspaceIDs, challenge.WorkspaceID) {
		return authorityRejected("workspace is not authorized")
	}
	if !contracts.IsApprovalSignerIdentifier(key.PrincipalID) ||
		!contracts.IsApprovalSignerIdentifier(key.CredentialID) ||
		!contracts.IsApprovalSignerIdentifier(key.DeviceID) {
		return authorityRejected("key authority identity must use the portable ASCII signer identifier grammar")
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return authorityRejected("invalid ed25519 public key length")
	}
	if key.NotBefore.IsZero() || key.NotAfter.IsZero() || !key.NotAfter.After(key.NotBefore) {
		return authorityRejected("key validity window is invalid")
	}
	if now.Before(key.NotBefore) || !now.Before(key.NotAfter) {
		return authorityRejected("key is outside its validity window")
	}
	if !containsExactAuthority(key.Roles, challenge.RequiredRole) {
		return authorityRejected("required role is not authorized")
	}
	if !containsExactAuthority(key.Actions, challenge.Action) {
		return authorityRejected("pack action is not authorized")
	}
	if !containsExactAuthority(key.Audiences, challenge.Audience) {
		return authorityRejected("audience is not authorized")
	}
	return nil
}

func containsExactAuthority(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
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
