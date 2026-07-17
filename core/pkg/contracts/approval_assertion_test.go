// quantum_posture: these vectors cover classical Ed25519 approval assertions;
// they do not establish hybrid or post-quantum approval support.
package contracts

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestApprovalGrantAndAssertionGoldenVectors(t *testing.T) {
	grant, err := validApprovalGrant().Seal()
	if err != nil {
		t.Fatalf("ApprovalGrant.Seal() error = %v", err)
	}
	if want := "sha256:b9f38f37e3ca5231b549b0ffe2e0a59e8ede6f11cedcab1402f7098ce7241832"; grant.GrantHash != want {
		t.Fatalf("ApprovalGrant.GrantHash = %q, want %q", grant.GrantHash, want)
	}

	challenge, err := validApprovalChallenge().Seal()
	if err != nil {
		t.Fatalf("ApprovalChallenge.Seal() error = %v", err)
	}
	if want := "sha256:98060a276357d51c0d6661cf2c795f2d99bf84f365ee439d875dd4379ed4bd60"; challenge.ChallengeHash != want {
		t.Fatalf("ApprovalChallenge.ChallengeHash = %q, want %q", challenge.ChallengeHash, want)
	}

	assertion := validApprovalAssertion(challenge)
	digest, err := assertion.SigningDigest()
	if err != nil {
		t.Fatalf("ApprovalAssertion.SigningDigest() error = %v", err)
	}
	if got, want := hex.EncodeToString(digest), "abcebc7fe1dd96040a5a6533f3d38584e7794235d79db0722e3da5f4ba294a8d"; got != want {
		t.Fatalf("ApprovalAssertion signing digest = %q, want %q", got, want)
	}
}

func TestApprovalChallengeSealIsDeterministicAndBindsFields(t *testing.T) {
	base := validApprovalChallenge()
	sealed, err := base.Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	sealedAgain, err := sealed.Seal()
	if err != nil {
		t.Fatalf("Seal() repeat error = %v", err)
	}
	if sealed.ChallengeHash != sealedAgain.ChallengeHash {
		t.Fatalf("Seal() is not deterministic: %s != %s", sealed.ChallengeHash, sealedAgain.ChallengeHash)
	}

	mutations := map[string]func(*ApprovalChallenge){
		"tenant":       func(c *ApprovalChallenge) { c.TenantID = "tenant-b" },
		"pack":         func(c *ApprovalChallenge) { c.PackID = "pack-b" },
		"effect":       func(c *ApprovalChallenge) { c.EffectHash = sha256Ref("9") },
		"policy":       func(c *ApprovalChallenge) { c.PolicyHash = sha256Ref("8") },
		"authority":    func(c *ApprovalChallenge) { c.AuthoritySnapshotHash = sha256Ref("7") },
		"role":         func(c *ApprovalChallenge) { c.RequiredRole = "security-admin" },
		"quorum":       func(c *ApprovalChallenge) { c.Quorum = 3 },
		"issued at":    func(c *ApprovalChallenge) { c.IssuedAt = c.IssuedAt.Add(time.Second) },
		"expires at":   func(c *ApprovalChallenge) { c.ExpiresAt = c.ExpiresAt.Add(time.Second) },
		"server":       func(c *ApprovalChallenge) { c.ServerIdentity = "spiffe://helm/server-b" },
		"fresh nonce":  func(c *ApprovalChallenge) { c.Nonce = repeatHex("7") },
		"challenge id": func(c *ApprovalChallenge) { c.ChallengeID = "challenge-b" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			candidate.ConnectorAuthority = approvalConnectorAuthorityFor(
				candidate.TenantID, candidate.WorkspaceID, candidate.PackID, candidate.PackVersion,
				candidate.PackManifestHash, candidate.Action, candidate.EffectHash, candidate.PolicyHash,
			)
			changed, err := candidate.Seal()
			if err != nil {
				t.Fatalf("Seal() mutated error = %v", err)
			}
			if changed.ChallengeHash == sealed.ChallengeHash {
				t.Fatalf("mutation did not change challenge hash %s", sealed.ChallengeHash)
			}
		})
	}
}

func TestApprovalChallengeValidateAtChecksIssuanceIntegrityAndWindow(t *testing.T) {
	challenge := validApprovalChallenge()
	if err := challenge.ValidateAt(challenge.IssuedAt); !errors.Is(err, ErrApprovalChallengeIntegrity) {
		t.Fatalf("ValidateAt() unsealed error = %v, want ErrApprovalChallengeIntegrity", err)
	}

	sealed, err := challenge.Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if err := sealed.ValidateAt(sealed.IssuedAt); err != nil {
		t.Fatalf("ValidateAt() issued_at error = %v", err)
	}
	if err := sealed.ValidateAt(sealed.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("ValidateAt() before expiry error = %v", err)
	}
	if err := sealed.ValidateAt(sealed.EligibleAt.Add(-time.Nanosecond)); !errors.Is(err, ErrApprovalChallengeInactive) {
		t.Fatalf("ValidateAt() before eligibility error = %v, want ErrApprovalChallengeInactive", err)
	}
	if err := sealed.ValidateAt(sealed.IssuedAt.Add(-time.Nanosecond)); !errors.Is(err, ErrApprovalChallengeInactive) {
		t.Fatalf("ValidateAt() before issuance error = %v, want ErrApprovalChallengeInactive", err)
	}
	if err := sealed.ValidateAt(sealed.ExpiresAt); !errors.Is(err, ErrApprovalChallengeInactive) {
		t.Fatalf("ValidateAt() at expiry error = %v, want ErrApprovalChallengeInactive", err)
	}

	sealed.EffectHash = sha256Ref("9")
	if err := sealed.ValidateAt(sealed.IssuedAt); !errors.Is(err, ErrApprovalChallengeInvalid) {
		t.Fatalf("ValidateAt() tampered error = %v, want ErrApprovalChallengeInvalid", err)
	}
}

func TestApprovalChallengeRejectsUnsafeTemporalShape(t *testing.T) {
	tests := map[string]func(*ApprovalChallenge){
		"zero hold":                 func(c *ApprovalChallenge) { c.EligibleAt = c.HoldStartedAt },
		"issued during hold":        func(c *ApprovalChallenge) { c.IssuedAt = c.EligibleAt.Add(-time.Nanosecond) },
		"expiry equals issuance":    func(c *ApprovalChallenge) { c.ExpiresAt = c.IssuedAt },
		"missing nonce":             func(c *ApprovalChallenge) { c.Nonce = "" },
		"missing authority source":  func(c *ApprovalChallenge) { c.AuthoritySource = "" },
		"missing authority version": func(c *ApprovalChallenge) { c.AuthorityVersion = "" },
		"malformed authority hash":  func(c *ApprovalChallenge) { c.AuthoritySnapshotHash = "sha256:abc" },
		"non allow decision":        func(c *ApprovalChallenge) { c.Decision = "DENY" },
		"zero quorum":               func(c *ApprovalChallenge) { c.Quorum = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			challenge := validApprovalChallenge()
			mutate(&challenge)
			if err := challenge.Validate(); !errors.Is(err, ErrApprovalChallengeInvalid) {
				t.Fatalf("Validate() error = %v, want ErrApprovalChallengeInvalid", err)
			}
		})
	}
}

func TestApprovalContractsRejectNonUTCTimestamps(t *testing.T) {
	nonUTC := time.FixedZone("UTC+2", 2*60*60)

	challenge := validApprovalChallenge()
	challenge.IssuedAt = challenge.IssuedAt.In(nonUTC)
	if err := challenge.Validate(); !errors.Is(err, ErrApprovalChallengeInvalid) {
		t.Fatalf("ApprovalChallenge.Validate() error = %v, want ErrApprovalChallengeInvalid", err)
	}

	grant := validApprovalGrant()
	grant.IssuedAt = grant.IssuedAt.In(nonUTC)
	if err := grant.Validate(); !errors.Is(err, ErrApprovalGrantInvalid) {
		t.Fatalf("ApprovalGrant.Validate() error = %v, want ErrApprovalGrantInvalid", err)
	}
}

func TestApprovalAssertionSigningDigestBindsEnvelope(t *testing.T) {
	challenge, err := validApprovalChallenge().Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	base := validApprovalAssertion(challenge)
	digest, err := base.SigningDigest()
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}

	mutations := map[string]func(*ApprovalAssertion){
		"challenge id":   func(a *ApprovalAssertion) { a.ChallengeID = "challenge-b" },
		"challenge hash": func(a *ApprovalAssertion) { a.ChallengeHash = sha256Ref("9") },
		"key id":         func(a *ApprovalAssertion) { a.KeyID = "approver-key-b" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			changed, err := candidate.SigningDigest()
			if err != nil {
				t.Fatalf("SigningDigest() mutated error = %v", err)
			}
			if string(changed) == string(digest) {
				t.Fatal("signing-envelope mutation did not change digest")
			}
		})
	}

	changedSignature := base
	changedSignature.Signature = "ed25519:" + strings.Repeat("1", 128)
	unchanged, err := changedSignature.SigningDigest()
	if err != nil {
		t.Fatalf("SigningDigest() signature change error = %v", err)
	}
	if string(unchanged) != string(digest) {
		t.Fatal("signature must be excluded from its own digest")
	}
}

func TestApprovalAssertionRejectsMalformedEnvelopeOrSignature(t *testing.T) {
	challenge, err := validApprovalChallenge().Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	tests := map[string]func(*ApprovalAssertion){
		"wrong domain":      func(a *ApprovalAssertion) { a.Domain = "HELM/ApprovalAssertion/v2" },
		"unknown algorithm": func(a *ApprovalAssertion) { a.Algorithm = "rsa" },
		"missing key":       func(a *ApprovalAssertion) { a.KeyID = "" },
		"short signature":   func(a *ApprovalAssertion) { a.Signature = "ed25519:ab" },
		"uppercase signature": func(a *ApprovalAssertion) {
			a.Signature = "ed25519:" + strings.Repeat("A", 128)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			assertion := validApprovalAssertion(challenge)
			mutate(&assertion)
			if err := assertion.Validate(); !errors.Is(err, ErrApprovalAssertionInvalid) {
				t.Fatalf("Validate() error = %v, want ErrApprovalAssertionInvalid", err)
			}
		})
	}
}

func validApprovalChallenge() ApprovalChallenge {
	holdStarted := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	eligible := holdStarted.Add(5 * time.Minute)
	return ApprovalChallenge{
		Domain:           ApprovalChallengeDomainV1,
		SchemaVersion:    ApprovalChallengeSchemaV1,
		ContractVersion:  ApprovalChallengeContractV1,
		ChallengeID:      "challenge-a",
		ApprovalID:       "approval-a",
		TenantID:         "tenant-a",
		WorkspaceID:      "workspace-a",
		Audience:         "packs.lifecycle",
		PackID:           "pack-a",
		PackVersion:      "1.0.0",
		PackManifestHash: sha256Ref("a"),
		Action:           ApprovalGrantActionInstall,
		ConnectorAuthority: approvalConnectorAuthorityFor(
			"tenant-a", "workspace-a", "pack-a", "1.0.0", sha256Ref("a"),
			ApprovalGrantActionInstall, sha256Ref("1"), sha256Ref("3"),
		),
		IntentHash:            sha256Ref("0"),
		EffectHash:            sha256Ref("1"),
		PlanHash:              sha256Ref("2"),
		Decision:              ApprovalGrantDecisionAllow,
		PolicyVersion:         "policy-v1",
		PolicyEpoch:           "epoch-1",
		PolicyHash:            sha256Ref("3"),
		AuthoritySource:       "spiffe://helm/authority/approvers",
		AuthorityVersion:      "authority-v1",
		AuthoritySnapshotHash: sha256Ref("4"),
		RequiredRole:          "pack-admin",
		Quorum:                2,
		ServerIdentity:        "spiffe://helm/server-a",
		HoldStartedAt:         holdStarted,
		EligibleAt:            eligible,
		IssuedAt:              eligible.Add(time.Minute),
		ExpiresAt:             eligible.Add(10 * time.Minute),
		Nonce:                 repeatHex("6"),
	}
}

func validApprovalAssertion(challenge ApprovalChallenge) ApprovalAssertion {
	return ApprovalAssertion{
		Domain:          ApprovalAssertionDomainV1,
		SchemaVersion:   ApprovalAssertionSchemaV1,
		ContractVersion: ApprovalAssertionContractV1,
		ChallengeID:     challenge.ChallengeID,
		ChallengeHash:   challenge.ChallengeHash,
		KeyID:           "approver-key-a",
		Algorithm:       ApprovalAssertionEd25519,
		Signature:       "ed25519:" + strings.Repeat("0", 128),
	}
}
