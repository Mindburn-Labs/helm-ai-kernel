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
	if want := "sha256:cbe72fb406de363da696477c4e69dffd930bdeb9603d101a5b389dac98319cd7"; grant.GrantHash != want {
		t.Fatalf("ApprovalGrant.GrantHash = %q, want %q", grant.GrantHash, want)
	}

	challenge, err := validApprovalChallenge().Seal()
	if err != nil {
		t.Fatalf("ApprovalChallenge.Seal() error = %v", err)
	}
	if want := "sha256:aba636bf5caa97e81b2fe77f2fef4a54e6426ee6b1307f958de9f281561b36c4"; challenge.ChallengeHash != want {
		t.Fatalf("ApprovalChallenge.ChallengeHash = %q, want %q", challenge.ChallengeHash, want)
	}

	assertion := validApprovalAssertion(challenge)
	digest, err := assertion.SigningDigest()
	if err != nil {
		t.Fatalf("ApprovalAssertion.SigningDigest() error = %v", err)
	}
	if got, want := hex.EncodeToString(digest), "2ce9f9c03ec4628fd9095f031aa1793a16b35d1bbbba2c50d8bdd29bb147cbbd"; got != want {
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
	if err := sealed.ValidateAt(sealed.IssuedAt); !errors.Is(err, ErrApprovalChallengeIntegrity) {
		t.Fatalf("ValidateAt() tampered error = %v, want ErrApprovalChallengeIntegrity", err)
	}
}

func TestApprovalChallengeRejectsUnsafeTemporalShape(t *testing.T) {
	tests := map[string]func(*ApprovalChallenge){
		"zero hold":              func(c *ApprovalChallenge) { c.EligibleAt = c.HoldStartedAt },
		"issued during hold":     func(c *ApprovalChallenge) { c.IssuedAt = c.EligibleAt.Add(-time.Nanosecond) },
		"expiry equals issuance": func(c *ApprovalChallenge) { c.ExpiresAt = c.IssuedAt },
		"missing nonce":          func(c *ApprovalChallenge) { c.Nonce = "" },
		"non allow decision":     func(c *ApprovalChallenge) { c.Decision = "DENY" },
		"zero quorum":            func(c *ApprovalChallenge) { c.Quorum = 0 },
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
		IntentHash:       sha256Ref("0"),
		EffectHash:       sha256Ref("1"),
		PlanHash:         sha256Ref("2"),
		Decision:         ApprovalGrantDecisionAllow,
		PolicyVersion:    "policy-v1",
		PolicyEpoch:      "epoch-1",
		PolicyHash:       sha256Ref("3"),
		RequiredRole:     "pack-admin",
		Quorum:           2,
		ServerIdentity:   "spiffe://helm/server-a",
		HoldStartedAt:    holdStarted,
		EligibleAt:       eligible,
		IssuedAt:         eligible.Add(time.Minute),
		ExpiresAt:        eligible.Add(10 * time.Minute),
		Nonce:            repeatHex("6"),
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
