// quantum_posture: these tests cover classical Ed25519 approval assertions;
// they do not establish hybrid or post-quantum approval support.
package approvalverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestVerifyQuorumAcceptsDistinctTrustedSignersDeterministically(t *testing.T) {
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	assertions := []contracts.ApprovalAssertion{
		signedAssertion(t, challenge, "key-b", privateKeys["key-b"]),
		signedAssertion(t, challenge, "key-a", privateKeys["key-a"]),
	}
	now := challenge.IssuedAt.Add(time.Minute)

	got, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), now)
	if err != nil {
		t.Fatalf("VerifyQuorum() error = %v", err)
	}
	if gotBinding := bindingFromProjection(got); gotBinding != optionsFor(challenge).Expected {
		t.Fatalf("VerifyQuorum() projection binding = %+v, want %+v", gotBinding, optionsFor(challenge).Expected)
	}
	if got.VerifiedAt != now.UTC() {
		t.Fatalf("VerifiedAt = %s, want %s", got.VerifiedAt, now.UTC())
	}
	if len(got.Signers) != 2 || got.Signers[0].PrincipalID != "principal-a" || got.Signers[1].PrincipalID != "principal-b" {
		t.Fatalf("Signers are not canonically sorted: %+v", got.Signers)
	}
	if want := "sha256:0a4333fe9e92aa61edb9e478630da19b2f43f8da2e8695d89aecd0d303ef8365"; got.SignerSetHash != want {
		t.Fatalf("SignerSetHash = %q, want %q", got.SignerSetHash, want)
	}

	reversed, err := VerifyQuorum(challenge, []contracts.ApprovalAssertion{assertions[1], assertions[0]}, store, optionsFor(challenge), now)
	if err != nil {
		t.Fatalf("VerifyQuorum() reversed error = %v", err)
	}
	if reversed.SignerSetHash != got.SignerSetHash {
		t.Fatalf("SignerSetHash depends on assertion order: %s != %s", reversed.SignerSetHash, got.SignerSetHash)
	}
}

func TestVerifyQuorumRejectsExpectedBindingSubstitution(t *testing.T) {
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	assertions := signedQuorum(t, challenge, privateKeys)
	mutations := map[string]func(*testing.T, *ExpectedBinding){
		"challenge id":   func(_ *testing.T, e *ExpectedBinding) { e.ChallengeID = "challenge-b" },
		"challenge hash": func(_ *testing.T, e *ExpectedBinding) { e.ChallengeHash = shaRef("9") },
		"approval":       func(_ *testing.T, e *ExpectedBinding) { e.ApprovalID = "approval-b" },
		"tenant":         func(_ *testing.T, e *ExpectedBinding) { e.TenantID = "tenant-b" },
		"workspace":      func(_ *testing.T, e *ExpectedBinding) { e.WorkspaceID = "workspace-b" },
		"audience":       func(_ *testing.T, e *ExpectedBinding) { e.Audience = "packs.other" },
		"pack":           func(_ *testing.T, e *ExpectedBinding) { e.PackID = "pack-b" },
		"pack version":   func(_ *testing.T, e *ExpectedBinding) { e.PackVersion = "2.0.0" },
		"manifest":       func(_ *testing.T, e *ExpectedBinding) { e.PackManifestHash = shaRef("8") },
		"action":         func(_ *testing.T, e *ExpectedBinding) { e.Action = contracts.ApprovalGrantActionRollback },
		"connector authority": func(t *testing.T, e *ExpectedBinding) {
			authority := e.ConnectorAuthority
			authority.ConnectorID = "connector-b"
			authority.AuthorityHash = ""
			sealed, err := authority.Seal()
			if err != nil {
				t.Fatalf("seal substituted connector authority: %v", err)
			}
			e.ConnectorAuthority = sealed
		},
		"intent":             func(_ *testing.T, e *ExpectedBinding) { e.IntentHash = shaRef("7") },
		"effect":             func(_ *testing.T, e *ExpectedBinding) { e.EffectHash = shaRef("6") },
		"plan":               func(_ *testing.T, e *ExpectedBinding) { e.PlanHash = shaRef("5") },
		"policy":             func(_ *testing.T, e *ExpectedBinding) { e.PolicyHash = shaRef("4") },
		"decision":           func(_ *testing.T, e *ExpectedBinding) { e.Decision = "DENY" },
		"policy version":     func(_ *testing.T, e *ExpectedBinding) { e.PolicyVersion = "policy-v2" },
		"policy epoch":       func(_ *testing.T, e *ExpectedBinding) { e.PolicyEpoch = "epoch-2" },
		"authority source":   func(_ *testing.T, e *ExpectedBinding) { e.AuthoritySource = "spiffe://helm/authority/other" },
		"authority version":  func(_ *testing.T, e *ExpectedBinding) { e.AuthorityVersion = "authority-v2" },
		"authority snapshot": func(_ *testing.T, e *ExpectedBinding) { e.AuthoritySnapshotHash = shaRef("b") },
		"role":               func(_ *testing.T, e *ExpectedBinding) { e.RequiredRole = "security-admin" },
		"quorum":             func(_ *testing.T, e *ExpectedBinding) { e.Quorum = 3 },
		"server":             func(_ *testing.T, e *ExpectedBinding) { e.ServerIdentity = "spiffe://helm/server-b" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			opts := optionsFor(challenge)
			mutate(t, &opts.Expected)
			if _, err := VerifyQuorum(challenge, assertions, store, opts, challenge.IssuedAt); !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("VerifyQuorum() error = %v, want ErrVerificationFailed", err)
			}
		})
	}
}

func TestVerifyQuorumRejectsAssertionChallengeSubstitution(t *testing.T) {
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	base := signedQuorum(t, challenge, privateKeys)
	tests := map[string]func(*contracts.ApprovalAssertion){
		"challenge id":   func(a *contracts.ApprovalAssertion) { a.ChallengeID = "challenge-b" },
		"challenge hash": func(a *contracts.ApprovalAssertion) { a.ChallengeHash = shaRef("9") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			assertions := append([]contracts.ApprovalAssertion(nil), base...)
			mutate(&assertions[0])
			if _, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), challenge.IssuedAt); !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("VerifyQuorum() error = %v, want ErrVerificationFailed", err)
			}
		})
	}
}

func TestVerifyQuorumRejectsInactiveOrPolicyUnsafeChallenge(t *testing.T) {
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	assertions := signedQuorum(t, challenge, privateKeys)

	tests := map[string]struct {
		now    time.Time
		mutate func(*VerifyOptions)
	}{
		"before eligible": {now: challenge.EligibleAt.Add(-time.Nanosecond)},
		"before issuance": {now: challenge.IssuedAt.Add(-time.Nanosecond)},
		"at expiry":       {now: challenge.ExpiresAt},
		"hold too short": {
			now: challenge.IssuedAt,
			mutate: func(o *VerifyOptions) {
				o.MinHoldDuration = challenge.EligibleAt.Sub(challenge.HoldStartedAt) + time.Second
			},
		},
		"ttl too long": {
			now: challenge.IssuedAt,
			mutate: func(o *VerifyOptions) {
				o.MaxChallengeTTL = challenge.ExpiresAt.Sub(challenge.HoldStartedAt) - time.Second
			},
		},
		"missing hold policy": {
			now: challenge.IssuedAt,
			mutate: func(o *VerifyOptions) {
				o.MinHoldDuration = 0
			},
		},
		"ttl does not exceed hold": {
			now: challenge.IssuedAt,
			mutate: func(o *VerifyOptions) {
				o.MaxChallengeTTL = o.MinHoldDuration
			},
		},
		"missing assertion cap": {
			now: challenge.IssuedAt,
			mutate: func(o *VerifyOptions) {
				o.MaxAssertions = 0
			},
		},
		"cap below quorum": {
			now: challenge.IssuedAt,
			mutate: func(o *VerifyOptions) {
				o.MaxAssertions = challenge.Quorum - 1
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			opts := optionsFor(challenge)
			if test.mutate != nil {
				test.mutate(&opts)
			}
			if _, err := VerifyQuorum(challenge, assertions, store, opts, test.now); !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("VerifyQuorum() error = %v, want ErrVerificationFailed", err)
			}
		})
	}
}

func TestVerifyQuorumRejectsUntrustedAuthority(t *testing.T) {
	challenge := sealedChallenge(t)
	baseStore, privateKeys := trustedStore(challenge)
	baseAssertions := signedQuorum(t, challenge, privateKeys)
	now := challenge.IssuedAt

	tests := map[string]func(*TrustStore, *[]contracts.ApprovalAssertion){
		"unknown key": func(_ *TrustStore, assertions *[]contracts.ApprovalAssertion) {
			(*assertions)[0].KeyID = "unknown-key"
		},
		"disabled": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.Enabled = false
			store.Keys["key-a"] = key
		},
		"cross tenant": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.TenantID = "tenant-b"
			store.Keys["key-a"] = key
		},
		"cross workspace": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.WorkspaceIDs = []string{"workspace-b"}
			store.Keys["key-a"] = key
		},
		"wildcard role": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.Roles = []string{"*"}
			store.Keys["key-a"] = key
		},
		"wildcard audience": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.Audiences = []string{"*"}
			store.Keys["key-a"] = key
		},
		"wrong audience": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.Audiences = []string{"packs.other"}
			store.Keys["key-a"] = key
		},
		"wrong action": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.Actions = []string{contracts.ApprovalGrantActionUninstall}
			store.Keys["key-a"] = key
		},
		"expired key": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.NotAfter = now
			store.Keys["key-a"] = key
		},
		"future key": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.NotBefore = now.Add(time.Second)
			store.Keys["key-a"] = key
		},
		"registry key mismatch": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.KeyID = "key-other"
			store.Keys["key-a"] = key
		},
		"malformed public key": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.PublicKey = ed25519.PublicKey{1}
			store.Keys["key-a"] = key
		},
		"invalid key window": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.NotAfter = key.NotBefore
			store.Keys["key-a"] = key
		},
		"incomplete identity": func(store *TrustStore, _ *[]contracts.ApprovalAssertion) {
			key := store.Keys["key-a"]
			key.DeviceID = "device a"
			store.Keys["key-a"] = key
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := cloneStore(baseStore)
			assertions := append([]contracts.ApprovalAssertion(nil), baseAssertions...)
			mutate(&store, &assertions)
			if _, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), now); !errors.Is(err, ErrAuthorityRejected) {
				t.Fatalf("VerifyQuorum() error = %v, want ErrAuthorityRejected", err)
			}
		})
	}
}

func TestVerifyQuorumRejectsAuthoritySnapshotSubstitution(t *testing.T) {
	challenge := sealedChallenge(t)
	baseStore, privateKeys := trustedStore(challenge)
	assertions := signedQuorum(t, challenge, privateKeys)
	tests := map[string]func(*TrustStore){
		"source":   func(s *TrustStore) { s.AuthoritySource = "spiffe://helm/authority/other" },
		"version":  func(s *TrustStore) { s.AuthorityVersion = "authority-v2" },
		"snapshot": func(s *TrustStore) { s.AuthoritySnapshotHash = shaRef("b") },
		"empty":    func(s *TrustStore) { s.Keys = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := cloneStore(baseStore)
			mutate(&store)
			if _, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), challenge.IssuedAt); !errors.Is(err, ErrAuthorityRejected) {
				t.Fatalf("VerifyQuorum() error = %v, want ErrAuthorityRejected", err)
			}
		})
	}
}

func TestVerifyQuorumRejectsBadOrMalleableSignature(t *testing.T) {
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	assertions := signedQuorum(t, challenge, privateKeys)
	corruptSignature(&assertions[0])
	if _, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), challenge.IssuedAt); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("VerifyQuorum() bad signature error = %v, want ErrSignatureRejected", err)
	}

	store.Keys["key-alias"] = store.Keys["key-a"]
	alias := store.Keys["key-alias"]
	alias.KeyID = "key-alias"
	alias.PrincipalID = "principal-alias"
	alias.CredentialID = "credential-alias"
	alias.DeviceID = "device-alias"
	store.Keys["key-alias"] = alias
	assertions = signedQuorum(t, challenge, privateKeys)
	assertions[0].KeyID = "key-alias"
	if _, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), challenge.IssuedAt); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("VerifyQuorum() key-id substitution error = %v, want ErrSignatureRejected", err)
	}
}

func TestVerifyQuorumRejectsDuplicateSignerDimensions(t *testing.T) {
	challenge := sealedChallenge(t)
	baseStore, privateKeys := trustedStore(challenge)
	baseAssertions := signedQuorum(t, challenge, privateKeys)
	tests := map[string]func(*TrustedApproverKey, *contracts.ApprovalAssertion){
		"key": func(_ *TrustedApproverKey, assertion *contracts.ApprovalAssertion) {
			*assertion = baseAssertions[0]
		},
		"principal":  func(k *TrustedApproverKey, _ *contracts.ApprovalAssertion) { k.PrincipalID = "principal-a" },
		"credential": func(k *TrustedApproverKey, _ *contracts.ApprovalAssertion) { k.CredentialID = "credential-a" },
		"device":     func(k *TrustedApproverKey, _ *contracts.ApprovalAssertion) { k.DeviceID = "device-a" },
		"public key": func(k *TrustedApproverKey, assertion *contracts.ApprovalAssertion) {
			k.PublicKey = baseStore.Keys["key-a"].PublicKey
			*assertion = signedAssertion(t, challenge, "key-b", privateKeys["key-a"])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := cloneStore(baseStore)
			assertions := append([]contracts.ApprovalAssertion(nil), baseAssertions...)
			key := store.Keys["key-b"]
			mutate(&key, &assertions[1])
			store.Keys["key-b"] = key
			if _, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), challenge.IssuedAt); !errors.Is(err, ErrDuplicateSigner) {
				t.Fatalf("VerifyQuorum() error = %v, want ErrDuplicateSigner", err)
			}
		})
	}
}

func TestVerifyQuorumPinsBoundedOverQuorumSemantics(t *testing.T) {
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	privateC := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	privateKeys["key-c"] = privateC
	store.Keys["key-c"] = TrustedApproverKey{
		KeyID:        "key-c",
		TenantID:     challenge.TenantID,
		PrincipalID:  "principal-c",
		CredentialID: "credential-c",
		DeviceID:     "device-c",
		PublicKey:    privateC.Public().(ed25519.PublicKey),
		WorkspaceIDs: []string{challenge.WorkspaceID},
		Roles:        []string{challenge.RequiredRole},
		Actions:      []string{challenge.Action},
		Audiences:    []string{challenge.Audience},
		Enabled:      true,
		NotBefore:    challenge.HoldStartedAt.Add(-time.Hour),
		NotAfter:     challenge.ExpiresAt.Add(time.Hour),
	}
	all := []contracts.ApprovalAssertion{
		signedAssertion(t, challenge, "key-a", privateKeys["key-a"]),
		signedAssertion(t, challenge, "key-b", privateKeys["key-b"]),
		signedAssertion(t, challenge, "key-c", privateKeys["key-c"]),
	}
	permutations := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	opts := optionsFor(challenge)
	opts.MaxAssertions = 3
	var signerSetHash string
	for _, permutation := range permutations {
		assertions := []contracts.ApprovalAssertion{all[permutation[0]], all[permutation[1]], all[permutation[2]]}
		got, err := VerifyQuorum(challenge, assertions, store, opts, challenge.IssuedAt)
		if err != nil {
			t.Fatalf("VerifyQuorum() permutation %v error = %v", permutation, err)
		}
		if len(got.Signers) != 3 {
			t.Fatalf("VerifyQuorum() permutation %v signers = %d, want 3", permutation, len(got.Signers))
		}
		if signerSetHash == "" {
			signerSetHash = got.SignerSetHash
		} else if got.SignerSetHash != signerSetHash {
			t.Fatalf("SignerSetHash depends on over-quorum order: %s != %s", got.SignerSetHash, signerSetHash)
		}
	}

	invalidSurplus := append([]contracts.ApprovalAssertion(nil), all...)
	corruptSignature(&invalidSurplus[2])
	if _, err := VerifyQuorum(challenge, invalidSurplus, store, opts, challenge.IssuedAt); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("VerifyQuorum() invalid surplus error = %v, want ErrSignatureRejected", err)
	}

	opts.MaxAssertions = 2
	if _, err := VerifyQuorum(challenge, all, store, opts, challenge.IssuedAt); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("VerifyQuorum() over cap error = %v, want ErrVerificationFailed", err)
	}
}

func TestVerifyQuorumRejectsInsufficientQuorum(t *testing.T) {
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	one := []contracts.ApprovalAssertion{signedAssertion(t, challenge, "key-a", privateKeys["key-a"])}
	if _, err := VerifyQuorum(challenge, one, store, optionsFor(challenge), challenge.IssuedAt); !errors.Is(err, ErrQuorumNotMet) {
		t.Fatalf("VerifyQuorum() error = %v, want ErrQuorumNotMet", err)
	}
}

func TestVerifyQuorumPreservesContractErrorIdentity(t *testing.T) {
	challenge := sealedChallenge(t)
	store, privateKeys := trustedStore(challenge)
	assertions := signedQuorum(t, challenge, privateKeys)

	_, err := VerifyQuorum(challenge, assertions, store, optionsFor(challenge), challenge.EligibleAt.Add(-time.Nanosecond))
	if !errors.Is(err, ErrVerificationFailed) || !errors.Is(err, contracts.ErrApprovalChallengeInactive) {
		t.Fatalf("VerifyQuorum() challenge error = %v, want verifier and contract identities", err)
	}

	assertions[0].Signature = "ed25519:ab"
	_, err = VerifyQuorum(challenge, assertions, store, optionsFor(challenge), challenge.IssuedAt)
	if !errors.Is(err, ErrVerificationFailed) || !errors.Is(err, contracts.ErrApprovalAssertionInvalid) {
		t.Fatalf("VerifyQuorum() assertion error = %v, want verifier and contract identities", err)
	}
}

func sealedChallenge(t *testing.T) contracts.ApprovalChallenge {
	t.Helper()
	holdStarted := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	challenge, err := (contracts.ApprovalChallenge{
		Domain:                contracts.ApprovalChallengeDomainV1,
		SchemaVersion:         contracts.ApprovalChallengeSchemaV1,
		ContractVersion:       contracts.ApprovalChallengeContractV1,
		ChallengeID:           "challenge-a",
		ApprovalID:            "approval-a",
		TenantID:              "tenant-a",
		WorkspaceID:           "workspace-a",
		Audience:              "packs.lifecycle",
		PackID:                "pack-a",
		PackVersion:           "1.0.0",
		PackManifestHash:      shaRef("a"),
		Action:                contracts.ApprovalGrantActionInstall,
		ConnectorAuthority:    connectorAuthorityFixture(t),
		IntentHash:            shaRef("0"),
		EffectHash:            shaRef("1"),
		PlanHash:              shaRef("2"),
		Decision:              contracts.ApprovalGrantDecisionAllow,
		PolicyVersion:         "policy-v1",
		PolicyEpoch:           "epoch-1",
		PolicyHash:            shaRef("3"),
		AuthoritySource:       "spiffe://helm/authority/approvers",
		AuthorityVersion:      "authority-v1",
		AuthoritySnapshotHash: shaRef("4"),
		RequiredRole:          "pack-admin",
		Quorum:                2,
		ServerIdentity:        "spiffe://helm/server-a",
		HoldStartedAt:         holdStarted,
		EligibleAt:            holdStarted.Add(5 * time.Minute),
		IssuedAt:              holdStarted.Add(6 * time.Minute),
		ExpiresAt:             holdStarted.Add(15 * time.Minute),
		Nonce:                 strings.Repeat("6", 64),
	}).Seal()
	if err != nil {
		t.Fatalf("ApprovalChallenge.Seal() error = %v", err)
	}
	return challenge
}

func trustedStore(challenge contracts.ApprovalChallenge) (TrustStore, map[string]ed25519.PrivateKey) {
	privateA := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	privateB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	privateKeys := map[string]ed25519.PrivateKey{"key-a": privateA, "key-b": privateB}
	keys := make(map[string]TrustedApproverKey, 2)
	for i, keyID := range []string{"key-a", "key-b"} {
		suffix := string(rune('a' + i))
		keys[keyID] = TrustedApproverKey{
			KeyID:        keyID,
			TenantID:     challenge.TenantID,
			PrincipalID:  "principal-" + suffix,
			CredentialID: "credential-" + suffix,
			DeviceID:     "device-" + suffix,
			PublicKey:    privateKeys[keyID].Public().(ed25519.PublicKey),
			WorkspaceIDs: []string{challenge.WorkspaceID},
			Roles:        []string{challenge.RequiredRole},
			Actions:      []string{challenge.Action},
			Audiences:    []string{challenge.Audience},
			Enabled:      true,
			NotBefore:    challenge.HoldStartedAt.Add(-time.Hour),
			NotAfter:     challenge.ExpiresAt.Add(time.Hour),
		}
	}
	return TrustStore{
		AuthoritySource:       challenge.AuthoritySource,
		AuthorityVersion:      challenge.AuthorityVersion,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash,
		Keys:                  keys,
	}, privateKeys
}

func signedQuorum(t *testing.T, challenge contracts.ApprovalChallenge, privateKeys map[string]ed25519.PrivateKey) []contracts.ApprovalAssertion {
	t.Helper()
	return []contracts.ApprovalAssertion{
		signedAssertion(t, challenge, "key-a", privateKeys["key-a"]),
		signedAssertion(t, challenge, "key-b", privateKeys["key-b"]),
	}
}

func signedAssertion(t *testing.T, challenge contracts.ApprovalChallenge, keyID string, privateKey ed25519.PrivateKey) contracts.ApprovalAssertion {
	t.Helper()
	assertion := contracts.ApprovalAssertion{
		Domain:          contracts.ApprovalAssertionDomainV1,
		SchemaVersion:   contracts.ApprovalAssertionSchemaV1,
		ContractVersion: contracts.ApprovalAssertionContractV1,
		ChallengeID:     challenge.ChallengeID,
		ChallengeHash:   challenge.ChallengeHash,
		KeyID:           keyID,
		Algorithm:       contracts.ApprovalAssertionEd25519,
	}
	digest, err := assertion.SigningDigest()
	if err != nil {
		t.Fatalf("ApprovalAssertion.SigningDigest() error = %v", err)
	}
	assertion.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, digest))
	return assertion
}

func corruptSignature(assertion *contracts.ApprovalAssertion) {
	last := byte('0')
	if assertion.Signature[len(assertion.Signature)-1] == last {
		last = '1'
	}
	assertion.Signature = assertion.Signature[:len(assertion.Signature)-1] + string(last)
}

func optionsFor(challenge contracts.ApprovalChallenge) VerifyOptions {
	return VerifyOptions{
		Expected: ExpectedBinding{
			ChallengeID:           challenge.ChallengeID,
			ChallengeHash:         challenge.ChallengeHash,
			ApprovalID:            challenge.ApprovalID,
			TenantID:              challenge.TenantID,
			WorkspaceID:           challenge.WorkspaceID,
			Audience:              challenge.Audience,
			PackID:                challenge.PackID,
			PackVersion:           challenge.PackVersion,
			PackManifestHash:      challenge.PackManifestHash,
			Action:                challenge.Action,
			ConnectorAuthority:    challenge.ConnectorAuthority,
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
			RequiredRole:          challenge.RequiredRole,
			Quorum:                challenge.Quorum,
			ServerIdentity:        challenge.ServerIdentity,
		},
		MinHoldDuration: 5 * time.Minute,
		MaxChallengeTTL: 20 * time.Minute,
		MaxAssertions:   4,
	}
}

func cloneStore(store TrustStore) TrustStore {
	cloned := TrustStore{
		AuthoritySource:       store.AuthoritySource,
		AuthorityVersion:      store.AuthorityVersion,
		AuthoritySnapshotHash: store.AuthoritySnapshotHash,
		Keys:                  make(map[string]TrustedApproverKey, len(store.Keys)),
	}
	for keyID, key := range store.Keys {
		cloned.Keys[keyID] = key
	}
	return cloned
}

func bindingFromProjection(got VerifiedApprovalRef) ExpectedBinding {
	return ExpectedBinding{
		ChallengeID:           got.ChallengeID,
		ChallengeHash:         got.ChallengeHash,
		ApprovalID:            got.ApprovalID,
		TenantID:              got.TenantID,
		WorkspaceID:           got.WorkspaceID,
		Audience:              got.Audience,
		PackID:                got.PackID,
		PackVersion:           got.PackVersion,
		PackManifestHash:      got.PackManifestHash,
		Action:                got.Action,
		ConnectorAuthority:    got.ConnectorAuthority,
		IntentHash:            got.IntentHash,
		EffectHash:            got.EffectHash,
		PlanHash:              got.PlanHash,
		Decision:              got.Decision,
		PolicyVersion:         got.PolicyVersion,
		PolicyEpoch:           got.PolicyEpoch,
		PolicyHash:            got.PolicyHash,
		AuthoritySource:       got.AuthoritySource,
		AuthorityVersion:      got.AuthorityVersion,
		AuthoritySnapshotHash: got.AuthoritySnapshotHash,
		RequiredRole:          got.RequiredRole,
		Quorum:                got.Quorum,
		ServerIdentity:        got.ServerIdentity,
	}
}

func connectorAuthorityFixture(t *testing.T) contracts.ApprovalConnectorAuthority {
	t.Helper()
	authority, err := (contracts.ApprovalConnectorAuthority{
		SchemaVersion:   contracts.ApprovalConnectorAuthoritySchemaV1,
		ContractVersion: contracts.ApprovalConnectorAuthorityContractV1,
		State:           contracts.ApprovalConnectorAuthorityStateV1,
		BindingRef:      "binding-a", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		PackID: "pack-a", PackVersion: "1.0.0", PackManifestHash: shaRef("a"),
		Action: contracts.ApprovalGrantActionInstall, EffectHash: shaRef("1"), PolicyHash: shaRef("3"),
		ConnectorID: "connector-a", ConnectorVersion: "1.0.0",
		ReleaseScopeKind: contracts.ConnectorReleaseAuthorityScopeGlobal, ReleaseAuthorityID: "connector-registry-a",
		ReleaseRegistryRevision: 1, ReleaseAuthorityHash: shaRef("4"), ConnectorExecutorKind: "digital",
		ConnectorBinaryHash: shaRef("7"), ConnectorSignatureRef: "sigstore://connector-a/1.0.0",
		ConnectorSignatureHash: shaRef("6"),
		ConnectorSignerID:      "publisher-a", ConnectorSandboxProfile: "sandbox-pack-lifecycle-v1",
		ConnectorDriftPolicyRef: "policy://connector-drift/v1", CertificationRef: "cert://connector-a/1.0.0",
		CertificationHash: shaRef("8"), CertificationAuthority: "spiffe://helm/certification-authority",
	}).Seal()
	if err != nil {
		t.Fatalf("seal connector authority: %v", err)
	}
	return authority
}

func shaRef(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
