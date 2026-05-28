package safedep

import (
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestClassifyHazardSeparatesTrustAndDecay(t *testing.T) {
	if got := ClassifyHazard(contracts.HazardDeadManExpired, true, true); got.State != contracts.SafeDepTerminalFreeze || got.ActivationAllowed {
		t.Fatalf("dead-man expiry must terminal freeze without activation: %+v", got)
	}
	if got := ClassifyHazard(contracts.HazardEnginePinMismatch, true, true); got.State != contracts.SafeDepDeprecatedReadonly || got.ActivationAllowed {
		t.Fatalf("engine pin mismatch must become read-only deprecation: %+v", got)
	}
	if got := ClassifyHazard(contracts.HazardCredentialExpired, true, false); got.State != contracts.SafeDepDegradedNarrowing || !got.ActivationAllowed {
		t.Fatalf("credential rot during clock should allow degraded narrowing: %+v", got)
	}
	if got := ClassifyHazard(contracts.HazardCredentialExpired, false, false); got.ActivationAllowed {
		t.Fatalf("credential rot outside active clock must not activate: %+v", got)
	}
}

func TestContinuityRejectsReplayAndStaleEpoch(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	cp := contracts.ContinuityCheckpoint{
		CheckpointID:                 "cp-1",
		OrgGenomeHash:                "sha256:org",
		PolicyHash:                   "sha256:policy",
		PolicyEpoch:                  9,
		HazardSequence:               10,
		DeadManWindowID:              "dm-1",
		DeadManActive:                true,
		LatestAcceptedCheckpointHash: "sha256:last",
		Nonce:                        "nonce-1",
		AttestedTime:                 now,
		ExpiresAt:                    now.Add(time.Minute),
	}
	expected := ContinuityExpectation{
		PolicyEpoch:                  9,
		PolicyHash:                   "sha256:policy",
		OrgGenomeHash:                "sha256:org",
		MinHazardSequence:            9,
		LatestAcceptedCheckpointHash: "sha256:last",
		RequireDeadManActive:         true,
		Now:                          now,
	}
	nonces := NewMemoryNonceStore()
	if err := ValidateAndConsumeContinuity(cp, expected, nonces); err != nil {
		t.Fatalf("valid continuity rejected: %v", err)
	}
	if err := ValidateAndConsumeContinuity(cp, expected, nonces); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
	cp.Nonce = "nonce-2"
	cp.PolicyEpoch = 8
	if err := ValidateAndConsumeContinuity(cp, expected, nonces); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected stale epoch rejection, got %v", err)
	}
}

func TestEmergencyCapsuleRequiresNarrowingSubsetAndBinding(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	capsule := validCapsule(now)
	expected := CapsuleExpectation{
		HazardCode:             contracts.HazardCredentialExpired,
		State:                  contracts.SafeDepDegradedNarrowing,
		OrgGenomeHash:          "sha256:org",
		PolicyEpoch:            7,
		PolicyHash:             "sha256:policy",
		P0CeilingsHash:         "sha256:p0",
		P1BundleHash:           "sha256:p1",
		CPIHash:                "sha256:cpi",
		ProviderRegistryHash:   "sha256:providers",
		CredentialRegistryHash: "sha256:creds",
		VerifierProfileHash:    "sha256:verifier",
		Now:                    now,
		MaxTTL:                 30 * time.Minute,
		RequireTransparency:    true,
	}
	if err := ValidateEmergencyCapsule(capsule, expected); err != nil {
		t.Fatalf("valid capsule rejected: %v", err)
	}
	capsule.SubsetProofHash = ""
	if err := ValidateEmergencyCapsule(capsule, expected); !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected subset proof rejection, got %v", err)
	}
	capsule = validCapsule(now)
	capsule.State = contracts.SafeDepDeprecatedReadonly
	if err := ValidateEmergencyCapsule(capsule, expected); !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected non-narrowing capsule rejection, got %v", err)
	}
}

func TestHardwareCeremonyRejectsDuplicateOutsiderAndRevokedSigner(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	ceremony := validCapsule(now).Ceremony
	authorized := map[string]contracts.ThresholdSignature{
		"alice": {SignerID: "alice", Role: "founder", DeviceID: "yubi-a"},
		"bob":   {SignerID: "bob", Role: "security", DeviceID: "yubi-b"},
		"carol": {SignerID: "carol", Role: "ops", DeviceID: "yubi-c"},
	}
	if err := ValidateHardwareCeremony(ceremony, CeremonyExpectation{AuthorizedSigners: authorized, RequiredQuorum: 3, PolicyEpoch: 7, Now: now}); err != nil {
		t.Fatalf("valid ceremony rejected: %v", err)
	}
	ceremony.Approvals[1].SignerID = "alice"
	if err := ValidateHardwareCeremony(ceremony, CeremonyExpectation{AuthorizedSigners: authorized, RequiredQuorum: 3, PolicyEpoch: 7, Now: now}); !errors.Is(err, ErrHardwareQuorumUnbound) {
		t.Fatalf("expected duplicate signer rejection, got %v", err)
	}
	ceremony = validCapsule(now).Ceremony
	ceremony.Approvals[2].SignerID = "mallory"
	if err := ValidateHardwareCeremony(ceremony, CeremonyExpectation{AuthorizedSigners: authorized, RequiredQuorum: 3, PolicyEpoch: 7, Now: now}); !errors.Is(err, ErrHardwareQuorumUnbound) {
		t.Fatalf("expected outsider rejection, got %v", err)
	}
	authorized["carol"] = contracts.ThresholdSignature{SignerID: "carol", Role: "ops", DeviceID: "yubi-c", RevokedAtEpoch: 7}
	ceremony = validCapsule(now).Ceremony
	if err := ValidateHardwareCeremony(ceremony, CeremonyExpectation{AuthorizedSigners: authorized, RequiredQuorum: 3, PolicyEpoch: 7, Now: now}); !errors.Is(err, ErrHardwareQuorumUnbound) {
		t.Fatalf("expected revoked signer rejection, got %v", err)
	}
}

func TestAttestationResultAndDevFallbackValidation(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	env := validCapsule(now).Attestation
	if err := ValidateAttestationResult(env, AttestationExpectation{ProfileID: "nitro-prod", PolicyHash: "sha256:appraisal", Nonce: "nonce-1", MeasurementHash: "sha256:measurement", Now: now}); err != nil {
		t.Fatalf("valid attestation result rejected: %v", err)
	}
	env.Synthetic = true
	if err := ValidateAttestationResult(env, AttestationExpectation{Now: now}); !errors.Is(err, ErrAttestationResultRequired) {
		t.Fatalf("expected synthetic attestation rejection, got %v", err)
	}
	if err := ValidateDevFallbackPosture(contracts.DevFallbackPosture{EnvCredentialFallback: true}); !errors.Is(err, ErrDevFallbackPresent) {
		t.Fatalf("expected env fallback rejection, got %v", err)
	}
}

func TestValidateActivationRequiresContinuityCapsuleQuorumDelegationAndAttestation(t *testing.T) {
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	capsule := validCapsule(now)
	checkpoint := contracts.ContinuityCheckpoint{
		CheckpointID:                 "cp-1",
		OrgGenomeHash:                "sha256:org",
		PolicyHash:                   "sha256:policy",
		PolicyEpoch:                  7,
		HazardSequence:               11,
		DeadManWindowID:              "dm-1",
		DeadManActive:                true,
		LatestAcceptedCheckpointHash: "sha256:last",
		Nonce:                        "nonce-activation",
		AttestedTime:                 now,
		ExpiresAt:                    now.Add(time.Minute),
	}
	expectation := ActivationExpectation{
		Continuity: ContinuityExpectation{
			PolicyEpoch:                  7,
			PolicyHash:                   "sha256:policy",
			OrgGenomeHash:                "sha256:org",
			MinHazardSequence:            10,
			LatestAcceptedCheckpointHash: "sha256:last",
			RequireDeadManActive:         true,
		},
		Capsule: CapsuleExpectation{
			HazardCode:             contracts.HazardCredentialExpired,
			State:                  contracts.SafeDepDegradedNarrowing,
			OrgGenomeHash:          "sha256:org",
			PolicyEpoch:            7,
			PolicyHash:             "sha256:policy",
			P0CeilingsHash:         "sha256:p0",
			P1BundleHash:           "sha256:p1",
			CPIHash:                "sha256:cpi",
			ProviderRegistryHash:   "sha256:providers",
			CredentialRegistryHash: "sha256:creds",
			VerifierProfileHash:    "sha256:verifier",
			MaxTTL:                 30 * time.Minute,
		},
		Ceremony: CeremonyExpectation{
			RequiredQuorum: 3,
			PolicyEpoch:    7,
		},
		Attestation: AttestationExpectation{
			ProfileID:       "nitro-prod",
			PolicyHash:      "sha256:appraisal",
			Nonce:           "nonce-1",
			MeasurementHash: "sha256:measurement",
		},
		Now: now,
	}
	if err := ValidateActivation(checkpoint, capsule, contracts.DevFallbackPosture{}, expectation, NewMemoryNonceStore()); err != nil {
		t.Fatalf("valid activation rejected: %v", err)
	}
	capsule.Ceremony.Approvals = capsule.Ceremony.Approvals[:2]
	if err := ValidateActivation(checkpoint, capsule, contracts.DevFallbackPosture{}, expectation, NewMemoryNonceStore()); !errors.Is(err, ErrHardwareQuorumUnbound) {
		t.Fatalf("expected quorum rejection, got %v", err)
	}
}

func validCapsule(now time.Time) contracts.EmergencyCapsule {
	return contracts.EmergencyCapsule{
		CapsuleID:              "capsule-1",
		Version:                1,
		ApertureID:             "rotate-credential",
		HazardCode:             contracts.HazardCredentialExpired,
		State:                  contracts.SafeDepDegradedNarrowing,
		OrgGenomeHash:          "sha256:org",
		PolicyEpoch:            7,
		PolicyHash:             "sha256:policy",
		P0CeilingsHash:         "sha256:p0",
		P1BundleHash:           "sha256:p1",
		CPIHash:                "sha256:cpi",
		ProviderRegistryHash:   "sha256:providers",
		CredentialRegistryHash: "sha256:creds",
		VerifierProfileHash:    "sha256:verifier",
		PredecessorHash:        "sha256:previous",
		SubsetProofHash:        "sha256:subset",
		SubsetProofKind:        "cpi-narrowing-v1",
		AllowedActions:         []string{"credential.rotate.propose"},
		AllowedConnectors:      []string{"github"},
		TTLSeconds:             int64((10 * time.Minute).Seconds()),
		NotBefore:              now.Add(-time.Minute),
		ExpiresAt:              now.Add(10 * time.Minute),
		Signatures: []contracts.ThresholdSignature{
			{SignerID: "alice", Role: "founder", DeviceID: "yubi-a", KeyID: "k1", Signature: "sig-a"},
			{SignerID: "bob", Role: "security", DeviceID: "yubi-b", KeyID: "k2", Signature: "sig-b"},
			{SignerID: "carol", Role: "ops", DeviceID: "yubi-c", KeyID: "k3", Signature: "sig-c"},
		},
		Ceremony: contracts.HardwareCeremonyTranscript{
			CeremonyID:          "ceremony-1",
			RequiredQuorum:      3,
			EnrolledSignerCount: 5,
			StartedAt:           now.Add(-time.Minute),
			ExpiresAt:           now.Add(5 * time.Minute),
			TranscriptHash:      "sha256:ceremony",
			Approvals: []contracts.HardwareApproval{
				{SignerID: "alice", Role: "founder", DeviceID: "yubi-a", AssertionHash: "sha256:a", SignedAt: now},
				{SignerID: "bob", Role: "security", DeviceID: "yubi-b", AssertionHash: "sha256:b", SignedAt: now},
				{SignerID: "carol", Role: "ops", DeviceID: "yubi-c", AssertionHash: "sha256:c", SignedAt: now},
			},
		},
		Delegation: contracts.EmergencyDelegationChain{
			SessionID:      "session-1",
			HumanSubjectID: "alice",
			Scope:          []string{"credential.rotate.propose"},
			MaxHops:        1,
			NotBefore:      now.Add(-time.Minute),
			ExpiresAt:      now.Add(10 * time.Minute),
			Hops: []contracts.EmergencyDelegationHop{
				{IssuerID: "alice", SubjectID: "agent-1", ScopeHash: "sha256:scope", SignedAt: now, Signature: "sig-hop"},
			},
		},
		Attestation: contracts.AttestationResultEnvelope{
			EnvelopeID:      "attestation-1",
			ProfileID:       "nitro-prod",
			Subject:         "emergency-appraiser",
			Platform:        "aws-nitro",
			MeasurementHash: "sha256:measurement",
			Nonce:           "nonce-1",
			TrustTier:       "verified",
			PolicyHash:      "sha256:appraisal",
			IssuedAt:        now.Add(-time.Minute),
			ExpiresAt:       now.Add(time.Minute),
			Signature:       "sig-attestation",
		},
		Transparency: contracts.TransparencyAnchor{Backend: "rekor", LogID: "log-1", InclusionProofHash: "sha256:proof"},
	}
}
