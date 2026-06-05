package safedep

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type coverageHazardError struct {
	hazard contracts.SafeDepHazardCode
}

func (e coverageHazardError) Error() string {
	return "hazard: " + string(e.hazard)
}

func (e coverageHazardError) SafeDepHazardCode() contracts.SafeDepHazardCode {
	return e.hazard
}

type coverageStringer string

func (s coverageStringer) String() string {
	return string(s)
}

type coverageContinuityStore struct {
	latest      ContinuityState
	latestOK    bool
	latestErr   error
	appendState ContinuityState
	appendErr   error
	storeErr    error
	getErr      error
	closeErr    error
	appended    []contracts.ContinuityCheckpoint
	stored      []contracts.ActivationReceipt
	closed      []string
}

func (s *coverageContinuityStore) Latest(context.Context) (ContinuityState, bool, error) {
	if s.latestErr != nil {
		return ContinuityState{}, false, s.latestErr
	}
	return s.latest, s.latestOK, nil
}

func (s *coverageContinuityStore) AppendCheckpoint(_ context.Context, checkpoint contracts.ContinuityCheckpoint) (ContinuityState, error) {
	s.appended = append(s.appended, checkpoint)
	if s.appendErr != nil {
		return ContinuityState{}, s.appendErr
	}
	if s.appendState.CheckpointHash != "" {
		return s.appendState, nil
	}
	hash, err := CheckpointHash(checkpoint)
	if err != nil {
		return ContinuityState{}, err
	}
	return ContinuityState{
		CheckpointID:    checkpoint.CheckpointID,
		CheckpointHash:  hash,
		HazardSequence:  checkpoint.HazardSequence,
		PolicyEpoch:     checkpoint.PolicyEpoch,
		LamportClock:    checkpoint.LamportClock,
		DeadManWindowID: checkpoint.DeadManWindowID,
	}, nil
}

func (s *coverageContinuityStore) StoreActivation(_ context.Context, receipt contracts.ActivationReceipt) error {
	s.stored = append(s.stored, receipt)
	return s.storeErr
}

func (s *coverageContinuityStore) GetActivation(context.Context, string) (contracts.ActivationReceipt, bool, error) {
	if s.getErr != nil {
		return contracts.ActivationReceipt{}, false, s.getErr
	}
	return contracts.ActivationReceipt{}, false, nil
}

func (s *coverageContinuityStore) CloseActivation(_ context.Context, activationID string, _ contracts.ContinuityCheckpoint) error {
	s.closed = append(s.closed, activationID)
	return s.closeErr
}

type coverageEvidenceSink struct {
	err    error
	refs   EvidenceRefs
	events []EvidenceEvent
}

func (s *coverageEvidenceSink) RecordSafeDepEvent(_ context.Context, event EvidenceEvent) (EvidenceRefs, error) {
	s.events = append(s.events, event)
	if s.err != nil {
		return EvidenceRefs{}, s.err
	}
	if s.refs != (EvidenceRefs{}) {
		return s.refs, nil
	}
	return EvidenceRefs{ProofGraphRef: "proofgraph:test", EvidencePackRef: "evidencepack:test"}, nil
}

type coverageReceiptSigner struct {
	err error
	sig string
}

func (s coverageReceiptSigner) Sign([]byte) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.sig != "" {
		return s.sig, nil
	}
	return "signed-receipt", nil
}

func TestCoverageContextSignalsAndHelpers(t *testing.T) {
	if signal := SignalFromError(nil, true, true); !signal.Empty() {
		t.Fatalf("nil error produced signal: %+v", signal)
	}
	if signal := SignalFromError(errors.New("plain"), true, true); !signal.Empty() {
		t.Fatalf("plain error produced signal: %+v", signal)
	}
	signal := SignalFromError(coverageHazardError{hazard: contracts.HazardCredentialExpired}, true, false)
	if signal.HazardCode != contracts.HazardCredentialExpired || !signal.ActiveClock || signal.HighRiskLane {
		t.Fatalf("unexpected coded signal: %+v", signal)
	}

	nested := SignalFromContext(map[string]any{
		"safe_deprecation": map[string]any{
			"hazard_code":    string(contracts.HazardAPIRot),
			"lane_id":        coverageStringer(" lane-a "),
			"connector_id":   "github",
			"active_clock":   "true",
			"high_risk_lane": true,
			"reason":         "credential drift",
		},
	})
	if nested.HazardCode != contracts.HazardAPIRot || nested.LaneID != "lane-a" || !nested.ActiveClock || !nested.HighRiskLane {
		t.Fatalf("unexpected nested signal: %+v", nested)
	}
	if signal := SignalFromContext(nil); !signal.Empty() {
		t.Fatalf("empty context produced signal: %+v", signal)
	}
	if signal := SignalFromContext(map[string]any{"safe_deprecation": "not-map"}); !signal.Empty() {
		t.Fatalf("invalid nested context produced signal: %+v", signal)
	}

	direct := GateRequest{Signal: Signal{HazardCode: contracts.HazardDeadManExpired}, InspectionOnly: true}
	if got := GateRequestFromContext(map[string]any{"safe_deprecation_gate_request": direct}); got.Signal.HazardCode != direct.Signal.HazardCode || !got.InspectionOnly {
		t.Fatalf("direct gate request not returned: %+v", got)
	}
	now := fixedSafeDepClock()
	capsule := validCapsule(now)
	checkpoint := validContinuityCheckpoint(now, "ctx-nonce", 3)
	derived := GateRequestFromContext(map[string]any{
		"hazard_code":                              string(contracts.HazardCredentialExpired),
		"safe_deprecation_checkpoint":              checkpoint,
		"safe_deprecation_capsule":                 capsule,
		"safe_deprecation_dev_fallback_posture":    contracts.DevFallbackPosture{},
		"safe_deprecation_expectation":             ActivationExpectation{Now: now},
		"safe_deprecation_inspection_only":         true,
		"safe_deprecation_active_clock":            true,
		"safe_deprecation_connector_id":            "github",
		"safe_deprecation_lane_id":                 "lane-1",
		"safe_deprecation_reason":                  "rot",
		"safe_deprecation_high_risk_lane":          "true",
		"safe_deprecation_unknown_ignored_context": "ignored",
	})
	if derived.Capsule == nil || derived.Checkpoint.CheckpointID == "" || !derived.InspectionOnly || derived.Expectation.Now != now {
		t.Fatalf("derived gate request incomplete: %+v", derived)
	}
	pointerDerived := GateRequestFromContext(map[string]any{"safe_deprecation_capsule": &capsule})
	if pointerDerived.Capsule != &capsule {
		t.Fatalf("pointer capsule not preserved: %+v", pointerDerived.Capsule)
	}
	if got := GateRequestFromContext(nil); !got.Signal.Empty() {
		t.Fatalf("empty gate context produced request: %+v", got)
	}

	if !IsInspectionAction("", "status") || IsInspectionAction("write", "mutate") {
		t.Fatal("inspection action classification mismatch")
	}
	if firstString(map[string]any{"a": " ", "b": coverageStringer(" value ")}, "a", "b") != "value" {
		t.Fatal("firstString did not trim fmt.Stringer")
	}
	if firstString(map[string]any{"a": 12}, "a") != "" {
		t.Fatal("firstString should ignore unsupported values")
	}
	if !firstBool(map[string]any{"a": "TRUE"}, "a") || firstBool(map[string]any{"a": "false"}, "a") {
		t.Fatal("firstBool string parsing mismatch")
	}
	if firstBool(map[string]any{"a": 1}, "a") {
		t.Fatal("firstBool should ignore unsupported values")
	}
}

func TestCoverageValidationBranchMatrices(t *testing.T) {
	now := fixedSafeDepClock()
	checkpoint := validContinuityCheckpoint(now, "nonce-branches", 11)
	continuityExpected := ContinuityExpectation{
		PolicyEpoch:                  7,
		PolicyHash:                   "sha256:policy",
		OrgGenomeHash:                "sha256:org",
		MinHazardSequence:            10,
		LatestAcceptedCheckpointHash: "sha256:last",
		RequireDeadManActive:         true,
		Now:                          now,
	}
	for name, mutate := range map[string]func(*contracts.ContinuityCheckpoint){
		"missing id":    func(c *contracts.ContinuityCheckpoint) { c.CheckpointID = "" },
		"missing nonce": func(c *contracts.ContinuityCheckpoint) { c.Nonce = "" },
		"policy hash":   func(c *contracts.ContinuityCheckpoint) { c.PolicyHash = "sha256:other" },
		"org hash":      func(c *contracts.ContinuityCheckpoint) { c.OrgGenomeHash = "sha256:other" },
		"old sequence":  func(c *contracts.ContinuityCheckpoint) { c.HazardSequence = 10 },
		"latest hash":   func(c *contracts.ContinuityCheckpoint) { c.LatestAcceptedCheckpointHash = "sha256:other" },
		"deadman":       func(c *contracts.ContinuityCheckpoint) { c.DeadManActive = false },
		"missing time":  func(c *contracts.ContinuityCheckpoint) { c.AttestedTime = time.Time{} },
		"future time":   func(c *contracts.ContinuityCheckpoint) { c.AttestedTime = now.Add(3 * time.Minute) },
		"expired":       func(c *contracts.ContinuityCheckpoint) { c.ExpiresAt = now.Add(-time.Second) },
		"wrong epoch":   func(c *contracts.ContinuityCheckpoint) { c.PolicyEpoch = 8 },
		"default max skew": func(c *contracts.ContinuityCheckpoint) {
			c.AttestedTime = time.Now().UTC().Add(3 * time.Minute)
		},
	} {
		t.Run("continuity "+name, func(t *testing.T) {
			candidate := checkpoint
			expected := continuityExpected
			if name == "default max skew" {
				expected.Now = time.Now().UTC()
				expected.MaxClockSkew = 0
			}
			mutate(&candidate)
			if err := ValidateContinuity(candidate, expected); !errors.Is(err, ErrContinuityStale) {
				t.Fatalf("expected continuity stale, got %v", err)
			}
		})
	}
	if err := ValidateAndConsumeContinuity(checkpoint, continuityExpected, nil); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected nil nonce store rejection, got %v", err)
	}
	nonces := NewMemoryNonceStore()
	if nonces.Consume(" ") {
		t.Fatal("blank nonce should not be consumed")
	}

	capsule := validCapsule(now)
	capsuleExpected := CapsuleExpectation{
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
		PreviousCapsuleHash:    "sha256:previous",
		Now:                    now,
		MinTTL:                 time.Minute,
		MaxTTL:                 30 * time.Minute,
		RequireTransparency:    true,
	}
	for name, mutate := range map[string]func(*contracts.EmergencyCapsule){
		"missing id":      func(c *contracts.EmergencyCapsule) { c.CapsuleID = "" },
		"hazard mismatch": func(c *contracts.EmergencyCapsule) { c.HazardCode = contracts.HazardAPIRot },
		"org mismatch":    func(c *contracts.EmergencyCapsule) { c.OrgGenomeHash = "sha256:other" },
		"epoch mismatch":  func(c *contracts.EmergencyCapsule) { c.PolicyEpoch = 8 },
		"policy mismatch": func(c *contracts.EmergencyCapsule) { c.PolicyHash = "sha256:other" },
		"p0 mismatch":     func(c *contracts.EmergencyCapsule) { c.P0CeilingsHash = "sha256:other" },
		"p1 mismatch":     func(c *contracts.EmergencyCapsule) { c.P1BundleHash = "sha256:other" },
		"cpi mismatch":    func(c *contracts.EmergencyCapsule) { c.CPIHash = "sha256:other" },
		"provider":        func(c *contracts.EmergencyCapsule) { c.ProviderRegistryHash = "sha256:other" },
		"credential":      func(c *contracts.EmergencyCapsule) { c.CredentialRegistryHash = "sha256:other" },
		"verifier":        func(c *contracts.EmergencyCapsule) { c.VerifierProfileHash = "sha256:other" },
		"predecessor":     func(c *contracts.EmergencyCapsule) { c.PredecessorHash = "sha256:other" },
		"missing subset":  func(c *contracts.EmergencyCapsule) { c.SubsetProofKind = "" },
		"nonpositive ttl": func(c *contracts.EmergencyCapsule) { c.TTLSeconds = 0 },
		"too short ttl":   func(c *contracts.EmergencyCapsule) { c.TTLSeconds = 30 },
		"too long ttl":    func(c *contracts.EmergencyCapsule) { c.TTLSeconds = int64((time.Hour).Seconds()) },
		"not before":      func(c *contracts.EmergencyCapsule) { c.NotBefore = now.Add(time.Second) },
		"expired":         func(c *contracts.EmergencyCapsule) { c.ExpiresAt = now.Add(-time.Second) },
		"missing sigs":    func(c *contracts.EmergencyCapsule) { c.Signatures = nil },
		"bad transparency": func(c *contracts.EmergencyCapsule) {
			c.Transparency.Deferred = true
			c.Transparency.DeferredUntil = time.Time{}
		},
	} {
		t.Run("capsule "+name, func(t *testing.T) {
			candidate := capsule
			mutate(&candidate)
			if err := ValidateEmergencyCapsule(candidate, capsuleExpected); !errors.Is(err, ErrEmergencyCapsuleInvalid) {
				t.Fatalf("expected capsule invalid, got %v", err)
			}
		})
	}

	ceremony := validCapsule(now).Ceremony
	for name, tc := range map[string]struct {
		mutate   func(*contracts.HardwareCeremonyTranscript)
		expected CeremonyExpectation
	}{
		"no quorum":        {mutate: func(c *contracts.HardwareCeremonyTranscript) { c.RequiredQuorum = 0 }, expected: CeremonyExpectation{Now: now}},
		"too much quorum":  {mutate: func(c *contracts.HardwareCeremonyTranscript) {}, expected: CeremonyExpectation{Now: now, RequiredQuorum: 6}},
		"missing id":       {mutate: func(c *contracts.HardwareCeremonyTranscript) { c.CeremonyID = "" }, expected: CeremonyExpectation{Now: now, RequiredQuorum: 3}},
		"veto open":        {mutate: func(c *contracts.HardwareCeremonyTranscript) { c.VetoUntil = now.Add(time.Minute) }, expected: CeremonyExpectation{Now: now, RequiredQuorum: 3}},
		"expired":          {mutate: func(c *contracts.HardwareCeremonyTranscript) { c.ExpiresAt = now.Add(-time.Second) }, expected: CeremonyExpectation{Now: now, RequiredQuorum: 3}},
		"incomplete":       {mutate: func(c *contracts.HardwareCeremonyTranscript) { c.Approvals[0].AssertionHash = "" }, expected: CeremonyExpectation{Now: now, RequiredQuorum: 3}},
		"duplicate device": {mutate: func(c *contracts.HardwareCeremonyTranscript) { c.Approvals[1].DeviceID = c.Approvals[0].DeviceID }, expected: CeremonyExpectation{Now: now, RequiredQuorum: 3}},
		"duplicate role":   {mutate: func(c *contracts.HardwareCeremonyTranscript) { c.Approvals[1].Role = c.Approvals[0].Role }, expected: CeremonyExpectation{Now: now, RequiredQuorum: 3, RequireDistinctRoles: true}},
		"hardware no registry": {
			mutate:   func(c *contracts.HardwareCeremonyTranscript) {},
			expected: CeremonyExpectation{Now: now, RequiredQuorum: 3, RequireHardwareBound: true},
		},
		"approval revoked": {
			mutate: func(c *contracts.HardwareCeremonyTranscript) { c.Approvals[0].RevokedAtEpoch = 7 },
			expected: CeremonyExpectation{
				Now:            now,
				RequiredQuorum: 3,
				PolicyEpoch:    7,
			},
		},
		"role mismatch": {
			mutate: func(c *contracts.HardwareCeremonyTranscript) {},
			expected: CeremonyExpectation{Now: now, RequiredQuorum: 3, PolicyEpoch: 7, AuthorizedSigners: map[string]contracts.ThresholdSignature{
				"alice": {SignerID: "alice", Role: "security", DeviceID: "yubi-a"},
			}},
		},
		"device mismatch": {
			mutate: func(c *contracts.HardwareCeremonyTranscript) {},
			expected: CeremonyExpectation{Now: now, RequiredQuorum: 3, PolicyEpoch: 7, AuthorizedSigners: map[string]contracts.ThresholdSignature{
				"alice": {SignerID: "alice", Role: "founder", DeviceID: "other-device"},
			}},
		},
		"hardware verify": {
			mutate: func(c *contracts.HardwareCeremonyTranscript) {},
			expected: CeremonyExpectation{Now: now, RequiredQuorum: 3, PolicyEpoch: 7, RequireHardwareBound: true, AuthorizedSigners: map[string]contracts.ThresholdSignature{
				"alice": {SignerID: "alice", Role: "founder", DeviceID: "yubi-a", PublicKey: "not-a-key", Signature: "sig"},
			}},
		},
	} {
		t.Run("ceremony "+name, func(t *testing.T) {
			candidate := ceremony
			tc.mutate(&candidate)
			if err := ValidateHardwareCeremony(candidate, tc.expected); !errors.Is(err, ErrHardwareQuorumUnbound) {
				t.Fatalf("expected ceremony invalid, got %v", err)
			}
		})
	}
	if !strings.Contains(hardwareApprovalPayload("sha256:t", ceremony.Approvals[0]), "alice") {
		t.Fatal("hardware approval payload did not bind signer")
	}
	hardwareBound, authorized := coverageHardwareBoundCeremony(t, now)
	if err := ValidateHardwareCeremony(hardwareBound, CeremonyExpectation{
		AuthorizedSigners:    authorized,
		RequiredQuorum:       3,
		PolicyEpoch:          7,
		Now:                  now,
		RequireHardwareBound: true,
	}); err != nil {
		t.Fatalf("valid hardware-bound ceremony rejected: %v", err)
	}
	tampered := hardwareBound
	tampered.Approvals[0].AssertionHash = "sha256:tampered"
	if err := ValidateHardwareCeremony(tampered, CeremonyExpectation{
		AuthorizedSigners:    authorized,
		RequiredQuorum:       3,
		PolicyEpoch:          7,
		Now:                  now,
		RequireHardwareBound: true,
	}); !errors.Is(err, ErrHardwareQuorumUnbound) {
		t.Fatalf("expected tampered hardware assertion rejection, got %v", err)
	}
	missingSignature := hardwareBound
	missingSignature.Approvals[0].AssertionSignature = ""
	unsigned := make(map[string]contracts.ThresholdSignature, len(authorized))
	for signerID, signer := range authorized {
		unsigned[signerID] = signer
	}
	unsigned["alice"] = contracts.ThresholdSignature{SignerID: "alice", Role: "founder", DeviceID: "yubi-a", PublicKey: authorized["alice"].PublicKey}
	if err := ValidateHardwareCeremony(missingSignature, CeremonyExpectation{
		AuthorizedSigners:    unsigned,
		RequiredQuorum:       3,
		PolicyEpoch:          7,
		Now:                  now,
		RequireHardwareBound: true,
	}); !errors.Is(err, ErrHardwareQuorumUnbound) {
		t.Fatalf("expected missing hardware assertion rejection, got %v", err)
	}

	delegation := validCapsule(now).Delegation
	for name, mutate := range map[string]func(*contracts.EmergencyDelegationChain){
		"missing session": func(d *contracts.EmergencyDelegationChain) { d.SessionID = "" },
		"negative hops":   func(d *contracts.EmergencyDelegationChain) { d.MaxHops = -1 },
		"hop limit":       func(d *contracts.EmergencyDelegationChain) { d.MaxHops = 0 },
		"not before":      func(d *contracts.EmergencyDelegationChain) { d.NotBefore = now.Add(time.Second) },
		"expired":         func(d *contracts.EmergencyDelegationChain) { d.ExpiresAt = now.Add(-time.Second) },
		"incomplete hop":  func(d *contracts.EmergencyDelegationChain) { d.Hops[0].Signature = "" },
	} {
		t.Run("delegation "+name, func(t *testing.T) {
			candidate := delegation
			mutate(&candidate)
			if err := ValidateEmergencyDelegation(candidate, now); !errors.Is(err, ErrEmergencyCapsuleInvalid) {
				t.Fatalf("expected delegation invalid, got %v", err)
			}
		})
	}

	attestation := validCapsule(now).Attestation
	for name, mutate := range map[string]func(*contracts.AttestationResultEnvelope){
		"missing signed":       func(a *contracts.AttestationResultEnvelope) { a.EnvelopeID = "" },
		"profile mismatch":     func(a *contracts.AttestationResultEnvelope) { a.ProfileID = "other" },
		"policy mismatch":      func(a *contracts.AttestationResultEnvelope) { a.PolicyHash = "sha256:other" },
		"nonce mismatch":       func(a *contracts.AttestationResultEnvelope) { a.Nonce = "other" },
		"measurement mismatch": func(a *contracts.AttestationResultEnvelope) { a.MeasurementHash = "sha256:other" },
		"expired":              func(a *contracts.AttestationResultEnvelope) { a.ExpiresAt = now.Add(-time.Second) },
		"unverified":           func(a *contracts.AttestationResultEnvelope) { a.TrustTier = "unverified" },
	} {
		t.Run("attestation "+name, func(t *testing.T) {
			candidate := attestation
			mutate(&candidate)
			if err := ValidateAttestationResult(candidate, AttestationExpectation{ProfileID: "nitro-prod", PolicyHash: "sha256:appraisal", Nonce: "nonce-1", MeasurementHash: "sha256:measurement", Now: now}); !errors.Is(err, ErrAttestationResultRequired) {
				t.Fatalf("expected attestation invalid, got %v", err)
			}
		})
	}

	for name, posture := range map[string]contracts.DevFallbackPosture{
		"audit":    {AuditMode: true},
		"mock":     {MockAttester: true},
		"nitro":    {SyntheticNitro: true},
		"hsm":      {SoftwareHSM: true},
		"bearer":   {DevBearerAuth: true},
		"overlay":  {UnsignedMutableOverlay: true},
		"envcreds": {EnvCredentialFallback: true},
	} {
		t.Run("dev fallback "+name, func(t *testing.T) {
			if err := ValidateDevFallbackPosture(posture); !errors.Is(err, ErrDevFallbackPresent) {
				t.Fatalf("expected dev fallback error, got %v", err)
			}
		})
	}
	if !defaultTime(time.Time{}, now).Equal(now) || !defaultTime(now.Add(time.Minute), now).Equal(now.Add(time.Minute)) {
		t.Fatal("defaultTime returned unexpected value")
	}
}

func TestCoverageValidateActivationFailureBranches(t *testing.T) {
	now := fixedSafeDepClock()
	for _, tc := range []struct {
		name    string
		mutate  func(*contracts.ContinuityCheckpoint, *contracts.EmergencyCapsule, *contracts.DevFallbackPosture, *ActivationExpectation, *MemoryNonceStore)
		wantErr error
	}{
		{
			name: "dev fallback",
			mutate: func(_ *contracts.ContinuityCheckpoint, _ *contracts.EmergencyCapsule, posture *contracts.DevFallbackPosture, _ *ActivationExpectation, _ *MemoryNonceStore) {
				posture.SoftwareHSM = true
			},
			wantErr: ErrDevFallbackPresent,
		},
		{
			name: "nonce replay",
			mutate: func(cp *contracts.ContinuityCheckpoint, _ *contracts.EmergencyCapsule, _ *contracts.DevFallbackPosture, _ *ActivationExpectation, nonces *MemoryNonceStore) {
				nonces.Consume(cp.Nonce)
			},
			wantErr: ErrContinuityStale,
		},
		{
			name: "capsule invalid",
			mutate: func(_ *contracts.ContinuityCheckpoint, capsule *contracts.EmergencyCapsule, _ *contracts.DevFallbackPosture, _ *ActivationExpectation, _ *MemoryNonceStore) {
				capsule.CapsuleID = ""
			},
			wantErr: ErrEmergencyCapsuleInvalid,
		},
		{
			name: "ceremony invalid",
			mutate: func(_ *contracts.ContinuityCheckpoint, capsule *contracts.EmergencyCapsule, _ *contracts.DevFallbackPosture, _ *ActivationExpectation, _ *MemoryNonceStore) {
				capsule.Ceremony.Approvals = capsule.Ceremony.Approvals[:2]
			},
			wantErr: ErrHardwareQuorumUnbound,
		},
		{
			name: "delegation invalid",
			mutate: func(_ *contracts.ContinuityCheckpoint, capsule *contracts.EmergencyCapsule, _ *contracts.DevFallbackPosture, _ *ActivationExpectation, _ *MemoryNonceStore) {
				capsule.Delegation.MaxHops = 0
			},
			wantErr: ErrEmergencyCapsuleInvalid,
		},
		{
			name: "attestation invalid",
			mutate: func(_ *contracts.ContinuityCheckpoint, capsule *contracts.EmergencyCapsule, _ *contracts.DevFallbackPosture, _ *ActivationExpectation, _ *MemoryNonceStore) {
				capsule.Attestation.Synthetic = true
			},
			wantErr: ErrAttestationResultRequired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkpoint := validContinuityCheckpoint(now, "activation-"+strings.ReplaceAll(tc.name, " ", "-"), 11)
			capsule := validCapsule(now)
			posture := contracts.DevFallbackPosture{}
			expectation := coverageActivationExpectation(now)
			nonces := NewMemoryNonceStore()
			tc.mutate(&checkpoint, &capsule, &posture, &expectation, nonces)
			if err := ValidateActivation(checkpoint, capsule, posture, expectation, nonces); !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}

	capsule := validCapsule(now)
	hardwareCeremony, expectationSigners := coverageHardwareBoundCeremony(t, now)
	capsule.Ceremony = hardwareCeremony
	expectation := coverageActivationExpectation(now)
	expectation.Ceremony.RequireHardwareBound = true
	expectation.Ceremony.AuthorizedSigners = expectationSigners
	if err := ValidateActivation(
		validContinuityCheckpoint(now, "activation-hardware-bound", 11),
		capsule,
		contracts.DevFallbackPosture{},
		expectation,
		NewMemoryNonceStore(),
	); err != nil {
		t.Fatalf("valid hardware-bound activation rejected: %v", err)
	}
}

func TestCoverageControllerAndMemoryStoreBranches(t *testing.T) {
	now := fixedSafeDepClock()
	if result, err := (*Controller)(nil).Gate(context.Background(), GateRequest{}); err != nil || !result.DispatchAllowed {
		t.Fatalf("nil controller gate = %+v err=%v", result, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewController(ControllerConfig{Clock: fixedSafeDepClock}).Gate(canceled, GateRequest{Signal: Signal{HazardCode: contracts.HazardDeadManExpired}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled gate, got %v", err)
	}
	controller := NewController(ControllerConfig{Clock: fixedSafeDepClock})
	clockInactive, err := controller.Gate(context.Background(), GateRequest{Signal: Signal{HazardCode: contracts.HazardCredentialExpired, ActiveClock: false}})
	if err != nil {
		t.Fatalf("clock inactive gate errored: %v", err)
	}
	if clockInactive.DispatchAllowed || clockInactive.ProofGraphRef == "" {
		t.Fatalf("clock inactive gate should deny with evidence: %+v", clockInactive)
	}

	store := NewMemoryContinuityStore()
	checkpoint := validContinuityCheckpoint(now, "restore-nonce", 1)
	if _, err := store.AppendCheckpoint(context.Background(), contracts.ContinuityCheckpoint{CheckpointID: "missing-nonce"}); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected missing nonce error, got %v", err)
	}
	state, err := store.AppendCheckpoint(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("append checkpoint: %v", err)
	}
	next := validContinuityCheckpoint(now, "bad-latest", 2)
	next.LatestAcceptedCheckpointHash = "sha256:wrong"
	if _, err := store.AppendCheckpoint(context.Background(), next); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected latest mismatch, got %v", err)
	}
	if err := store.StoreActivation(context.Background(), contracts.ActivationReceipt{}); err == nil {
		t.Fatal("expected missing activation id error")
	}
	receipt := contracts.ActivationReceipt{ActivationID: "activation-1", CapsuleID: "capsule-1", ExpiresAt: now.Add(time.Hour)}
	if err := store.StoreActivation(context.Background(), receipt); err != nil {
		t.Fatalf("store activation: %v", err)
	}
	got, ok, err := store.GetActivation(context.Background(), receipt.ActivationID)
	if err != nil || !ok || got.ActivationID != receipt.ActivationID {
		t.Fatalf("get activation got=%+v ok=%v err=%v", got, ok, err)
	}
	if err := store.CloseActivation(context.Background(), "missing", checkpoint); err == nil {
		t.Fatal("expected missing close activation error")
	}
	if err := store.CloseActivation(context.Background(), receipt.ActivationID, checkpoint); err != nil {
		t.Fatalf("close activation: %v", err)
	}
	closed, ok, err := store.GetActivation(context.Background(), receipt.ActivationID)
	if err != nil || !ok || closed.ExpiresAt.Equal(receipt.ExpiresAt) {
		t.Fatalf("activation was not closed: %+v ok=%v err=%v", closed, ok, err)
	}

	restoreController := NewController(ControllerConfig{Store: store, Clock: fixedSafeDepClock})
	restoreCheckpoint := validContinuityCheckpoint(now, "restore-nonce-2", 2)
	restoreCheckpoint.LatestAcceptedCheckpointHash = state.CheckpointHash
	if err := restoreController.Restore(context.Background(), receipt.ActivationID, restoreCheckpoint); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := (*Controller)(nil).Restore(context.Background(), "ignored", restoreCheckpoint); err != nil {
		t.Fatalf("nil restore should be no-op: %v", err)
	}

	scopeCapsule := validCapsule(now)
	scopeReq := GateRequest{Action: "credential.rotate.propose", ConnectorID: "github", Capsule: &scopeCapsule}
	if err := validateCapsuleScope(scopeCapsule, scopeReq); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	noActions := scopeCapsule
	noActions.AllowedActions = nil
	if err := validateCapsuleScope(noActions, scopeReq); !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected no action scope error, got %v", err)
	}
	badConnector := scopeCapsule
	if err := validateCapsuleScope(badConnector, GateRequest{Action: "credential.rotate.propose", ConnectorID: "slack"}); !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected connector scope error, got %v", err)
	}
	badDelegation := scopeCapsule
	badDelegation.Delegation.Scope = []string{"other"}
	if err := validateCapsuleScope(badDelegation, scopeReq); !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected delegation scope error, got %v", err)
	}
	if firstScopeHash(contracts.EmergencyDelegationChain{}) != "" {
		t.Fatal("empty delegation should not have scope hash")
	}

	noEvidence := &Controller{clock: fixedSafeDepClock}
	refs, err := noEvidence.record(context.Background(), EvidenceEvent{Type: "none"})
	if err != nil || refs != (EvidenceRefs{}) {
		t.Fatalf("nil evidence refs=%+v err=%v", refs, err)
	}
	if !(*Controller)(nil).now().After(time.Time{}) {
		t.Fatal("nil controller now should return current time")
	}
	result := GateResult{}
	noEvidence.attachEvidence(context.Background(), &result, "safedep.coverage", &checkpoint, &scopeCapsule)
	if result.ProofGraphRef != "" {
		t.Fatalf("nil evidence attach should not set refs: %+v", result)
	}
	if _, err := (HashEvidenceSink{}).RecordSafeDepEvent(canceled, EvidenceEvent{Type: "ctx"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled evidence sink, got %v", err)
	}
	if _, err := store.AppendCheckpoint(context.Background(), checkpoint); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected memory nonce replay, got %v", err)
	}
	rollback := validContinuityCheckpoint(now, "rollback-nonce", 1)
	if _, err := store.AppendCheckpoint(context.Background(), rollback); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected memory rollback rejection, got %v", err)
	}
	if id := activationID(scopeCapsule, checkpoint); !strings.HasPrefix(id, "safedep-act-") {
		t.Fatalf("unexpected activation id: %s", id)
	}
}

func TestCoverageControllerActivationAndRestoreErrors(t *testing.T) {
	now := fixedSafeDepClock()
	capsule := validCapsule(now)
	request := func(nonce string) GateRequest {
		return GateRequest{
			Signal:      Signal{HazardCode: contracts.HazardCredentialExpired, ActiveClock: true},
			Checkpoint:  validContinuityCheckpoint(now, nonce, 1),
			Capsule:     &capsule,
			Action:      "credential.rotate.propose",
			ConnectorID: "github",
		}
	}
	if _, err := NewController(ControllerConfig{Clock: fixedSafeDepClock}).Gate(context.Background(), GateRequest{
		Signal: Signal{HazardCode: contracts.HazardCredentialExpired, ActiveClock: true},
	}); !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected missing capsule rejection, got %v", err)
	}

	latestErr := errors.New("latest failed")
	if _, err := NewController(ControllerConfig{
		Store: &coverageContinuityStore{latestErr: latestErr},
		Clock: fixedSafeDepClock,
	}).Gate(context.Background(), request("latest-error")); !errors.Is(err, latestErr) {
		t.Fatalf("expected latest error, got %v", err)
	}

	appendErr := errors.New("append failed")
	if _, err := NewController(ControllerConfig{
		Store: &coverageContinuityStore{appendErr: appendErr},
		Clock: fixedSafeDepClock,
	}).Gate(context.Background(), request("append-error")); !errors.Is(err, appendErr) {
		t.Fatalf("expected append error, got %v", err)
	}

	evidenceErr := errors.New("evidence failed")
	if _, err := NewController(ControllerConfig{
		Store:    &coverageContinuityStore{},
		Evidence: &coverageEvidenceSink{err: evidenceErr},
		Clock:    fixedSafeDepClock,
	}).Gate(context.Background(), request("evidence-error")); !errors.Is(err, evidenceErr) {
		t.Fatalf("expected evidence error, got %v", err)
	}

	signerErr := errors.New("signer failed")
	if _, err := NewController(ControllerConfig{
		Store:    &coverageContinuityStore{},
		Evidence: &coverageEvidenceSink{},
		Signer:   coverageReceiptSigner{err: signerErr},
		Clock:    fixedSafeDepClock,
	}).Gate(context.Background(), request("signer-error")); !errors.Is(err, signerErr) {
		t.Fatalf("expected signer error, got %v", err)
	}

	storeErr := errors.New("store activation failed")
	if _, err := NewController(ControllerConfig{
		Store:    &coverageContinuityStore{storeErr: storeErr},
		Evidence: &coverageEvidenceSink{},
		Clock:    fixedSafeDepClock,
	}).Gate(context.Background(), request("store-error")); !errors.Is(err, storeErr) {
		t.Fatalf("expected store activation error, got %v", err)
	}

	successStore := &coverageContinuityStore{}
	signed, err := NewController(ControllerConfig{
		Store:    successStore,
		Evidence: &coverageEvidenceSink{},
		Signer:   coverageReceiptSigner{sig: "receipt-signature"},
		Clock:    fixedSafeDepClock,
	}).Gate(context.Background(), request("signed-success"))
	if err != nil {
		t.Fatalf("signed activation rejected: %v", err)
	}
	if !signed.DispatchAllowed || signed.ActivationReceipt == nil || signed.ActivationReceipt.Signature != "receipt-signature" {
		t.Fatalf("signed activation missing receipt signature: %+v", signed)
	}
	if len(successStore.stored) != 1 || successStore.stored[0].Signature != "receipt-signature" {
		t.Fatalf("signed activation was not stored: %+v", successStore.stored)
	}

	restoreLatestErr := errors.New("restore latest failed")
	if err := NewController(ControllerConfig{
		Store: &coverageContinuityStore{latestErr: restoreLatestErr},
		Clock: fixedSafeDepClock,
	}).Restore(context.Background(), "activation", validContinuityCheckpoint(now, "restore-latest", 1)); !errors.Is(err, restoreLatestErr) {
		t.Fatalf("expected restore latest error, got %v", err)
	}
	restoreAppendErr := errors.New("restore append failed")
	if err := NewController(ControllerConfig{
		Store: &coverageContinuityStore{appendErr: restoreAppendErr},
		Clock: fixedSafeDepClock,
	}).Restore(context.Background(), "activation", validContinuityCheckpoint(now, "restore-append", 1)); !errors.Is(err, restoreAppendErr) {
		t.Fatalf("expected restore append error, got %v", err)
	}
	restoreCloseErr := errors.New("restore close failed")
	if err := NewController(ControllerConfig{
		Store: &coverageContinuityStore{closeErr: restoreCloseErr},
		Clock: fixedSafeDepClock,
	}).Restore(context.Background(), "activation", validContinuityCheckpoint(now, "restore-close", 1)); !errors.Is(err, restoreCloseErr) {
		t.Fatalf("expected restore close error, got %v", err)
	}
	if err := NewController(ControllerConfig{
		Store: &coverageContinuityStore{},
		Clock: fixedSafeDepClock,
	}).Restore(context.Background(), "activation", contracts.ContinuityCheckpoint{CheckpointID: "missing-nonce"}); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected restore continuity error, got %v", err)
	}
}

func TestCoverageSQLiteContinuityStoreBranches(t *testing.T) {
	if _, err := NewSQLiteContinuityStore(nil); err == nil {
		t.Fatal("expected nil sqlite db error")
	}
	closedDB, err := sql.Open("sqlite", "file:safedep-closed-init?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := closedDB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteContinuityStore(closedDB); err == nil {
		t.Fatal("expected closed sqlite db init error")
	}
	db, err := sql.Open("sqlite", "file:safedep-coverage?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLiteContinuityStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if latest, ok, err := store.Latest(context.Background()); err != nil || ok || latest.CheckpointID != "" {
		t.Fatalf("empty latest latest=%+v ok=%v err=%v", latest, ok, err)
	}
	now := fixedSafeDepClock()
	checkpoint := validContinuityCheckpoint(now, "sqlite-nonce", 1)
	state, err := store.AppendCheckpoint(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("append sqlite checkpoint: %v", err)
	}
	latest, ok, err := store.Latest(context.Background())
	if err != nil || !ok || latest.CheckpointHash != state.CheckpointHash {
		t.Fatalf("latest sqlite latest=%+v ok=%v err=%v", latest, ok, err)
	}
	receipt := contracts.ActivationReceipt{
		ActivationID: "sqlite-activation",
		CapsuleID:    "capsule-1",
		ApertureID:   "aperture-1",
		HazardCode:   contracts.HazardCredentialExpired,
		State:        contracts.SafeDepDegradedNarrowing,
		PolicyEpoch:  7,
		ExpiresAt:    now.Add(time.Hour),
	}
	if err := store.StoreActivation(context.Background(), receipt); err != nil {
		t.Fatalf("store sqlite activation: %v", err)
	}
	got, ok, err := store.GetActivation(context.Background(), receipt.ActivationID)
	if err != nil || !ok || got.ActivationID != receipt.ActivationID {
		t.Fatalf("get sqlite activation got=%+v ok=%v err=%v", got, ok, err)
	}
	if got, ok, err := store.GetActivation(context.Background(), "missing"); err != nil || ok || got.ActivationID != "" {
		t.Fatalf("missing sqlite activation got=%+v ok=%v err=%v", got, ok, err)
	}
	if err := store.CloseActivation(context.Background(), "missing", checkpoint); err == nil {
		t.Fatal("expected missing sqlite activation close error")
	}
	if err := store.CloseActivation(context.Background(), receipt.ActivationID, checkpoint); err != nil {
		t.Fatalf("close sqlite activation: %v", err)
	}
	if formatTime(time.Time{}) != "" || !strings.Contains(formatTime(now), "2026-05-24") {
		t.Fatal("formatTime returned unexpected values")
	}

	closedRuntimeDB, err := sql.Open("sqlite", "file:safedep-closed-runtime?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	closedRuntimeStore, err := NewSQLiteContinuityStore(closedRuntimeDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := closedRuntimeDB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := closedRuntimeStore.Latest(context.Background()); err == nil {
		t.Fatal("expected latest on closed sqlite db to fail")
	}
	if _, err := closedRuntimeStore.AppendCheckpoint(context.Background(), validContinuityCheckpoint(now, "closed-append", 1)); err == nil {
		t.Fatal("expected append on closed sqlite db to fail")
	}
	if err := closedRuntimeStore.StoreActivation(context.Background(), receipt); err == nil {
		t.Fatal("expected store activation on closed sqlite db to fail")
	}
	if _, _, err := closedRuntimeStore.GetActivation(context.Background(), receipt.ActivationID); err == nil {
		t.Fatal("expected get activation on closed sqlite db to fail")
	}
	if err := closedRuntimeStore.CloseActivation(context.Background(), receipt.ActivationID, checkpoint); err == nil {
		t.Fatal("expected close activation on closed sqlite db to fail")
	}
}

func validContinuityCheckpoint(now time.Time, nonce string, sequence uint64) contracts.ContinuityCheckpoint {
	return contracts.ContinuityCheckpoint{
		CheckpointID:                 fmt.Sprintf("cp-%s", nonce),
		OrgGenomeHash:                "sha256:org",
		PolicyHash:                   "sha256:policy",
		PolicyEpoch:                  7,
		HazardSequence:               sequence,
		LamportClock:                 sequence,
		DeadManWindowID:              "dm-1",
		DeadManActive:                true,
		LatestAcceptedCheckpointHash: "sha256:last",
		Nonce:                        nonce,
		AttestedTime:                 now,
		ExpiresAt:                    now.Add(time.Minute),
	}
}

func coverageActivationExpectation(now time.Time) ActivationExpectation {
	return ActivationExpectation{
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
}

func coverageHardwareBoundCeremony(t *testing.T, now time.Time) (contracts.HardwareCeremonyTranscript, map[string]contracts.ThresholdSignature) {
	t.Helper()
	ceremony := validCapsule(now).Ceremony
	authorized := make(map[string]contracts.ThresholdSignature, len(ceremony.Approvals))
	for i, approval := range ceremony.Approvals {
		signer, err := helmcrypto.NewEd25519Signer(approval.SignerID + "-hardware")
		if err != nil {
			t.Fatalf("new hardware signer: %v", err)
		}
		signature, err := signer.Sign([]byte(hardwareApprovalPayload(ceremony.TranscriptHash, approval)))
		if err != nil {
			t.Fatalf("sign hardware approval: %v", err)
		}
		ceremony.Approvals[i].AssertionSignature = signature
		authorized[approval.SignerID] = contracts.ThresholdSignature{
			SignerID:  approval.SignerID,
			Role:      approval.Role,
			DeviceID:  approval.DeviceID,
			KeyID:     approval.SignerID + "-hardware",
			PublicKey: signer.PublicKey(),
		}
	}
	return ceremony, authorized
}
