// Package safedep validates HELM's continuity-gated emergency release plane.
package safedep

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

var (
	ErrContinuityStale           = errors.New("safe dep: continuity stale")
	ErrEmergencyCapsuleInvalid   = errors.New("safe dep: emergency capsule invalid")
	ErrHardwareQuorumUnbound     = errors.New("safe dep: hardware quorum unbound")
	ErrAttestationResultRequired = errors.New("safe dep: attestation result required")
	ErrDevFallbackPresent        = errors.New("safe dep: dev fallback present")
)

type ContinuityExpectation struct {
	PolicyEpoch                  uint64
	PolicyHash                   string
	OrgGenomeHash                string
	MinHazardSequence            uint64
	LatestAcceptedCheckpointHash string
	RequireDeadManActive         bool
	Now                          time.Time
	MaxClockSkew                 time.Duration
}

type CapsuleExpectation struct {
	HazardCode             contracts.SafeDepHazardCode
	State                  contracts.SafeDepState
	OrgGenomeHash          string
	PolicyEpoch            uint64
	PolicyHash             string
	P0CeilingsHash         string
	P1BundleHash           string
	CPIHash                string
	ProviderRegistryHash   string
	CredentialRegistryHash string
	VerifierProfileHash    string
	PreviousCapsuleHash    string
	Now                    time.Time
	MinTTL                 time.Duration
	MaxTTL                 time.Duration
	RequireTransparency    bool
}

type CeremonyExpectation struct {
	AuthorizedSigners    map[string]contracts.ThresholdSignature
	RequiredQuorum       int
	PolicyEpoch          uint64
	Now                  time.Time
	RequireDistinctRoles bool
	RequireHardwareBound bool
}

type AttestationExpectation struct {
	ProfileID       string
	PolicyHash      string
	Nonce           string
	MeasurementHash string
	Now             time.Time
}

type ActivationExpectation struct {
	Continuity  ContinuityExpectation
	Capsule     CapsuleExpectation
	Ceremony    CeremonyExpectation
	Attestation AttestationExpectation
	Now         time.Time
}

type NonceStore interface {
	Consume(nonce string) bool
}

type MemoryNonceStore struct {
	mu     sync.Mutex
	nonces map[string]struct{}
}

func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{nonces: make(map[string]struct{})}
}

func (s *MemoryNonceStore) Consume(nonce string) bool {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nonces[nonce]; ok {
		return false
	}
	s.nonces[nonce] = struct{}{}
	return true
}

func ClassifyHazard(hazard contracts.SafeDepHazardCode, activeClock bool, highRiskLane bool) contracts.HazardClassification {
	classification := contracts.HazardClassification{
		HazardCode:   hazard,
		ActiveClock:  activeClock,
		HighRiskLane: highRiskLane,
	}
	switch hazard {
	case contracts.HazardDeadManExpired, contracts.HazardContinuityMissing:
		classification.State = contracts.SafeDepTerminalFreeze
		classification.ReasonCode = contracts.ReasonSafeDepTerminalFreeze
	case contracts.HazardEnginePinMismatch, contracts.HazardAttestationFailure, contracts.HazardVerifierProfileDrift:
		classification.State = contracts.SafeDepDeprecatedReadonly
		classification.ReasonCode = contracts.ReasonSafeDepDeprecatedReadonly
	case contracts.HazardCredentialExpired, contracts.HazardAPIRot, contracts.HazardNetworkPartition, contracts.HazardTransparencyLogOutage, contracts.HazardStalePolicyFeed:
		classification.State = contracts.SafeDepDegradedNarrowing
		classification.ReasonCode = contracts.ReasonSafeDepDegradedNarrowing
		classification.ActivationAllowed = activeClock
	default:
		classification.State = contracts.SafeDepTerminalFreeze
		classification.ReasonCode = contracts.ReasonSafeDepTerminalFreeze
	}
	if classification.State != contracts.SafeDepDegradedNarrowing {
		classification.ActivationAllowed = false
	}
	return classification
}

func ValidateAndConsumeContinuity(cp contracts.ContinuityCheckpoint, expected ContinuityExpectation, nonces NonceStore) error {
	if err := ValidateContinuity(cp, expected); err != nil {
		return err
	}
	if nonces == nil || !nonces.Consume(cp.Nonce) {
		return fmt.Errorf("%w: nonce replay or missing nonce store", ErrContinuityStale)
	}
	return nil
}

func ValidateActivation(cp contracts.ContinuityCheckpoint, capsule contracts.EmergencyCapsule, posture contracts.DevFallbackPosture, expected ActivationExpectation, nonces NonceStore) error {
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := ValidateDevFallbackPosture(posture); err != nil {
		return err
	}
	expected.Continuity.Now = defaultTime(expected.Continuity.Now, now)
	if err := ValidateAndConsumeContinuity(cp, expected.Continuity, nonces); err != nil {
		return err
	}
	expected.Capsule.Now = defaultTime(expected.Capsule.Now, now)
	if err := ValidateEmergencyCapsule(capsule, expected.Capsule); err != nil {
		return err
	}
	expected.Ceremony.Now = defaultTime(expected.Ceremony.Now, now)
	if err := ValidateHardwareCeremony(capsule.Ceremony, expected.Ceremony); err != nil {
		return err
	}
	if err := ValidateEmergencyDelegation(capsule.Delegation, now); err != nil {
		return err
	}
	expected.Attestation.Now = defaultTime(expected.Attestation.Now, now)
	if err := ValidateAttestationResult(capsule.Attestation, expected.Attestation); err != nil {
		return err
	}
	return nil
}

func ValidateContinuity(cp contracts.ContinuityCheckpoint, expected ContinuityExpectation) error {
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(cp.CheckpointID) == "" || strings.TrimSpace(cp.Nonce) == "" {
		return fmt.Errorf("%w: checkpoint id and nonce are required", ErrContinuityStale)
	}
	if expected.PolicyEpoch != 0 && cp.PolicyEpoch != expected.PolicyEpoch {
		return fmt.Errorf("%w: policy epoch %d does not match expected %d", ErrContinuityStale, cp.PolicyEpoch, expected.PolicyEpoch)
	}
	if expected.PolicyHash != "" && cp.PolicyHash != expected.PolicyHash {
		return fmt.Errorf("%w: policy hash mismatch", ErrContinuityStale)
	}
	if expected.OrgGenomeHash != "" && cp.OrgGenomeHash != expected.OrgGenomeHash {
		return fmt.Errorf("%w: org genome hash mismatch", ErrContinuityStale)
	}
	if cp.HazardSequence <= expected.MinHazardSequence {
		return fmt.Errorf("%w: hazard sequence %d is not newer than %d", ErrContinuityStale, cp.HazardSequence, expected.MinHazardSequence)
	}
	if expected.LatestAcceptedCheckpointHash != "" && cp.LatestAcceptedCheckpointHash != expected.LatestAcceptedCheckpointHash {
		return fmt.Errorf("%w: latest accepted checkpoint hash mismatch", ErrContinuityStale)
	}
	if expected.RequireDeadManActive && !cp.DeadManActive {
		return fmt.Errorf("%w: dead-man window is not active", ErrContinuityStale)
	}
	if cp.AttestedTime.IsZero() {
		return fmt.Errorf("%w: attested time is required", ErrContinuityStale)
	}
	maxSkew := expected.MaxClockSkew
	if maxSkew == 0 {
		maxSkew = 2 * time.Minute
	}
	if cp.AttestedTime.After(now.Add(maxSkew)) {
		return fmt.Errorf("%w: attested time is in the future", ErrContinuityStale)
	}
	if !cp.ExpiresAt.IsZero() && !now.Before(cp.ExpiresAt) {
		return fmt.Errorf("%w: checkpoint expired", ErrContinuityStale)
	}
	return nil
}

func ValidateEmergencyCapsule(c contracts.EmergencyCapsule, expected CapsuleExpectation) error {
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(c.CapsuleID) == "" || strings.TrimSpace(c.ApertureID) == "" || c.Version == 0 {
		return fmt.Errorf("%w: capsule id, aperture id, and version are required", ErrEmergencyCapsuleInvalid)
	}
	if c.State != contracts.SafeDepDegradedNarrowing {
		return fmt.Errorf("%w: emergency capsules may only activate degraded narrowing", ErrEmergencyCapsuleInvalid)
	}
	if expected.State != "" && c.State != expected.State {
		return fmt.Errorf("%w: state mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.HazardCode != "" && c.HazardCode != expected.HazardCode {
		return fmt.Errorf("%w: hazard mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.OrgGenomeHash != "" && c.OrgGenomeHash != expected.OrgGenomeHash {
		return fmt.Errorf("%w: org genome hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.PolicyEpoch != 0 && c.PolicyEpoch != expected.PolicyEpoch {
		return fmt.Errorf("%w: policy epoch mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.PolicyHash != "" && c.PolicyHash != expected.PolicyHash {
		return fmt.Errorf("%w: policy hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.P0CeilingsHash != "" && c.P0CeilingsHash != expected.P0CeilingsHash {
		return fmt.Errorf("%w: P0 hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.P1BundleHash != "" && c.P1BundleHash != expected.P1BundleHash {
		return fmt.Errorf("%w: P1 hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.CPIHash != "" && c.CPIHash != expected.CPIHash {
		return fmt.Errorf("%w: CPI hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.ProviderRegistryHash != "" && c.ProviderRegistryHash != expected.ProviderRegistryHash {
		return fmt.Errorf("%w: provider registry hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.CredentialRegistryHash != "" && c.CredentialRegistryHash != expected.CredentialRegistryHash {
		return fmt.Errorf("%w: credential registry hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.VerifierProfileHash != "" && c.VerifierProfileHash != expected.VerifierProfileHash {
		return fmt.Errorf("%w: verifier profile hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if expected.PreviousCapsuleHash != "" && c.PredecessorHash != expected.PreviousCapsuleHash {
		return fmt.Errorf("%w: predecessor hash mismatch", ErrEmergencyCapsuleInvalid)
	}
	if strings.TrimSpace(c.SubsetProofHash) == "" || strings.TrimSpace(c.SubsetProofKind) == "" {
		return fmt.Errorf("%w: subset proof is required", ErrEmergencyCapsuleInvalid)
	}
	if c.TTLSeconds <= 0 {
		return fmt.Errorf("%w: TTL must be positive", ErrEmergencyCapsuleInvalid)
	}
	ttl := time.Duration(c.TTLSeconds) * time.Second
	if expected.MinTTL > 0 && ttl < expected.MinTTL {
		return fmt.Errorf("%w: TTL shorter than minimum", ErrEmergencyCapsuleInvalid)
	}
	if expected.MaxTTL > 0 && ttl > expected.MaxTTL {
		return fmt.Errorf("%w: TTL exceeds maximum", ErrEmergencyCapsuleInvalid)
	}
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore) {
		return fmt.Errorf("%w: capsule not yet valid", ErrEmergencyCapsuleInvalid)
	}
	if c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) {
		return fmt.Errorf("%w: capsule expired", ErrEmergencyCapsuleInvalid)
	}
	if len(c.Signatures) == 0 {
		return fmt.Errorf("%w: threshold signatures are required", ErrEmergencyCapsuleInvalid)
	}
	if expected.RequireTransparency && c.Transparency.Deferred && c.Transparency.DeferredUntil.IsZero() {
		return fmt.Errorf("%w: deferred transparency requires a deadline", ErrEmergencyCapsuleInvalid)
	}
	return nil
}

func ValidateHardwareCeremony(c contracts.HardwareCeremonyTranscript, expected CeremonyExpectation) error {
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	required := expected.RequiredQuorum
	if required == 0 {
		required = c.RequiredQuorum
	}
	if required < 1 {
		return fmt.Errorf("%w: quorum is required", ErrHardwareQuorumUnbound)
	}
	if c.EnrolledSignerCount > 0 && required > c.EnrolledSignerCount {
		return fmt.Errorf("%w: quorum exceeds enrolled signer count", ErrHardwareQuorumUnbound)
	}
	if strings.TrimSpace(c.CeremonyID) == "" || strings.TrimSpace(c.TranscriptHash) == "" {
		return fmt.Errorf("%w: ceremony id and transcript hash are required", ErrHardwareQuorumUnbound)
	}
	if !c.VetoUntil.IsZero() && now.Before(c.VetoUntil) {
		return fmt.Errorf("%w: veto window is still open", ErrHardwareQuorumUnbound)
	}
	if !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt) {
		return fmt.Errorf("%w: ceremony expired", ErrHardwareQuorumUnbound)
	}
	seenSigners := map[string]struct{}{}
	seenDevices := map[string]struct{}{}
	seenRoles := map[string]struct{}{}
	valid := 0
	for _, approval := range c.Approvals {
		signerID := strings.TrimSpace(approval.SignerID)
		deviceID := strings.TrimSpace(approval.DeviceID)
		if signerID == "" || deviceID == "" || strings.TrimSpace(approval.AssertionHash) == "" {
			return fmt.Errorf("%w: approval signer, device, and assertion are required", ErrHardwareQuorumUnbound)
		}
		if _, ok := seenSigners[signerID]; ok {
			return fmt.Errorf("%w: duplicate signer %s", ErrHardwareQuorumUnbound, signerID)
		}
		if _, ok := seenDevices[deviceID]; ok {
			return fmt.Errorf("%w: duplicate device %s", ErrHardwareQuorumUnbound, deviceID)
		}
		if expected.RequireDistinctRoles && strings.TrimSpace(approval.Role) != "" {
			role := strings.TrimSpace(approval.Role)
			if _, ok := seenRoles[role]; ok {
				return fmt.Errorf("%w: duplicate role %s", ErrHardwareQuorumUnbound, role)
			}
			seenRoles[role] = struct{}{}
		}
		if len(expected.AuthorizedSigners) > 0 {
			authorized, ok := expected.AuthorizedSigners[signerID]
			if !ok {
				return fmt.Errorf("%w: unauthorized signer %s", ErrHardwareQuorumUnbound, signerID)
			}
			if authorized.Role != "" && approval.Role != authorized.Role {
				return fmt.Errorf("%w: signer role mismatch for %s", ErrHardwareQuorumUnbound, signerID)
			}
			if authorized.DeviceID != "" && approval.DeviceID != authorized.DeviceID {
				return fmt.Errorf("%w: signer device mismatch for %s", ErrHardwareQuorumUnbound, signerID)
			}
			if authorized.RevokedAtEpoch > 0 && expected.PolicyEpoch >= authorized.RevokedAtEpoch {
				return fmt.Errorf("%w: signer %s revoked", ErrHardwareQuorumUnbound, signerID)
			}
			if expected.RequireHardwareBound || strings.TrimSpace(authorized.PublicKey) != "" {
				if err := verifyHardwareApproval(c.TranscriptHash, approval, authorized); err != nil {
					return err
				}
			}
		} else if expected.RequireHardwareBound {
			return fmt.Errorf("%w: hardware-bound ceremony requires an authorized signer registry", ErrHardwareQuorumUnbound)
		}
		if approval.RevokedAtEpoch > 0 && expected.PolicyEpoch >= approval.RevokedAtEpoch {
			return fmt.Errorf("%w: approval signer %s revoked", ErrHardwareQuorumUnbound, signerID)
		}
		seenSigners[signerID] = struct{}{}
		seenDevices[deviceID] = struct{}{}
		valid++
	}
	if valid < required {
		return fmt.Errorf("%w: quorum %d of %d not met", ErrHardwareQuorumUnbound, valid, required)
	}
	return nil
}

func verifyHardwareApproval(transcriptHash string, approval contracts.HardwareApproval, authorized contracts.ThresholdSignature) error {
	publicKey := strings.TrimSpace(authorized.PublicKey)
	if publicKey == "" {
		return fmt.Errorf("%w: signer %s is not hardware-bound to a public key", ErrHardwareQuorumUnbound, approval.SignerID)
	}
	signature := strings.TrimSpace(approval.AssertionSignature)
	if signature == "" {
		signature = strings.TrimSpace(authorized.Signature)
	}
	if signature == "" {
		return fmt.Errorf("%w: signer %s missing hardware assertion signature", ErrHardwareQuorumUnbound, approval.SignerID)
	}
	payload := hardwareApprovalPayload(transcriptHash, approval)
	ok, err := helmcrypto.Verify(publicKey, signature, []byte(payload))
	if err != nil {
		return fmt.Errorf("%w: hardware assertion verification failed for %s: %v", ErrHardwareQuorumUnbound, approval.SignerID, err)
	}
	if !ok {
		return fmt.Errorf("%w: hardware assertion signature invalid for %s", ErrHardwareQuorumUnbound, approval.SignerID)
	}
	return nil
}

func hardwareApprovalPayload(transcriptHash string, approval contracts.HardwareApproval) string {
	return strings.Join([]string{
		strings.TrimSpace(transcriptHash),
		strings.TrimSpace(approval.SignerID),
		strings.TrimSpace(approval.Role),
		strings.TrimSpace(approval.DeviceID),
		strings.TrimSpace(approval.AssertionHash),
	}, ":")
}

func ValidateEmergencyDelegation(chain contracts.EmergencyDelegationChain, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(chain.SessionID) == "" || strings.TrimSpace(chain.HumanSubjectID) == "" {
		return fmt.Errorf("%w: delegation session and human subject are required", ErrEmergencyCapsuleInvalid)
	}
	if chain.MaxHops < 0 {
		return fmt.Errorf("%w: max hops cannot be negative", ErrEmergencyCapsuleInvalid)
	}
	if len(chain.Hops) > chain.MaxHops {
		return fmt.Errorf("%w: delegation hop limit exceeded", ErrEmergencyCapsuleInvalid)
	}
	if !chain.NotBefore.IsZero() && now.Before(chain.NotBefore) {
		return fmt.Errorf("%w: delegation not yet valid", ErrEmergencyCapsuleInvalid)
	}
	if chain.ExpiresAt.IsZero() || !now.Before(chain.ExpiresAt) {
		return fmt.Errorf("%w: delegation expired", ErrEmergencyCapsuleInvalid)
	}
	for _, hop := range chain.Hops {
		if strings.TrimSpace(hop.IssuerID) == "" || strings.TrimSpace(hop.SubjectID) == "" || strings.TrimSpace(hop.Signature) == "" {
			return fmt.Errorf("%w: delegation hop is incomplete", ErrEmergencyCapsuleInvalid)
		}
	}
	return nil
}

func ValidateAttestationResult(env contracts.AttestationResultEnvelope, expected AttestationExpectation) error {
	now := expected.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if strings.TrimSpace(env.EnvelopeID) == "" || strings.TrimSpace(env.Signature) == "" {
		return fmt.Errorf("%w: signed attestation result is required", ErrAttestationResultRequired)
	}
	if env.Synthetic {
		return fmt.Errorf("%w: synthetic attestation result refused", ErrAttestationResultRequired)
	}
	if expected.ProfileID != "" && env.ProfileID != expected.ProfileID {
		return fmt.Errorf("%w: verifier profile mismatch", ErrAttestationResultRequired)
	}
	if expected.PolicyHash != "" && env.PolicyHash != expected.PolicyHash {
		return fmt.Errorf("%w: appraisal policy hash mismatch", ErrAttestationResultRequired)
	}
	if expected.Nonce != "" && env.Nonce != expected.Nonce {
		return fmt.Errorf("%w: nonce mismatch", ErrAttestationResultRequired)
	}
	if expected.MeasurementHash != "" && env.MeasurementHash != expected.MeasurementHash {
		return fmt.Errorf("%w: measurement mismatch", ErrAttestationResultRequired)
	}
	if env.ExpiresAt.IsZero() || !now.Before(env.ExpiresAt) {
		return fmt.Errorf("%w: attestation result expired", ErrAttestationResultRequired)
	}
	if strings.TrimSpace(env.TrustTier) == "" || strings.EqualFold(env.TrustTier, "unverified") {
		return fmt.Errorf("%w: attestation result is not verified", ErrAttestationResultRequired)
	}
	return nil
}

func ValidateDevFallbackPosture(posture contracts.DevFallbackPosture) error {
	switch {
	case posture.AuditMode:
		return fmt.Errorf("%w: audit mode enabled", ErrDevFallbackPresent)
	case posture.MockAttester:
		return fmt.Errorf("%w: mock attester enabled", ErrDevFallbackPresent)
	case posture.SyntheticNitro:
		return fmt.Errorf("%w: synthetic nitro enabled", ErrDevFallbackPresent)
	case posture.SoftwareHSM:
		return fmt.Errorf("%w: software HSM enabled", ErrDevFallbackPresent)
	case posture.DevBearerAuth:
		return fmt.Errorf("%w: dev bearer auth enabled", ErrDevFallbackPresent)
	case posture.EnvCredentialFallback:
		return fmt.Errorf("%w: env credential fallback enabled", ErrDevFallbackPresent)
	case posture.UnsignedMutableOverlay:
		return fmt.Errorf("%w: unsigned mutable overlay enabled", ErrDevFallbackPresent)
	default:
		return nil
	}
}

func defaultTime(value time.Time, fallback time.Time) time.Time {
	if value.IsZero() {
		return fallback
	}
	return value
}
