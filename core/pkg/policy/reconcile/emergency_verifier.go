package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
)

type SafeDepEmergencyVerifier struct {
	Now                    func() time.Time
	RequiredQuorum         int
	AuthorizedSigners      map[string]contracts.ThresholdSignature
	RequireHardwareBound   bool
	RequireDistinctRoles   bool
	RequireTransparency    bool
	MaxTTL                 time.Duration
	ExpectedOrgGenomeHash  string
	ExpectedCPIHash        string
	ExpectedProviderHash   string
	ExpectedCredentialHash string
	ExpectedVerifierHash   string
}

func (v SafeDepEmergencyVerifier) VerifyEmergencyCapsule(ctx context.Context, head PolicyHead, capsule contracts.EmergencyCapsule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	expected := safedep.CapsuleExpectation{
		HazardCode:             capsule.HazardCode,
		State:                  contracts.SafeDepDegradedNarrowing,
		OrgGenomeHash:          v.ExpectedOrgGenomeHash,
		PolicyEpoch:            head.PolicyEpoch,
		PolicyHash:             head.PolicyHash,
		P0CeilingsHash:         head.P0CeilingsHash,
		P1BundleHash:           head.P1BundleHash,
		CPIHash:                v.ExpectedCPIHash,
		ProviderRegistryHash:   v.ExpectedProviderHash,
		CredentialRegistryHash: v.ExpectedCredentialHash,
		VerifierProfileHash:    v.ExpectedVerifierHash,
		Now:                    now,
		MaxTTL:                 v.MaxTTL,
		RequireTransparency:    v.RequireTransparency,
	}
	if expected.OrgGenomeHash == "" {
		expected.OrgGenomeHash = capsule.OrgGenomeHash
	}
	if expected.CPIHash == "" {
		expected.CPIHash = capsule.CPIHash
	}
	if expected.ProviderRegistryHash == "" {
		expected.ProviderRegistryHash = capsule.ProviderRegistryHash
	}
	if expected.CredentialRegistryHash == "" {
		expected.CredentialRegistryHash = capsule.CredentialRegistryHash
	}
	if expected.VerifierProfileHash == "" {
		expected.VerifierProfileHash = capsule.VerifierProfileHash
	}
	if err := safedep.ValidateEmergencyCapsule(capsule, expected); err != nil {
		return err
	}
	quorum := v.RequiredQuorum
	if quorum == 0 {
		quorum = 3
	}
	if err := safedep.ValidateHardwareCeremony(capsule.Ceremony, safedep.CeremonyExpectation{
		AuthorizedSigners:    v.AuthorizedSigners,
		RequiredQuorum:       quorum,
		PolicyEpoch:          head.PolicyEpoch,
		Now:                  now,
		RequireHardwareBound: v.RequireHardwareBound,
		RequireDistinctRoles: v.RequireDistinctRoles,
	}); err != nil {
		return err
	}
	if err := safedep.ValidateEmergencyDelegation(capsule.Delegation, now); err != nil {
		return err
	}
	if err := safedep.ValidateAttestationResult(capsule.Attestation, safedep.AttestationExpectation{
		ProfileID:       capsule.Attestation.ProfileID,
		PolicyHash:      capsule.Attestation.PolicyHash,
		Nonce:           capsule.Attestation.Nonce,
		MeasurementHash: capsule.Attestation.MeasurementHash,
		Now:             now,
	}); err != nil {
		return err
	}
	if len(capsule.AllowedActions) == 0 {
		return fmt.Errorf("%w: emergency capsule must predeclare narrowed actions", safedep.ErrEmergencyCapsuleInvalid)
	}
	return nil
}
