package certification

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/vcredentials"
)

// BadgeIssuer creates W3C Verifiable Credential badges for certified agents.
//
// It combines the certification Framework (which evaluates agent scores) with
// the vcredentials Issuer (which produces signed W3C VCs). The result is a
// cryptographically verifiable "HELM Verified Agent" badge that encodes the
// certification level as a capability claim.
type BadgeIssuer struct {
	vcIssuer  *vcredentials.Issuer
	framework *Framework
}

// NewBadgeIssuer creates a BadgeIssuer bound to a VC issuer and certification framework.
func NewBadgeIssuer(vcIssuer *vcredentials.Issuer, framework *Framework) *BadgeIssuer {
	return &BadgeIssuer{
		vcIssuer:  vcIssuer,
		framework: framework,
	}
}

// IssueBadge evaluates an agent against the certification framework and, if the
// agent qualifies for any certification level, issues a signed W3C Verifiable
// Credential badge.
//
// The badge encodes the certification level as a verified capability claim
// (action: "HELM_CERTIFIED_{LEVEL}") on the agent's DID.
//
// Returns:
//   - vc: the signed Verifiable Credential (nil if the agent did not pass)
//   - result: the certification evaluation result (always non-nil)
//   - err: only non-nil if VC issuance itself fails (not if the agent fails certification)
func (b *BadgeIssuer) IssueBadge(agentID, agentDID string, scores CertificationScores, validDuration time.Duration) (*vcredentials.VerifiableCredential, *CertificationResult, error) {
	result := b.framework.Evaluate(agentID, scores)

	if !result.Passed {
		return nil, result, nil
	}

	now := b.framework.clock()

	subject := vcredentials.AgentCapabilitySubject{
		ID:        agentDID,
		AgentName: agentID,
		Capabilities: []vcredentials.CapabilityClaim{
			{
				Action:     fmt.Sprintf("HELM_CERTIFIED_%s", result.Level),
				Resource:   "helm:certification:badge",
				Verified:   true,
				VerifiedAt: now,
			},
		},
		Constraints: vcredentials.CapabilityConstraints{
			TrustFloor:    scores.TrustScore,
			PrivilegeTier: string(result.Level),
		},
	}

	credID := fmt.Sprintf("urn:helm:certification:%s:%s", agentID, result.ResultID)

	vc, err := b.vcIssuer.Issue(credID, subject, validDuration)
	if err != nil {
		return nil, result, fmt.Errorf("issuing badge VC: %w", err)
	}

	return vc, result, nil
}
