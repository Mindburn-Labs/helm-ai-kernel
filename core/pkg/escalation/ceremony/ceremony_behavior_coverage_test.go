package ceremony

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPolicyValues(t *testing.T) {
	p := DefaultPolicy()
	assert.Equal(t, int64(2000), p.MinTimelockMs)
	assert.Equal(t, int64(1000), p.MinHoldMs)
	assert.False(t, p.RequireChallenge)
	assert.Equal(t, "helm:approval:v1", p.DomainSeparation)
}

func TestStrictPolicyValues(t *testing.T) {
	p := StrictPolicy()
	assert.Equal(t, int64(5000), p.MinTimelockMs)
	assert.True(t, p.RequireChallenge)
	assert.Contains(t, p.DomainSeparation, "strict")
}

func TestValidateCeremony_MissingUISummaryHash(t *testing.T) {
	r := ValidateCeremony(DefaultPolicy(), CeremonyRequest{
		TimelockMs: 3000, HoldMs: 2000, Signature: "sig",
	})
	assert.False(t, r.Valid)
	assert.Contains(t, r.Reason, "ui_summary_hash")
}

func TestValidateCeremony_ExactTimelockBoundary(t *testing.T) {
	r := ValidateCeremony(DefaultPolicy(), CeremonyRequest{
		TimelockMs: 2000, HoldMs: 1000, UISummaryHash: "h", Signature: "s",
	})
	assert.True(t, r.Valid)
}

func TestValidateCeremony_ExactHoldBoundary(t *testing.T) {
	r := ValidateCeremony(DefaultPolicy(), CeremonyRequest{
		TimelockMs: 5000, HoldMs: 1000, UISummaryHash: "h", Signature: "s",
	})
	assert.True(t, r.Valid)
}

func TestValidateCeremony_FutureSubmittedAt(t *testing.T) {
	r := ValidateCeremony(DefaultPolicy(), CeremonyRequest{
		TimelockMs: 3000, HoldMs: 2000, UISummaryHash: "h",
		Signature: "s", SubmittedAt: time.Now().Unix() + 9999,
	})
	assert.False(t, r.Valid)
	assert.Contains(t, r.Reason, "future")
}

func TestValidateCeremony_StrictWithOnlyChallengeNoResponse(t *testing.T) {
	r := ValidateCeremony(StrictPolicy(), CeremonyRequest{
		TimelockMs: 6000, HoldMs: 4000, UISummaryHash: "h",
		ChallengeHash: "c", Signature: "s",
	})
	assert.False(t, r.Valid)
	assert.Contains(t, r.Reason, "challenge/response")
}

func TestValidateCeremony_DefaultDoesNotRequireChallenge(t *testing.T) {
	r := ValidateCeremony(DefaultPolicy(), CeremonyRequest{
		TimelockMs: 3000, HoldMs: 2000, UISummaryHash: "h", Signature: "s",
	})
	assert.True(t, r.Valid)
}

func TestHashUISummary_DifferentInputsDifferentHashes(t *testing.T) {
	assert.NotEqual(t, HashUISummary("foo"), HashUISummary("bar"))
}

func TestHashUISummary_Length64Hex(t *testing.T) {
	assert.Len(t, HashUISummary("test"), 64)
}

func TestHashChallenge_Deterministic(t *testing.T) {
	assert.Equal(t, HashChallenge("x"), HashChallenge("x"))
}

func TestHashChallenge_EmptyInput(t *testing.T) {
	h := HashChallenge("")
	assert.Len(t, h, 64)
}

func TestDeriveGenesisChallenge_DifferentBindings(t *testing.T) {
	b1 := contracts.GenesisApprovalBinding{PolicyGenesisHash: "a", MirrorTextHash: "b", ImpactReportHash: "c", P0CeilingHash: "d"}
	b2 := contracts.GenesisApprovalBinding{PolicyGenesisHash: "x", MirrorTextHash: "b", ImpactReportHash: "c", P0CeilingHash: "d"}
	assert.NotEqual(t, DeriveGenesisChallenge(b1), DeriveGenesisChallenge(b2))
}

func TestValidateGenesisApproval_NoApproverKeys(t *testing.T) {
	req := validRequest()
	req.ApproverKeyIDs = nil
	req.Signatures = nil
	r := ValidateGenesisApproval(req)
	assert.False(t, r.Valid)
	assert.Contains(t, r.Reason, "approver")
}

func TestValidateGenesisApproval_NegativeTimelock(t *testing.T) {
	req := validRequest()
	req.TimelockDuration = -1 * time.Second
	r := ValidateGenesisApproval(req)
	assert.False(t, r.Valid)
	assert.Contains(t, r.Reason, "timelock")
}

func TestValidateGenesisApproval_ActivatesAtAfterTimelock(t *testing.T) {
	req := validRequest()
	req.TimelockDuration = 10 * time.Second
	r := ValidateGenesisApproval(req)
	require.True(t, r.Valid)
	assert.Greater(t, r.ActivatesAt, req.SubmittedAt.Unix())
}

func TestValidateGenesisApproval_QuorumZeroSingleSigner(t *testing.T) {
	req := validRequest()
	req.Quorum = 0
	r := ValidateGenesisApproval(req)
	assert.True(t, r.Valid)
}

func TestValidateGenesisApproval_EmergencyFlagSetsReview(t *testing.T) {
	req := validRequest()
	req.EmergencyOverride = true
	r := ValidateGenesisApproval(req)
	require.True(t, r.Valid)
	assert.True(t, r.RequiresReview)
	assert.True(t, r.ElevatedRisk)
}

func TestTimelockRemaining_Elapsed(t *testing.T) {
	req := validRequest()
	req.SubmittedAt = time.Now().Add(-1 * time.Hour)
	req.TimelockDuration = 1 * time.Second
	assert.Equal(t, time.Duration(0), TimelockRemaining(req))
}

func TestTimelockRemaining_NotElapsed(t *testing.T) {
	req := validRequest()
	req.SubmittedAt = time.Now()
	req.TimelockDuration = 1 * time.Hour
	remaining := TimelockRemaining(req)
	assert.Greater(t, remaining, 59*time.Minute)
}
