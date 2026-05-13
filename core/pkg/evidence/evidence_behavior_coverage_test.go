package evidence

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistryEmpty(t *testing.T) {
	reg := NewRegistry()
	assert.Equal(t, "unloaded", reg.ManifestVersion())
	assert.Nil(t, reg.GetContract("ANY"))
}

func TestLoadManifestNilReturnsError(t *testing.T) {
	reg := NewRegistry()
	assert.Error(t, reg.LoadManifest(nil))
}

func TestLoadManifestEmptyActionClassReturnsError(t *testing.T) {
	reg := NewRegistry()
	err := reg.LoadManifest(&contracts.EvidenceContractManifest{
		Version: "1.0.0",
		Contracts: []contracts.EvidenceContract{
			{ContractID: "EC-1", ActionClass: ""},
		},
	})
	assert.Error(t, err)
}

func TestGetContractReturnsLoadedContract(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	c := reg.GetContract("FUNDS_TRANSFER")
	require.NotNil(t, c)
	assert.Equal(t, "EC-001", c.ContractID)
}

func TestCheckBeforeNoContractSatisfied(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	v, err := reg.CheckBefore(context.Background(), "UNKNOWN_ACTION", nil)
	require.NoError(t, err)
	assert.True(t, v.Satisfied)
}

func TestCheckAfterNoContractSatisfied(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	v, err := reg.CheckAfter(context.Background(), "UNKNOWN_ACTION", nil)
	require.NoError(t, err)
	assert.True(t, v.Satisfied)
}

func TestCheckBeforeMissingEvidence(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	v, err := reg.CheckBefore(context.Background(), "DEPLOY", nil)
	require.NoError(t, err)
	assert.False(t, v.Satisfied)
	assert.Len(t, v.Missing, 1)
}

func TestCheckBeforeVerifiedSubmission(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	subs := []contracts.EvidenceSubmission{{EvidenceType: "hash_proof", Verified: true}}
	v, err := reg.CheckBefore(context.Background(), "DEPLOY", subs)
	require.NoError(t, err)
	assert.True(t, v.Satisfied)
}

func TestCheckAfterUnverifiedRejected(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	subs := []contracts.EvidenceSubmission{{EvidenceType: "receipt", Verified: false}}
	v, err := reg.CheckAfter(context.Background(), "FUNDS_TRANSFER", subs)
	require.NoError(t, err)
	assert.False(t, v.Satisfied)
}

func TestCheckBeforeIssuerConstraintWrongIssuer(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	subs := []contracts.EvidenceSubmission{{EvidenceType: "dual_attestation", IssuerID: "wrong", Verified: true}}
	v, err := reg.CheckBefore(context.Background(), "FUNDS_TRANSFER", subs)
	require.NoError(t, err)
	assert.False(t, v.Satisfied)
}

func TestCheckBeforeIssuerConstraintCorrectIssuer(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	subs := []contracts.EvidenceSubmission{{EvidenceType: "dual_attestation", IssuerID: "finance-system", Verified: true}}
	v, err := reg.CheckBefore(context.Background(), "FUNDS_TRANSFER", subs)
	require.NoError(t, err)
	assert.True(t, v.Satisfied)
}

func TestCheckBothPhaseBefore(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	v, err := reg.CheckBefore(context.Background(), "DATA_WRITE", nil)
	require.NoError(t, err)
	assert.False(t, v.Satisfied)
}

func TestCheckBothPhaseAfterSatisfied(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	subs := []contracts.EvidenceSubmission{{EvidenceType: "receipt", Verified: true}}
	v, err := reg.CheckAfter(context.Background(), "DATA_WRITE", subs)
	require.NoError(t, err)
	assert.True(t, v.Satisfied)
}

func TestWithClockOverride(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	reg := NewRegistry().WithClock(func() time.Time { return fixed })
	require.NoError(t, reg.LoadManifest(testManifest()))
	v, err := reg.CheckBefore(context.Background(), "UNKNOWN", nil)
	require.NoError(t, err)
	assert.Equal(t, fixed, v.VerifiedAt)
}

func TestManifestVersionAfterLoad(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	assert.Equal(t, "1.0.0", reg.ManifestVersion())
}

func TestComputeManifestHashDeterministic(t *testing.T) {
	m := testManifest()
	h1, err := ComputeManifestHash(m)
	require.NoError(t, err)
	h2, err := ComputeManifestHash(m)
	require.NoError(t, err)
	assert.Equal(t, h1, h2)
}

func TestComputeManifestHashPrefix(t *testing.T) {
	h, err := ComputeManifestHash(testManifest())
	require.NoError(t, err)
	assert.Contains(t, h, "sha256:")
}

func TestCheckVerdictContractID(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	v, err := reg.CheckBefore(context.Background(), "DEPLOY", nil)
	require.NoError(t, err)
	assert.Equal(t, "EC-002", v.ContractID)
}

func TestLoadManifestReplacesContracts(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.LoadManifest(testManifest()))
	assert.NotNil(t, reg.GetContract("FUNDS_TRANSFER"))
	m2 := &contracts.EvidenceContractManifest{Version: "2.0.0", Contracts: []contracts.EvidenceContract{
		{ContractID: "EC-X", ActionClass: "ONLY_THIS"},
	}}
	require.NoError(t, reg.LoadManifest(m2))
	assert.Nil(t, reg.GetContract("FUNDS_TRANSFER"))
	assert.NotNil(t, reg.GetContract("ONLY_THIS"))
}
