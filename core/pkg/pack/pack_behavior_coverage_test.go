package pack

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackBuilderMissingName(t *testing.T) {
	b := NewPackBuilder(PackManifest{Version: "1.0.0"})
	_, err := b.Build()
	assert.Error(t, err)
}

func TestPackBuilderMissingVersion(t *testing.T) {
	b := NewPackBuilder(PackManifest{Name: "test"})
	_, err := b.Build()
	assert.Error(t, err)
}

func TestPackBuilderUnsigned(t *testing.T) {
	p, err := NewPackBuilder(PackManifest{Name: "p", Version: "1.0.0"}).Build()
	require.NoError(t, err)
	assert.Empty(t, p.Signature)
	assert.NotEmpty(t, p.ContentHash)
}

func TestComputePackHashDeterministic(t *testing.T) {
	p := &Pack{Manifest: PackManifest{Name: "x", Version: "1.0.0", Capabilities: []string{"a"}}}
	assert.Equal(t, ComputePackHash(p), ComputePackHash(p))
}

func TestValidateManifestEmptyCapability(t *testing.T) {
	err := ValidateManifest(PackManifest{Capabilities: []string{"ok", ""}})
	assert.Error(t, err)
}

func TestValidateManifestValid(t *testing.T) {
	assert.NoError(t, ValidateManifest(PackManifest{Capabilities: []string{"auth", "billing"}}))
}

func TestCalculateTrustScoreNilSLOs(t *testing.T) {
	score := CalculateTrustScore(PackMetrics{}, nil)
	assert.Equal(t, 0.5, score)
}

func TestCalculateTrustScorePerfectMetrics(t *testing.T) {
	slos := &ServiceLevelObjectives{MaxFailureRate: 0.01, MinEvidenceRate: 0.99, MaxIncidentRate: 0.001}
	score := CalculateTrustScore(PackMetrics{FailureRate: 0.005, EvidenceSuccessRate: 1.0, IncidentRate: 0.0}, slos)
	assert.Equal(t, 1.0, score)
}

func TestCalculateTrustScoreHighFailure(t *testing.T) {
	slos := &ServiceLevelObjectives{MaxFailureRate: 0.01}
	score := CalculateTrustScore(PackMetrics{FailureRate: 0.02}, slos)
	assert.Less(t, score, 1.0)
}

func TestCalculateConfidenceScoreHigh(t *testing.T) {
	assert.Equal(t, 1.0, CalculateConfidenceScore(1000))
	assert.Equal(t, 1.0, CalculateConfidenceScore(5000))
}

func TestCalculateConfidenceScoreLow(t *testing.T) {
	assert.InDelta(t, 0.1, CalculateConfidenceScore(100), 0.001)
}

func TestCheckCompatibilityNoConstraint(t *testing.T) {
	assert.NoError(t, CheckCompatibility(PackManifest{}, "1.0.0"))
}

func TestCheckCompatibilityIncompatible(t *testing.T) {
	m := PackManifest{ApplicabilityConstraints: &ApplicabilityConstraints{KernelVersion: ">=2.0.0"}}
	assert.Error(t, CheckCompatibility(m, "1.5.0"))
}

func TestCheckDependencyMissing(t *testing.T) {
	dep := PackDependency{PackName: "missing", VersionSpec: ">=1.0.0"}
	assert.Error(t, CheckDependency(dep, nil))
}

func TestVerifierVerifyNilPack(t *testing.T) {
	v := NewVerifier(nil)
	ok, err := v.VerifyPack(nil)
	assert.False(t, ok)
	assert.Error(t, err)
}

func TestVerifierVerifyWithRequest(t *testing.T) {
	v := NewVerifier(nil)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	p, _ := NewPackBuilder(PackManifest{Name: "vp", Version: "1.0.0"}).WithSigningKey(priv).Build()

	req := &VerificationRequest{
		RequestID: "r1",
		Packs:     []ResolvedPack{{PackID: p.PackID, Manifest: p.Manifest, ContentHash: p.ContentHash}},
		Options:   DefaultVerificationOptions(),
	}
	result, err := v.Verify(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Summary.TotalPacks)
}
