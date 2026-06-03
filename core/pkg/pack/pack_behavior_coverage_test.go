package pack

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry"
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

func TestCoverageCompatibilityMatrixEdges(t *testing.T) {
	matrix := &CompatibilityMatrix{
		Entries: []CompatibilityEntry{
			{
				ComponentA: "kernel",
				VersionA:   ">=1.0.0 <2.0.0",
				ComponentB: "sdk-go",
				VersionB:   "^1.4.0",
				Status:     CompatFull,
				TestedAt:   time.Now().UTC(),
			},
		},
	}

	assert.Equal(t, CompatFull, matrix.IsCompatible("kernel", "1.5.0", "sdk-go", "1.4.2"))
	assert.Equal(t, CompatFull, matrix.IsCompatible("sdk-go", "1.4.2", "kernel", "1.5.0"))
	assert.Equal(t, CompatUntested, matrix.IsCompatible("kernel", "2.0.0", "sdk-go", "1.4.2"))
	assert.False(t, matchesConstraint("not a constraint", "1.0.0"))
	assert.False(t, matchesConstraint(">=1.0.0", "not-semver"))
}

func TestCoverageRegistryAdapterEdges(t *testing.T) {
	ctx := context.Background()
	bundleRegistry := registry.NewInMemoryRegistry()
	adapter := NewRegistryAdapter(bundleRegistry)

	_, err := adapter.GetPack(ctx, "missing")
	require.Error(t, err)
	_, err = adapter.ListVersions(ctx, "missing")
	require.Error(t, err)

	err = bundleRegistry.Register(&manifest.Bundle{
		Manifest: manifest.Module{
			Name:        "adapter-pack",
			Version:     "1.2.3",
			Description: "adapter coverage pack",
			Capabilities: []manifest.CapabilityConfig{
				{Name: "capture"},
				{Name: "attest"},
			},
		},
		Signature: "registry-signature",
	})
	require.NoError(t, err)

	got, err := adapter.GetPack(ctx, "adapter-pack")
	require.NoError(t, err)
	assert.Equal(t, "adapter-pack", got.PackID)
	assert.Equal(t, []string{"capture", "attest"}, got.Manifest.Capabilities)
	require.Len(t, got.Manifest.Signatures, 1)
	assert.Equal(t, "bundle-registry", got.Manifest.Signatures[0].SignerID)

	found, err := adapter.FindByCapability(ctx, "attest")
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.Equal(t, "adapter-pack", found[0].Manifest.Name)

	missing, err := adapter.FindByCapability(ctx, "missing")
	require.NoError(t, err)
	assert.Empty(t, missing)

	versions, err := adapter.ListVersions(ctx, "adapter-pack")
	require.NoError(t, err)
	require.Len(t, versions, 1)
	assert.Equal(t, "1.2.3", versions[0].Version)

	signedPack := &Pack{
		Manifest: PackManifest{
			Name:         "published-signed",
			Version:      "1.0.0",
			Description:  "signed publish coverage",
			Capabilities: []string{"sign"},
			Signatures:   []Signature{{Signature: "pack-signature"}},
		},
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, adapter.PublishPack(ctx, signedPack))
	publishedSigned, err := bundleRegistry.Get("published-signed")
	require.NoError(t, err)
	assert.Equal(t, "pack-signature", publishedSigned.Signature)

	unsignedPack := &Pack{
		Manifest: PackManifest{
			Name:         "published-unsigned",
			Version:      "1.0.0",
			Capabilities: []string{"plain"},
		},
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, adapter.PublishPack(ctx, unsignedPack))
	publishedUnsigned, err := bundleRegistry.Get("published-unsigned")
	require.NoError(t, err)
	assert.Empty(t, publishedUnsigned.Signature)
}

func TestCoverageResolverRegistryErrors(t *testing.T) {
	resolver := NewResolver(behaviorCoverageErrorPackRegistry{err: errors.New("registry failed")})

	_, err := resolver.Resolve(context.Background(), &ResolutionRequest{
		RequestID:    "pinned",
		Capabilities: []string{"capture"},
		Constraints:  ResolutionConstraints{PinnedVersions: map[string]string{"capture": "pack@1.0.0"}},
	})
	require.Error(t, err)

	_, err = resolver.Resolve(context.Background(), &ResolutionRequest{
		RequestID:    "lookup",
		Capabilities: []string{"capture"},
		Constraints:  DefaultConstraints(),
	})
	require.Error(t, err)
}

type behaviorCoverageErrorPackRegistry struct {
	err error
}

func (r behaviorCoverageErrorPackRegistry) GetPack(context.Context, string) (*Pack, error) {
	return nil, r.err
}

func (r behaviorCoverageErrorPackRegistry) FindByCapability(context.Context, string) ([]Pack, error) {
	return nil, r.err
}

func (r behaviorCoverageErrorPackRegistry) ListVersions(context.Context, string) ([]PackVersion, error) {
	return nil, r.err
}
