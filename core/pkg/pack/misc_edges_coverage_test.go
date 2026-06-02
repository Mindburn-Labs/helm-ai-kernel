package pack

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCoveragePackDependencyEdges(t *testing.T) {
	if err := CheckDependency(PackDependency{
		PackName: "optional-missing",
		Optional: true,
	}, nil); err != nil {
		t.Fatalf("optional missing dependency should pass: %v", err)
	}

	if err := CheckDependency(PackDependency{
		PackName:    "dep",
		VersionSpec: "not a constraint",
	}, []PackVersion{{PackName: "dep", Version: "1.0.0"}}); err == nil {
		t.Fatal("expected invalid dependency constraint to fail")
	}

	if err := CheckDependency(PackDependency{
		PackName:    "dep",
		VersionSpec: ">=1.0.0",
	}, []PackVersion{{PackName: "dep", Version: "not-semver"}}); err == nil {
		t.Fatal("expected invalid installed dependency version to fail")
	}

	if err := CheckDependency(PackDependency{
		PackName:    "dep",
		VersionSpec: ">=2.0.0",
	}, []PackVersion{{PackName: "dep", Version: "1.0.0"}}); err == nil {
		t.Fatal("expected dependency version mismatch to fail")
	}
}

func TestCoverageResolverEdges(t *testing.T) {
	ctx := context.Background()

	resolver := NewResolver(coverageErrorPackRegistry{})
	if _, err := resolver.resolveCapability(ctx, "capture", ResolutionConstraints{
		PinnedVersions: map[string]string{"capture": "missing-pack"},
	}); err == nil {
		t.Fatal("expected pinned pack lookup error")
	}

	if _, err := resolver.resolveCapability(ctx, "capture", ResolutionConstraints{}); err == nil {
		t.Fatal("expected capability search error")
	}
}

func TestCoverageCapabilityVerifierOption(t *testing.T) {
	defaultVerifier := NewCapabilityVerifier()
	defaultResult, err := defaultVerifier.VerifyManifest("default-skill", nil, []byte("safe content"))
	if err != nil {
		t.Fatalf("default VerifyManifest: %v", err)
	}
	if defaultResult.VerifiedAt.IsZero() {
		t.Fatal("default verifier should set VerifiedAt")
	}

	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	verifier := NewCapabilityVerifier(WithClock(func() time.Time { return now }))
	result, err := verifier.VerifyManifest("skill", []string{"network", "filesystem", "code_execution"}, []byte("safe content"))
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	if !result.VerifiedAt.Equal(now) {
		t.Fatalf("VerifiedAt = %s, want %s", result.VerifiedAt, now)
	}
}

func TestCoverageVerifierPackSignatureFailure(t *testing.T) {
	manifest := PackManifest{Name: "unsigned", Version: "1.0.0"}
	p := &Pack{
		PackID:      "unsigned",
		Manifest:    manifest,
		ContentHash: ComputePackHash(&Pack{Manifest: manifest}),
	}

	ok, err := NewVerifier(nil).VerifyPack(p)
	if ok || err == nil {
		t.Fatalf("VerifyPack ok=%v err=%v, want signature failure", ok, err)
	}
}

type coverageErrorPackRegistry struct{}

func (coverageErrorPackRegistry) GetPack(context.Context, string) (*Pack, error) {
	return nil, errors.New("get pack failed")
}

func (coverageErrorPackRegistry) FindByCapability(context.Context, string) ([]Pack, error) {
	return nil, errors.New("find capability failed")
}

func (coverageErrorPackRegistry) ListVersions(context.Context, string) ([]PackVersion, error) {
	return nil, errors.New("list versions failed")
}
