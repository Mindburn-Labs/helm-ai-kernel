package main

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
)

// TestDefaultBoundaryPolicyLoads is the regression test for the silent fail-open
// caused by hardcoding a stale schema version in services.go (was "1.0", the
// enforcer requires boundary.PolicyVersion exactly). If this test passes, the
// kernel starts with a non-nil BoundaryEnforcer in dev mode and never reaches
// the fatal branch in production mode.
func TestDefaultBoundaryPolicyLoads(t *testing.T) {
	pol := defaultBoundaryPolicy()
	if pol.Version != boundary.PolicyVersion {
		t.Fatalf("default policy version drifted: got %q, want %q", pol.Version, boundary.PolicyVersion)
	}

	pe, err := boundary.NewPerimeterEnforcer(pol)
	if err != nil {
		t.Fatalf("default boundary policy must load cleanly: %v", err)
	}
	if pe == nil {
		t.Fatal("perimeter enforcer is nil even though no error returned")
	}
}
