package governance

import (
	"context"
	"testing"
)

// ── Jurisdiction Resolution ─────────────────────────────────────

func TestEdgeAssistant_FallbackDenyAll(t *testing.T) {
	ea := &EdgeAssistant{
		Config:   EdgeConfig{Mode: EdgeFallback},
		Fallback: FallbackPolicy{Strategy: FallbackDenyAll},
	}
	if ea.ShouldAllow("deploy", "LOW") {
		t.Error("DENY_ALL should deny everything")
	}
}

func TestEdgeAssistant_RingFenceAllowsLow(t *testing.T) {
	ea := &EdgeAssistant{
		Config: EdgeConfig{Mode: EdgeFallback},
		Fallback: FallbackPolicy{
			Strategy:   FallbackRingFence,
			AllowRules: []FallbackRule{{EffectType: "log", MaxRisk: "MEDIUM"}},
		},
	}
	if !ea.ShouldAllow("log", "LOW") {
		t.Error("ring fence should allow LOW log")
	}
	if ea.ShouldAllow("deploy", "HIGH") {
		t.Error("ring fence should deny HIGH deploy")
	}
}

func TestCanaryDefaults(t *testing.T) {
	if DefaultCanary.Steps != 3 {
		t.Errorf("expected 3 steps, got %d", DefaultCanary.Steps)
	}
	if FastCanary.Steps != 1 {
		t.Errorf("expected 1 step for fast canary, got %d", FastCanary.Steps)
	}
}

// fakePDP is a minimal PDP that always allows, for testing the swarm wrapper.
type fakePDP struct{ version string }

func (s *fakePDP) Evaluate(_ context.Context, _ PDPRequest) (*PDPResponse, error) {
	return &PDPResponse{Decision: DecisionAllow, PolicyVersion: s.version}, nil
}

func (s *fakePDP) PolicyVersion() string { return s.version }
