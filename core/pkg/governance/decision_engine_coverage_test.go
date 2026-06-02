package governance

import (
	"context"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capabilities"
)

func TestDecisionEngineEffectClassCoverage(t *testing.T) {
	catalog := capabilities.NewToolCatalog()
	catalog.Add(capabilities.Capability{ID: "read", EffectClass: string(EffectClassE1)})
	catalog.Add(capabilities.Capability{ID: "invalid-effect", EffectClass: "E9"})

	engine, err := NewDecisionEngine(catalog)
	if err != nil {
		t.Fatalf("NewDecisionEngine: %v", err)
	}
	if len(engine.PublicKey()) == 0 {
		t.Fatal("PublicKey should return verifier material")
	}

	intent, err := engine.Evaluate(context.Background(), "intent-read", []byte(`{"action":"read"}`))
	if err != nil {
		t.Fatalf("E1 action should be permitted: %v", err)
	}
	if intent.TargetCapability != "read" {
		t.Fatalf("TargetCapability=%q want read", intent.TargetCapability)
	}

	_, err = engine.Evaluate(context.Background(), "intent-missing", []byte(`{"action":"missing"}`))
	if err == nil || !strings.Contains(err.Error(), "policy violation: E3 action 'missing'") {
		t.Fatalf("missing catalog entry should default to E3 denial, got %v", err)
	}

	_, err = engine.Evaluate(context.Background(), "intent-invalid", []byte(`{"action":"invalid-effect"}`))
	if err == nil || !strings.Contains(err.Error(), "policy violation: E3 action 'invalid-effect'") {
		t.Fatalf("unknown effect class should default to E3 denial, got %v", err)
	}
}

func TestDecisionEngineNilCatalogUsesLegacyPolicy(t *testing.T) {
	engine, err := NewDecisionEngine(nil)
	if err != nil {
		t.Fatalf("NewDecisionEngine: %v", err)
	}

	intent, err := engine.Evaluate(context.Background(), "intent-deploy", []byte(`{"action":"deploy"}`))
	if err != nil {
		t.Fatalf("legacy allowlist should permit deploy with nil catalog: %v", err)
	}
	if intent.TargetCapability != "deploy" {
		t.Fatalf("TargetCapability=%q want deploy", intent.TargetCapability)
	}
}
