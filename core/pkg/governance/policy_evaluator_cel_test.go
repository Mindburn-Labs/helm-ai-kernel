package governance

import (
	"context"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capabilities"
)

func TestCELPolicyEvaluatorVerifyModulePolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("valid module passes default allow and caches system rules", func(t *testing.T) {
		evaluator, err := NewCELPolicyEvaluator()
		if err != nil {
			t.Fatalf("NewCELPolicyEvaluator: %v", err)
		}

		module := celPolicyModule("", "", "")
		if err := evaluator.VerifyModulePolicy(ctx, module); err != nil {
			t.Fatalf("VerifyModulePolicy: %v", err)
		}
		if got, want := len(evaluator.prgCache), len(evaluator.systemRules); got != want {
			t.Fatalf("expected system rules cached, got %d want %d", got, want)
		}

		cacheSize := len(evaluator.prgCache)
		if err := evaluator.VerifyModulePolicy(ctx, module); err != nil {
			t.Fatalf("VerifyModulePolicy cache hit: %v", err)
		}
		if got := len(evaluator.prgCache); got != cacheSize {
			t.Fatalf("cache hit should not grow cache, got %d want %d", got, cacheSize)
		}
	})

	t.Run("valid self policy passes and extracts capability names", func(t *testing.T) {
		evaluator, err := NewCELPolicyEvaluator()
		if err != nil {
			t.Fatalf("NewCELPolicyEvaluator: %v", err)
		}

		module := celPolicyModule(
			`module.capability_names.exists(c, c == "read") && module.dependencies.exists(d, d == "base.runtime")`,
			"acme.reader",
			"1.2.3-build.4",
		)
		module.Dependencies = []string{"base.runtime"}
		module.Capabilities = []capabilities.Capability{{Name: "read"}}

		if err := evaluator.VerifyModulePolicy(ctx, module); err != nil {
			t.Fatalf("VerifyModulePolicy: %v", err)
		}
		if got, want := len(extractCapabilityNames(module.Capabilities)), 1; got != want {
			t.Fatalf("extractCapabilityNames len=%d want %d", got, want)
		}
	})

	t.Run("system policy denies malformed module name", func(t *testing.T) {
		evaluator, err := NewCELPolicyEvaluator()
		if err != nil {
			t.Fatalf("NewCELPolicyEvaluator: %v", err)
		}

		err = evaluator.VerifyModulePolicy(ctx, celPolicyModule("", "InvalidName", "1.2.3"))
		if err == nil || !strings.Contains(err.Error(), "system policy denied module") || !strings.Contains(err.Error(), "rule 0") {
			t.Fatalf("expected rule 0 system denial, got %v", err)
		}
	})

	t.Run("system policy denies malformed module version", func(t *testing.T) {
		evaluator, err := NewCELPolicyEvaluator()
		if err != nil {
			t.Fatalf("NewCELPolicyEvaluator: %v", err)
		}

		err = evaluator.VerifyModulePolicy(ctx, celPolicyModule("", "acme.reader", "latest"))
		if err == nil || !strings.Contains(err.Error(), "system policy denied module") || !strings.Contains(err.Error(), "rule 1") {
			t.Fatalf("expected rule 1 system denial, got %v", err)
		}
	})

	t.Run("system policy compile error fails closed", func(t *testing.T) {
		evaluator, err := NewCELPolicyEvaluator()
		if err != nil {
			t.Fatalf("NewCELPolicyEvaluator: %v", err)
		}
		evaluator.systemRules = []string{"module.name."}

		err = evaluator.VerifyModulePolicy(ctx, celPolicyModule("", "acme.reader", "1.2.3"))
		if err == nil || !strings.Contains(err.Error(), "system policy error (rule 0): compile:") {
			t.Fatalf("expected system compile error, got %v", err)
		}
	})

	t.Run("module self policy denies activation", func(t *testing.T) {
		evaluator, err := NewCELPolicyEvaluator()
		if err != nil {
			t.Fatalf("NewCELPolicyEvaluator: %v", err)
		}

		err = evaluator.VerifyModulePolicy(ctx, celPolicyModule("false", "acme.reader", "1.2.3"))
		if err == nil || !strings.Contains(err.Error(), "module policy denied activation") {
			t.Fatalf("expected module policy denial, got %v", err)
		}
	})

	t.Run("module self policy compile error fails closed", func(t *testing.T) {
		evaluator, err := NewCELPolicyEvaluator()
		if err != nil {
			t.Fatalf("NewCELPolicyEvaluator: %v", err)
		}

		err = evaluator.VerifyModulePolicy(ctx, celPolicyModule("module.name.", "acme.reader", "1.2.3"))
		if err == nil || !strings.Contains(err.Error(), "module policy error: compile:") {
			t.Fatalf("expected module compile error, got %v", err)
		}
	})
}

func TestCELPolicyEvaluatorEvaluateExprErrors(t *testing.T) {
	evaluator, err := NewCELPolicyEvaluator()
	if err != nil {
		t.Fatalf("NewCELPolicyEvaluator: %v", err)
	}

	input := map[string]any{
		"timestamp": int64(1),
		"module": map[string]any{
			"name":             "acme.reader",
			"version":          "1.2.3",
			"capability_names": []string{"read"},
			"dependencies":     []string{"base.runtime"},
		},
	}

	t.Run("non bool result is rejected", func(t *testing.T) {
		allowed, err := evaluator.evaluateExpr("module.name", input)
		if err == nil || !strings.Contains(err.Error(), "result not bool") {
			t.Fatalf("expected non-bool error, allowed=%t err=%v", allowed, err)
		}
	})

	t.Run("eval error is wrapped", func(t *testing.T) {
		allowed, err := evaluator.evaluateExpr("module.name / 0 == 1", input)
		if err == nil || !strings.Contains(err.Error(), "eval:") {
			t.Fatalf("expected eval error, allowed=%t err=%v", allowed, err)
		}
	})
}

func TestCELPolicyEvaluatorManifestFallbacks(t *testing.T) {
	module := ModuleBundle{
		ID:       "fallback.id",
		Manifest: map[string]any{"name": 12, "version": false},
	}

	if got := getNameFromManifest(module); got != "fallback.id" {
		t.Fatalf("getNameFromManifest fallback=%q", got)
	}
	if got := getVersionFromManifest(module); got != "0.0.0" {
		t.Fatalf("getVersionFromManifest fallback=%q", got)
	}
}

func celPolicyModule(policy, name, version string) ModuleBundle {
	if name == "" {
		name = "acme.reader"
	}
	if version == "" {
		version = "1.2.3"
	}
	return ModuleBundle{
		ID: "module-1",
		Manifest: map[string]any{
			"name":    name,
			"version": version,
		},
		Policy: policy,
	}
}
