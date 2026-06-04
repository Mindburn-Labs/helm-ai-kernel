package policybundles

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/google/cel-go/cel"
)

func TestAgentSafetyBaselineBundleShape(t *testing.T) {
	bundle := AgentSafetyBaselineBundle()
	if bundle.BundleID != AgentSafetyBaselineBundleID {
		t.Fatalf("bundle id = %q, want %q", bundle.BundleID, AgentSafetyBaselineBundleID)
	}
	if bundle.Category != AgentSafetyBaselineCategory {
		t.Fatalf("category = %q, want %q", bundle.Category, AgentSafetyBaselineCategory)
	}
	if bundle.Status != BundleStatusActive {
		t.Fatalf("status = %q, want active", bundle.Status)
	}
	if len(bundle.Rules) != 15 {
		t.Fatalf("rules = %d, want 15", len(bundle.Rules))
	}

	seen := map[string]bool{}
	for _, rule := range bundle.Rules {
		if rule.RuleID == "" || rule.Name == "" || rule.Description == "" || rule.Condition == "" {
			t.Fatalf("incomplete rule: %#v", rule)
		}
		if seen[rule.RuleID] {
			t.Fatalf("duplicate rule id %s", rule.RuleID)
		}
		seen[rule.RuleID] = true
		switch rule.Action {
		case "deny", "require_approval", "log", "encrypt":
		default:
			t.Fatalf("rule %s has unsupported action %q", rule.RuleID, rule.Action)
		}
		if rule.Action == "deny" || rule.Action == "require_approval" {
			reason := rule.Parameters["reason_code"]
			if !contracts.IsCanonicalReasonCode(reason) {
				t.Fatalf("rule %s reason %q is not canonical", rule.RuleID, reason)
			}
		}
	}

	for _, id := range []string{
		AgentSafetyRuleTaintedHighRisk,
		AgentSafetyRuleToolContract,
		AgentSafetyRuleHighImpactApproval,
		AgentSafetyRuleMemoryInfluenceOnly,
		AgentSafetyRuleA2AVerification,
		AgentSafetyRuleSafeDepOverride,
		AgentSafetyRuleBenchmarkEvidence,
	} {
		if !seen[id] {
			t.Fatalf("missing baseline rule %s", id)
		}
	}
}

func TestAgentSafetyBaselineConditionsCompile(t *testing.T) {
	env, err := celEnv()
	if err != nil {
		t.Fatalf("CEL env: %v", err)
	}

	for _, rule := range AgentSafetyBaselineBundle().Rules {
		t.Run(rule.RuleID, func(t *testing.T) {
			_, issues := env.Compile(rule.Condition)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("condition does not compile: %v\n%s", issues.Err(), rule.Condition)
			}
		})
	}
}

func TestAgentSafetyDecisionContextContract(t *testing.T) {
	fields := AgentSafetyDecisionContextFields()
	if len(fields) < 25 {
		t.Fatalf("fields = %d, want at least 25", len(fields))
	}

	required := map[string]bool{
		"effect_type":              false,
		"effect_class":             false,
		"tool_name":                false,
		"connector_id":             false,
		"action":                   false,
		"taint":                    false,
		"source_trust":             false,
		"source_channel":           false,
		"memory_tier":              false,
		"memory_review_state":      false,
		"memory_trust_score":       false,
		"provenance_score":         false,
		"destination":              false,
		"payload_bytes":            false,
		"delegation_session_valid": false,
		"credential_scope":         false,
		"a2a_signature_valid":      false,
		"manifest_digest_valid":    false,
		"output_contract_valid":    false,
		"approved_args_valid":      false,
		"safe_dep_state":           false,
		"inspection_only":          false,
	}

	for _, field := range fields {
		if field.Required && !field.FailClosed {
			t.Fatalf("required field %s must fail closed", field.Name)
		}
		if _, ok := required[field.Name]; ok {
			required[field.Name] = true
		}
	}
	for name, found := range required {
		if !found {
			t.Fatalf("missing decision context field %s", name)
		}
	}
}

func TestAgentSafetyBaselineHashDeterminism(t *testing.T) {
	ctx := context.Background()
	store1 := NewInMemoryBundleStore()
	store2 := NewInMemoryBundleStore()
	mgr1 := NewBundleManager(store1)
	mgr2 := NewBundleManager(store2)

	b1 := AgentSafetyBaselineBundle()
	b2 := AgentSafetyBaselineBundle()
	if err := mgr1.CreateBundle(ctx, b1); err != nil {
		t.Fatalf("create first: %v", err)
	}
	if err := mgr2.CreateBundle(ctx, b2); err != nil {
		t.Fatalf("create second: %v", err)
	}

	if b1.ContentHash == "" {
		t.Fatal("content hash is empty")
	}
	if b1.ContentHash != b2.ContentHash {
		t.Fatalf("content hash mismatch:\n%s\n%s", b1.ContentHash, b2.ContentHash)
	}
}

func celEnv() (*cel.Env, error) {
	return cel.NewEnv(AgentSafetyCELEnvOptions()...)
}
