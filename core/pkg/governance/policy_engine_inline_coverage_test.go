package governance

import (
	"context"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestPolicyEngineEvaluateRuntimeErrorFailsClosed(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	if err := engine.LoadPolicy("runtime-error", `context.risk / 0 == 1`); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	decision, err := engine.Evaluate(context.Background(), "runtime-error", contracts.AccessRequest{
		PrincipalID: "user-1",
		Action:      "read",
		ResourceID:  "doc-1",
		Context:     map[string]interface{}{"risk": 10},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Verdict != "DENY" {
		t.Fatalf("runtime errors should fail closed, got %s", decision.Verdict)
	}
	if !strings.Contains(decision.Reason, "Evaluation error:") {
		t.Fatalf("expected evaluation error reason, got %q", decision.Reason)
	}
}

func TestPolicyEngineEvaluateInlineErrors(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	tests := []struct {
		name    string
		expr    string
		vars    map[string]interface{}
		wantErr string
	}{
		{
			name:    "compile error",
			expr:    "risk_score <",
			vars:    map[string]interface{}{"risk_score": 50},
			wantErr: "inline policy compilation failed:",
		},
		{
			name:    "eval error",
			expr:    "risk_score / zero == 1",
			vars:    map[string]interface{}{"risk_score": 50, "zero": 0},
			wantErr: "inline evaluation failed:",
		},
		{
			name:    "non bool",
			expr:    "risk_score",
			vars:    map[string]interface{}{"risk_score": 50},
			wantErr: "inline expression did not evaluate to bool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := engine.EvaluateInline(tt.expr, tt.vars)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected %q error, allowed=%t err=%v", tt.wantErr, allowed, err)
			}
			if allowed {
				t.Fatal("error cases must fail closed")
			}
		})
	}
}
