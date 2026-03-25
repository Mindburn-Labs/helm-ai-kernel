package pdp

import (
	"context"
	"testing"
	"time"
)

func TestCedarPDP_Evaluate_Permit(t *testing.T) {
	pdp, err := NewCedarPDP(CedarConfig{
		PolicyRef: "test-v1",
		Policies: []CedarPolicy{
			{
				ID:     "policy-1",
				Effect: "permit",
				PrincipalMatch: `Agent::"agent-001"`,
				ActionMatch:    []string{`Action::"read_file"`},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "read_file",
		Resource:  "/tmp/test.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allow {
		t.Error("expected ALLOW, got DENY")
	}
	if resp.PolicyRef != "cedar:test-v1" {
		t.Errorf("expected PolicyRef 'cedar:test-v1', got %q", resp.PolicyRef)
	}
	if resp.DecisionHash == "" {
		t.Error("DecisionHash should not be empty")
	}
}

func TestCedarPDP_DefaultDeny_NoMatchingPermit(t *testing.T) {
	pdp, err := NewCedarPDP(CedarConfig{
		PolicyRef: "test-v1",
		Policies: []CedarPolicy{
			{
				ID:          "policy-1",
				Effect:      "permit",
				ActionMatch: []string{`Action::"read_file"`},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Request an action NOT in the permit policy
	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "delete_file",
		Resource:  "/etc/passwd",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY (no matching permit)")
	}
}

func TestCedarPDP_ForbidOverridesPermit(t *testing.T) {
	pdp, err := NewCedarPDP(CedarConfig{
		PolicyRef: "test-v1",
		Policies: []CedarPolicy{
			{
				ID:          "permit-all",
				Effect:      "permit",
				ActionMatch: []string{`Action::"delete_file"`},
			},
			{
				ID:          "forbid-delete",
				Effect:      "forbid",
				ActionMatch: []string{`Action::"delete_file"`},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "delete_file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY (forbid overrides permit — Cedar semantics)")
	}
}

func TestCedarPDP_ContextConditions(t *testing.T) {
	pdp, err := NewCedarPDP(CedarConfig{
		PolicyRef: "test-v1",
		Policies: []CedarPolicy{
			{
				ID:     "permit-with-context",
				Effect: "permit",
				ContextConditions: map[string]string{
					"environment": "production",
					"approved":    "true",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Missing context → deny
	resp, _ := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "deploy",
		Context:   map[string]any{"environment": "staging"},
	})
	if resp.Allow {
		t.Error("expected DENY when context conditions not met")
	}

	// Matching context → allow
	resp, _ = pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "agent-001",
		Action:    "deploy",
		Context:   map[string]any{"environment": "production", "approved": "true"},
	})
	if !resp.Allow {
		t.Error("expected ALLOW when all context conditions met")
	}
}

func TestCedarPDP_NilRequest(t *testing.T) {
	pdp, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "test-v1",
		Policies:  []CedarPolicy{{ID: "p1", Effect: "permit"}},
	})
	resp, err := pdp.Evaluate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY on nil request")
	}
}

func TestCedarPDP_ContextCancelled(t *testing.T) {
	pdp, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "test-v1",
		Policies:  []CedarPolicy{{ID: "p1", Effect: "permit"}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	resp, err := pdp.Evaluate(ctx, &DecisionRequest{
		Principal: "agent-001",
		Action:    "read_file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allow {
		t.Error("expected DENY on cancelled context")
	}
}

func TestCedarPDP_Backend(t *testing.T) {
	pdp, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "test",
		Policies:  []CedarPolicy{{ID: "p1", Effect: "permit"}},
	})
	if pdp.Backend() != BackendCedar {
		t.Errorf("expected backend %q, got %q", BackendCedar, pdp.Backend())
	}
}

func TestCedarPDP_PolicyHash_Deterministic(t *testing.T) {
	cfg := CedarConfig{
		PolicyRef: "v1",
		Policies: []CedarPolicy{
			{ID: "p1", Effect: "permit"},
			{ID: "p2", Effect: "forbid"},
		},
	}
	pdp1, _ := NewCedarPDP(cfg)
	pdp2, _ := NewCedarPDP(cfg)
	if pdp1.PolicyHash() != pdp2.PolicyHash() {
		t.Error("PolicyHash should be deterministic")
	}

	// Different policy order should give same hash (sorted by ID)
	cfg2 := CedarConfig{
		PolicyRef: "v1",
		Policies: []CedarPolicy{
			{ID: "p2", Effect: "forbid"},
			{ID: "p1", Effect: "permit"},
		},
	}
	pdp3, _ := NewCedarPDP(cfg2)
	if pdp1.PolicyHash() != pdp3.PolicyHash() {
		t.Error("PolicyHash should be order-independent (sorted by ID)")
	}
}

func TestCedarPDP_WildcardPrincipal(t *testing.T) {
	pdp, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "test",
		Policies: []CedarPolicy{
			{
				ID:             "wildcard",
				Effect:         "permit",
				PrincipalMatch: "?principal", // Cedar wildcard
				ActionMatch:    []string{`Action::"read_file"`},
			},
		},
	})

	resp, _ := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "any-agent-whatsoever",
		Action:    "read_file",
	})
	if !resp.Allow {
		t.Error("expected ALLOW for wildcard principal")
	}
}

func TestNewCedarPDP_NoPolicies(t *testing.T) {
	_, err := NewCedarPDP(CedarConfig{Policies: nil})
	if err == nil {
		t.Error("expected error for empty policies")
	}
}

func TestCedarPDP_MultiplePermitPolicies(t *testing.T) {
	pdp, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "test",
		Policies: []CedarPolicy{
			{ID: "p1", Effect: "permit", ActionMatch: []string{`Action::"read_file"`}},
			{ID: "p2", Effect: "permit", ActionMatch: []string{`Action::"write_file"`}},
		},
	})

	// First action matches p1
	resp1, _ := pdp.Evaluate(context.Background(), &DecisionRequest{Action: "read_file"})
	if !resp1.Allow {
		t.Error("expected ALLOW for read_file")
	}

	// Second action matches p2
	resp2, _ := pdp.Evaluate(context.Background(), &DecisionRequest{Action: "write_file"})
	if !resp2.Allow {
		t.Error("expected ALLOW for write_file")
	}

	// Third action matches neither
	resp3, _ := pdp.Evaluate(context.Background(), &DecisionRequest{Action: "delete_file"})
	if resp3.Allow {
		t.Error("expected DENY for delete_file (no matching permit)")
	}
}

// Ensure time.Duration isn't needed as import when unused
var _ = time.Second
