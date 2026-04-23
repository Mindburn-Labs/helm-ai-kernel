package pdp

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestHelmPDP_Allow(t *testing.T) {
	pdp := NewHelmPDP("v0.1.0", map[string]bool{
		"allowed_resource": true,
		"denied_resource":  false,
	})

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "user:alice",
		Action:    "read",
		Resource:  "allowed_resource",
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Errorf("expected allow, got deny (reason=%s)", resp.ReasonCode)
	}
	if resp.DecisionHash == "" {
		t.Error("decision hash must not be empty")
	}
	if !strings.HasPrefix(resp.DecisionHash, "sha256:") {
		t.Errorf("decision hash must start with sha256:, got %s", resp.DecisionHash)
	}
	if resp.PolicyRef == "" {
		t.Error("policy ref must not be empty")
	}
}

func TestHelmPDP_Deny(t *testing.T) {
	pdp := NewHelmPDP("v0.1.0", map[string]bool{
		"allowed_resource": true,
		"denied_resource":  false,
	})

	resp, err := pdp.Evaluate(context.Background(), &DecisionRequest{
		Principal: "user:alice",
		Action:    "write",
		Resource:  "denied_resource",
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allow {
		t.Error("expected deny, got allow")
	}
	if resp.ReasonCode == "" {
		t.Errorf("expected deny reason code, got %q", resp.ReasonCode)
	}
	if resp.DecisionHash == "" {
		t.Error("decision hash must not be empty on deny")
	}
}

func TestHelmPDP_NilRequest(t *testing.T) {
	pdp := NewHelmPDP("v0.1.0", nil)

	resp, err := pdp.Evaluate(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allow {
		t.Error("nil request must be denied (fail-closed)")
	}
}

func TestHelmPDP_BackendIdentity(t *testing.T) {
	pdp := NewHelmPDP("v0.1.0", nil)

	if pdp.Backend() != BackendHELM {
		t.Errorf("expected BackendHELM, got %v", pdp.Backend())
	}
	if pdp.PolicyHash() == "" {
		t.Error("policy hash must not be empty")
	}
}

func TestHelmPDP_DecisionHashDeterminism(t *testing.T) {
	pdp := NewHelmPDP("v0.1.0", map[string]bool{"res": true})

	req := &DecisionRequest{
		Principal: "user:bob",
		Action:    "execute",
		Resource:  "res",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	resp1, _ := pdp.Evaluate(context.Background(), req)
	resp2, _ := pdp.Evaluate(context.Background(), req)

	if resp1.DecisionHash != resp2.DecisionHash {
		t.Errorf("decision hash not deterministic: %s vs %s",
			resp1.DecisionHash, resp2.DecisionHash)
	}
}

func TestHelmPDP_ContextDeadline(t *testing.T) {
	pdp := NewHelmPDP("v0.1.0", map[string]bool{"res": true})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	resp, err := pdp.Evaluate(ctx, &DecisionRequest{
		Principal: "user:alice",
		Action:    "read",
		Resource:  "res",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allow {
		t.Error("cancelled context must deny (fail-closed)")
	}
}

func TestComputeDecisionHash(t *testing.T) {
	resp := &DecisionResponse{
		Allow:      true,
		ReasonCode: "",
		PolicyRef:  "helm:v1",
	}
	hash, err := ComputeDecisionHash(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("expected sha256: prefix, got %s", hash)
	}

	// Deterministic
	hash2, _ := ComputeDecisionHash(resp)
	if hash != hash2 {
		t.Errorf("hash not deterministic: %s vs %s", hash, hash2)
	}
}
