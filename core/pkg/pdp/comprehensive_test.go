package pdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCedarPDP_PermitMatchesResource(t *testing.T) {
	p, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "v1",
		Policies: []CedarPolicy{{ID: "p1", Effect: "permit", ResourceMatch: `Resource::"fs"`}},
	})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Resource: "fs"})
	if !resp.Allow {
		t.Fatal("expected ALLOW for matching resource")
	}
}

func TestCedarPDP_DenyNonMatchingResource(t *testing.T) {
	p, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "v1",
		Policies: []CedarPolicy{{ID: "p1", Effect: "permit", ResourceMatch: `Resource::"fs"`}},
	})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Resource: "network"})
	if resp.Allow {
		t.Fatal("expected DENY for non-matching resource")
	}
}

func TestCedarPDP_ForbidAlwaysWins(t *testing.T) {
	p, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "v1",
		Policies: []CedarPolicy{
			{ID: "p1", Effect: "permit"},
			{ID: "p2", Effect: "forbid"},
		},
	})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Action: "any"})
	if resp.Allow {
		t.Fatal("forbid should override permit")
	}
}

func TestCedarPDP_PolicyRefPrefix(t *testing.T) {
	p, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "abc",
		Policies:  []CedarPolicy{{ID: "p1", Effect: "permit"}},
	})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{})
	if resp.PolicyRef != "cedar:abc" {
		t.Fatalf("expected cedar:abc, got %s", resp.PolicyRef)
	}
}

func TestCedarPDP_DecisionHashPresent(t *testing.T) {
	p, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "v1",
		Policies:  []CedarPolicy{{ID: "p1", Effect: "permit"}},
	})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{})
	if !strings.HasPrefix(resp.DecisionHash, "sha256:") {
		t.Fatalf("decision hash should start with sha256:, got %s", resp.DecisionHash)
	}
}

func TestCedarPDP_ContextConditionMismatch(t *testing.T) {
	p, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "v1",
		Policies: []CedarPolicy{{
			ID: "p1", Effect: "permit",
			ContextConditions: map[string]string{"env": "prod"},
		}},
	})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{
		Context: map[string]any{"env": "staging"},
	})
	if resp.Allow {
		t.Fatal("mismatched context condition should deny")
	}
}

func TestCedarPDP_ContextConditionMissing(t *testing.T) {
	p, _ := NewCedarPDP(CedarConfig{
		PolicyRef: "v1",
		Policies: []CedarPolicy{{
			ID: "p1", Effect: "permit",
			ContextConditions: map[string]string{"env": "prod"},
		}},
	})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Context: map[string]any{}})
	if resp.Allow {
		t.Fatal("missing context key should deny")
	}
}

func TestCedarPDP_PolicyHashStable(t *testing.T) {
	cfg := CedarConfig{PolicyRef: "v1", Policies: []CedarPolicy{{ID: "p1", Effect: "permit"}}}
	p1, _ := NewCedarPDP(cfg)
	p2, _ := NewCedarPDP(cfg)
	if p1.PolicyHash() != p2.PolicyHash() {
		t.Fatal("policy hash should be stable across instances")
	}
}

func TestOpaPDP_AllowWithEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(opaResponse{Result: &opaResult{Allow: true}})
	}))
	defer srv.Close()
	p, _ := NewOpaPDP(OpaConfig{Endpoint: srv.URL, PolicyRef: "v1"})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{
		Principal: "a", Action: "b", Resource: "c",
		Environment: map[string]string{"region": "us"},
	})
	if !resp.Allow {
		t.Fatal("expected ALLOW")
	}
}

func TestOpaPDP_PolicyRefPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(opaResponse{Result: &opaResult{Allow: true}})
	}))
	defer srv.Close()
	p, _ := NewOpaPDP(OpaConfig{Endpoint: srv.URL, PolicyRef: "xyz"})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Action: "a"})
	if resp.PolicyRef != "opa:xyz" {
		t.Fatalf("expected opa:xyz, got %s", resp.PolicyRef)
	}
}

func TestOpaPDP_DenyReasonNormalized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(opaResponse{Result: &opaResult{Allow: false, ReasonCode: "custom"}})
	}))
	defer srv.Close()
	p, _ := NewOpaPDP(OpaConfig{Endpoint: srv.URL})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Action: "a"})
	if resp.ReasonCode != "PDP_DENY" {
		t.Fatalf("non-canonical reason should normalize to PDP_DENY, got %s", resp.ReasonCode)
	}
}

func TestOpaPDP_DefaultTimeout(t *testing.T) {
	p, _ := NewOpaPDP(OpaConfig{Endpoint: "http://localhost:9999"})
	if p.client.Timeout != 500*time.Millisecond {
		t.Fatalf("default timeout should be 500ms, got %v", p.client.Timeout)
	}
}

func TestOpaPDP_CustomTimeout(t *testing.T) {
	p, _ := NewOpaPDP(OpaConfig{Endpoint: "http://localhost:9999", TimeoutMs: 2000})
	if p.client.Timeout != 2000*time.Millisecond {
		t.Fatalf("custom timeout should be 2000ms, got %v", p.client.Timeout)
	}
}

func TestHelmPDP_UnknownResourceAllows(t *testing.T) {
	p := NewHelmPDP("v1", map[string]bool{"known": true})
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Resource: "unknown"})
	if !resp.Allow {
		t.Fatal("unknown resource should be allowed when no rule matches")
	}
}

func TestHelmPDP_NilRulesAllows(t *testing.T) {
	p := NewHelmPDP("v1", nil)
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Resource: "anything"})
	if !resp.Allow {
		t.Fatal("nil rules should allow all resources")
	}
}

func TestHelmPDP_PolicyRefIncludesVersion(t *testing.T) {
	p := NewHelmPDP("v2.0", nil)
	resp, _ := p.Evaluate(context.Background(), &DecisionRequest{Resource: "r"})
	if resp.PolicyRef != "helm:v2.0" {
		t.Fatalf("expected helm:v2.0, got %s", resp.PolicyRef)
	}
}

func TestHelmPDP_PolicyHashNonEmpty(t *testing.T) {
	p := NewHelmPDP("v1", map[string]bool{"a": true})
	if p.PolicyHash() == "" {
		t.Fatal("policy hash should not be empty")
	}
}

func TestHelmPDP_PolicyHashDiffers(t *testing.T) {
	p1 := NewHelmPDP("v1", map[string]bool{"a": true})
	p2 := NewHelmPDP("v2", map[string]bool{"a": true})
	if p1.PolicyHash() == p2.PolicyHash() {
		t.Fatal("different versions should produce different policy hashes")
	}
}

func TestPDPInterface_CedarSatisfies(t *testing.T) {
	var _ PolicyDecisionPoint = (*CedarPDP)(nil)
}

func TestPDPInterface_OpaSatisfies(t *testing.T) {
	var _ PolicyDecisionPoint = (*OpaPDP)(nil)
}

func TestPDPInterface_HelmSatisfies(t *testing.T) {
	var _ PolicyDecisionPoint = (*HelmPDP)(nil)
}

func TestDecisionRequest_FieldsPreserved(t *testing.T) {
	ts := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	req := &DecisionRequest{
		Principal: "u", Action: "a", Resource: "r",
		Context: map[string]any{"k": "v"}, Timestamp: ts,
	}
	if req.Principal != "u" || req.Action != "a" || req.Timestamp != ts {
		t.Fatal("request fields not preserved")
	}
}

func TestDecisionResponse_JSONRoundTrip(t *testing.T) {
	resp := &DecisionResponse{Allow: true, ReasonCode: "", PolicyRef: "helm:v1", DecisionHash: "sha256:abc"}
	data, _ := json.Marshal(resp)
	var out DecisionResponse
	json.Unmarshal(data, &out)
	if out.Allow != resp.Allow || out.DecisionHash != resp.DecisionHash {
		t.Fatal("response JSON round-trip mismatch")
	}
}

func TestComputeDecisionHash_DenyVsAllow(t *testing.T) {
	allow := &DecisionResponse{Allow: true, PolicyRef: "p"}
	deny := &DecisionResponse{Allow: false, PolicyRef: "p", ReasonCode: "PDP_DENY"}
	h1, _ := ComputeDecisionHash(allow)
	h2, _ := ComputeDecisionHash(deny)
	if h1 == h2 {
		t.Fatal("allow and deny should have different hashes")
	}
}
