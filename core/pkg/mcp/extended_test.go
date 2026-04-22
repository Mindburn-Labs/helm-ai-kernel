package mcp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── Protocol Version Negotiation Edge Cases ─────────────────

func TestNegotiate_FutureVersionRejected(t *testing.T) {
	_, ok := NegotiateProtocolVersion("2099-12-31")
	if ok {
		t.Error("far-future version should be rejected")
	}
}

func TestNegotiate_WhitespaceVersionRejected(t *testing.T) {
	_, ok := NegotiateProtocolVersion(" 2025-11-25 ")
	if ok {
		t.Error("whitespace-padded version should be rejected (exact match)")
	}
}

func TestNegotiate_AllSupportedVersionsAccepted(t *testing.T) {
	for _, v := range SupportedProtocolVersions {
		got, ok := NegotiateProtocolVersion(v)
		if !ok || got != v {
			t.Errorf("supported version %s should be accepted", v)
		}
	}
}

func TestNegotiate_EmptyAndLatestConsistent(t *testing.T) {
	v1, _ := NegotiateProtocolVersion("")
	v2, _ := NegotiateProtocolVersion(LatestProtocolVersion)
	if v1 != v2 {
		t.Errorf("empty request and latest should agree: %s vs %s", v1, v2)
	}
}

// ── Tool Catalog with Many Tools ────────────────────────────

func TestCatalog_Register100Tools(t *testing.T) {
	c := NewToolCatalog()
	for i := 0; i < 100; i++ {
		err := c.Register(context.Background(), ToolRef{Name: fmt.Sprintf("tool-%d", i), Description: "desc"})
		if err != nil {
			t.Fatalf("register tool-%d failed: %v", i, err)
		}
	}
	results, _ := c.Search(context.Background(), "")
	if len(results) != 100 {
		t.Errorf("expected 100 tools, got %d", len(results))
	}
}

func TestCatalog_SearchNoMatch(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "alpha", Description: "first"})
	results, _ := c.Search(context.Background(), "zzzzz")
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestCatalog_ConcurrentRegisterAndSearch(t *testing.T) {
	c := NewToolCatalog()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			_ = c.Register(context.Background(), ToolRef{Name: fmt.Sprintf("t-%d", idx), Description: "d"})
		}(i)
		go func(idx int) {
			defer wg.Done()
			_, _ = c.Search(context.Background(), fmt.Sprintf("t-%d", idx))
		}(i)
	}
	wg.Wait()
}

// ── Session TTL Boundary ────────────────────────────────────

func TestSessionStore_AccessRefreshesTTL(t *testing.T) {
	s := NewSessionStore(100 * time.Millisecond)
	defer s.Stop()
	id, _ := s.Create("v1", "c")
	time.Sleep(60 * time.Millisecond)
	session := s.Get(id) // should refresh LastAccess
	if session == nil {
		t.Fatal("session should still be alive after refresh")
	}
	time.Sleep(60 * time.Millisecond)
	session = s.Get(id) // refresh again
	if session == nil {
		t.Fatal("session should still be alive after second refresh within TTL")
	}
}

func TestSessionStore_LenAfterDelete(t *testing.T) {
	s := NewSessionStore(5 * time.Minute)
	defer s.Stop()
	id1, _ := s.Create("v1", "a")
	_, _ = s.Create("v1", "b")
	s.Delete(id1)
	if s.Len() != 1 {
		t.Errorf("expected 1 after delete, got %d", s.Len())
	}
}

func TestSessionStore_NegativeTTLDefaults(t *testing.T) {
	s := NewSessionStore(-5 * time.Minute)
	defer s.Stop()
	if s.ttl != DefaultSessionTTL {
		t.Errorf("expected default TTL, got %v", s.ttl)
	}
}

// ── Governance Firewall with Complex Delegation ─────────────

func TestGovernanceFirewall_MultipleDelegationTools(t *testing.T) {
	eval := &mockEvaluator{verdict: "ALLOW"}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "safe_b",
		SessionID:              "s",
		DelegationAllowedTools: []string{"safe_a", "safe_b", "safe_c"},
	})
	if err != nil {
		t.Fatalf("tool in delegation scope should pass: %v", err)
	}
}

func TestGovernanceFirewall_EmptyDelegationAllowsAll(t *testing.T) {
	eval := &mockEvaluator{verdict: "ALLOW"}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "anything",
		SessionID:              "s",
		DelegationAllowedTools: []string{},
	})
	if err != nil {
		t.Fatalf("empty delegation list should allow all: %v", err)
	}
}

func TestGovernanceFirewall_DelegationSessionIDPassedToContext(t *testing.T) {
	eval := &mockEvaluator{verdict: "ALLOW"}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:            "tool",
		SessionID:           "s",
		DelegationSessionID: "deleg-123",
		DelegationVerifier:  "verifier-abc",
	})
	if err != nil {
		t.Fatalf("delegation metadata should not cause error: %v", err)
	}
}

// ── Concurrent Session Creation ─────────────────────────────

func TestSessionStore_ConcurrentCreate(t *testing.T) {
	s := NewSessionStore(5 * time.Minute)
	defer s.Stop()
	var wg sync.WaitGroup
	ids := make(chan string, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id, err := s.Create("v1", fmt.Sprintf("client-%d", idx))
			if err != nil {
				t.Errorf("create failed: %v", err)
				return
			}
			ids <- id
		}(i)
	}
	wg.Wait()
	close(ids)
	if s.Len() != 100 {
		t.Errorf("expected 100 sessions, got %d", s.Len())
	}
	seen := make(map[string]bool)
	for id := range ids {
		if seen[id] {
			t.Errorf("duplicate session ID: %s", id)
		}
		seen[id] = true
	}
}

// ── ToolRef and ToolAnnotations ─────────────────────────────

func TestToolAnnotations_AllHints(t *testing.T) {
	ann := &ToolAnnotations{ReadOnlyHint: true, DestructiveHint: true, IdempotentHint: true, OpenWorldHint: true}
	payload := toolAnnotationsPayload(ann)
	if len(payload) != 4 {
		t.Errorf("expected 4 annotation fields, got %d", len(payload))
	}
}

func TestToolAnnotations_EmptyStructReturnsEmptyMap(t *testing.T) {
	ann := &ToolAnnotations{}
	payload := toolAnnotationsPayload(ann)
	if len(payload) != 0 {
		t.Errorf("zero-value annotations should produce empty map, got %d entries", len(payload))
	}
}

func TestToolDescriptor_WithOutputSchema(t *testing.T) {
	ref := ToolRef{Name: "t", Description: "d", OutputSchema: map[string]any{"type": "object"}}
	p := ToolDescriptorPayload(ref)
	if p["outputSchema"] == nil {
		t.Error("outputSchema should be present")
	}
}

func TestToolDescriptor_NoOutputSchema(t *testing.T) {
	ref := ToolRef{Name: "t", Description: "d"}
	p := ToolDescriptorPayload(ref)
	if p["outputSchema"] != nil {
		t.Error("outputSchema should not be present when nil")
	}
}

func TestElicitation_DENYIsNotElicitation(t *testing.T) {
	if IsElicitationVerdict("DENY") {
		t.Error("DENY should not be an elicitation verdict")
	}
}

func TestCatalog_LookupAfterOverwrite(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "t", Description: "v1"})
	_ = c.Register(context.Background(), ToolRef{Name: "t", Description: "v2"})
	ref, ok := c.Lookup("t")
	if !ok || ref.Description != "v2" {
		t.Error("overwritten tool should return latest version")
	}
}
