package mcp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// ── 1-5: Tool catalog with 200 tools ────────────────────────────

func TestDeep_Register200Tools(t *testing.T) {
	c := NewToolCatalog()
	for i := 0; i < 200; i++ {
		err := c.Register(context.Background(), ToolRef{Name: fmt.Sprintf("tool_%d", i), Description: "auto"})
		if err != nil {
			t.Fatalf("register tool_%d: %v", i, err)
		}
	}
	results, _ := c.Search(context.Background(), "")
	if len(results) != 200 {
		t.Fatalf("want 200 tools got %d", len(results))
	}
}

func TestDeep_CatalogSearchSubstring(t *testing.T) {
	c := NewToolCatalog()
	for i := 0; i < 200; i++ {
		c.Register(context.Background(), ToolRef{Name: fmt.Sprintf("tool_%d", i), Description: "auto"})
	}
	results, _ := c.Search(context.Background(), "tool_1")
	if len(results) < 10 {
		t.Fatalf("search 'tool_1' should match >=10 tools, got %d", len(results))
	}
}

func TestDeep_CatalogLookupExact(t *testing.T) {
	c := NewToolCatalog()
	for i := 0; i < 200; i++ {
		c.Register(context.Background(), ToolRef{Name: fmt.Sprintf("tool_%d", i), Description: "auto"})
	}
	_, ok := c.Lookup("tool_199")
	if !ok {
		t.Error("lookup tool_199 should succeed")
	}
	_, ok = c.Lookup("nonexistent")
	if ok {
		t.Error("lookup nonexistent should fail")
	}
}

func TestDeep_CatalogValidateEmptyName(t *testing.T) {
	c := NewToolCatalog()
	err := c.Register(context.Background(), ToolRef{Name: "", Description: "bad"})
	if err == nil {
		t.Error("empty name should fail validation")
	}
}

func TestDeep_CatalogConcurrentRegister(t *testing.T) {
	c := NewToolCatalog()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Register(context.Background(), ToolRef{Name: fmt.Sprintf("t%d", i), Description: "d"})
		}(i)
	}
	wg.Wait()
	all, _ := c.Search(context.Background(), "")
	if len(all) != 200 {
		t.Fatalf("concurrent register: want 200 got %d", len(all))
	}
}

// ── 6-10: Session store reaping under load ──────────────────────

func TestDeep_SessionCreateAndGet(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	id, err := store.Create("2025-11-25", "test-client")
	if err != nil {
		t.Fatal(err)
	}
	s := store.Get(id)
	if s == nil {
		t.Fatal("session should exist after create")
	}
	if s.ProtocolVersion != "2025-11-25" {
		t.Fatalf("protocol version mismatch: %s", s.ProtocolVersion)
	}
}

func TestDeep_SessionExpiry(t *testing.T) {
	store := NewSessionStore(time.Millisecond)
	defer store.Stop()
	id, _ := store.Create("2025-11-25", "c")
	time.Sleep(5 * time.Millisecond)
	if store.Get(id) != nil {
		t.Error("expired session should return nil")
	}
}

func TestDeep_SessionDelete(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	id, _ := store.Create("2025-11-25", "c")
	store.Delete(id)
	if store.Get(id) != nil {
		t.Error("deleted session should return nil")
	}
}

func TestDeep_SessionLen(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	for i := 0; i < 50; i++ {
		store.Create("2025-11-25", "c")
	}
	if store.Len() != 50 {
		t.Fatalf("want 50 sessions got %d", store.Len())
	}
}

func TestDeep_SessionConcurrentCreate(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Create("2025-11-25", "c")
		}()
	}
	wg.Wait()
	if store.Len() != 100 {
		t.Fatalf("concurrent creates: want 100 got %d", store.Len())
	}
}

// ── 11-15: Governance firewall with delegation ──────────────────

type deepMockEval struct {
	verdict string
	reason  string
	err     error
}

func (m *deepMockEval) EvaluateDecision(_ context.Context, _ guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &contracts.DecisionRecord{
		ID:      "deep-test",
		Verdict: m.verdict,
		Reason:  m.reason,
	}, nil
}

func TestDeep_GovernanceFirewallAllow(t *testing.T) {
	gf := NewGovernanceFirewall(&deepMockEval{verdict: string(contracts.VerdictAllow)}, NewToolCatalog())
	err := gf.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName: "read", SessionID: "s1",
	})
	if err != nil {
		t.Fatalf("allow should pass: %v", err)
	}
}

func TestDeep_DelegationScopeBlock(t *testing.T) {
	gf := NewGovernanceFirewall(&deepMockEval{verdict: string(contracts.VerdictAllow)}, NewToolCatalog())
	err := gf.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "admin_delete",
		DelegationAllowedTools: []string{"read", "write"},
	})
	if err == nil {
		t.Error("out-of-scope tool must be blocked")
	}
}

func TestDeep_DelegationScopeAllow(t *testing.T) {
	gf := NewGovernanceFirewall(&deepMockEval{verdict: string(contracts.VerdictAllow)}, NewToolCatalog())
	err := gf.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "read",
		DelegationAllowedTools: []string{"read", "write"},
		SessionID:              "s1",
	})
	if err != nil {
		t.Fatalf("in-scope tool with ALLOW verdict should pass: %v", err)
	}
}

func TestDeep_GovernanceFirewallDeny(t *testing.T) {
	gf := NewGovernanceFirewall(&deepMockEval{verdict: string(contracts.VerdictDeny), reason: "policy"}, nil)
	err := gf.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName: "danger", SessionID: "s1",
	})
	if err == nil {
		t.Error("DENY verdict should block")
	}
}

func TestDeep_GovernanceFirewallEscalate(t *testing.T) {
	gf := NewGovernanceFirewall(&deepMockEval{verdict: string(contracts.VerdictEscalate), reason: "approval needed"}, nil)
	err := gf.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName: "risky", SessionID: "s1",
	})
	if err == nil {
		t.Error("ESCALATE verdict should block")
	}
}

// ── 16-20: Protocol negotiation ─────────────────────────────────

func TestDeep_NegotiateLatest(t *testing.T) {
	v, ok := NegotiateProtocolVersion("2025-11-25")
	if !ok || v != "2025-11-25" {
		t.Fatalf("latest should negotiate: %s %v", v, ok)
	}
}

func TestDeep_NegotiateLegacy(t *testing.T) {
	v, ok := NegotiateProtocolVersion("2025-03-26")
	if !ok || v != "2025-03-26" {
		t.Fatalf("legacy should negotiate: %s %v", v, ok)
	}
}

func TestDeep_NegotiateEmpty(t *testing.T) {
	v, ok := NegotiateProtocolVersion("")
	if !ok || v != LatestProtocolVersion {
		t.Fatalf("empty should return latest: %s %v", v, ok)
	}
}

func TestDeep_NegotiateUnsupported(t *testing.T) {
	_, ok := NegotiateProtocolVersion("1999-01-01")
	if ok {
		t.Error("unsupported version must not negotiate")
	}
}

func TestDeep_ConcurrentNegotiate(t *testing.T) {
	var wg sync.WaitGroup
	versions := []string{"2025-11-25", "2025-06-18", "2025-03-26", "", "bad"}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			NegotiateProtocolVersion(versions[i%len(versions)])
		}(i)
	}
	wg.Wait()
}

// ── 21-25: Tool descriptor / content / annotations ──────────────

func TestDeep_ToolDescriptorPayload(t *testing.T) {
	ref := ToolRef{
		Name:         "tool1",
		Title:        "Tool One",
		Description:  "desc",
		Schema:       map[string]any{"type": "object"},
		OutputSchema: map[string]any{"type": "object"},
		Annotations:  &ToolAnnotations{ReadOnlyHint: true, DestructiveHint: true},
	}
	p := ToolDescriptorPayload(ref)
	if p["title"] != "Tool One" {
		t.Error("title missing")
	}
	if p["outputSchema"] == nil {
		t.Error("outputSchema missing")
	}
	ann := p["annotations"].(map[string]any)
	if !ann["readOnlyHint"].(bool) {
		t.Error("readOnlyHint missing")
	}
}

func TestDeep_ToolResultPayloadFallback(t *testing.T) {
	resp := ToolExecutionResponse{Content: "hello", IsError: false}
	p := ToolResultPayload(resp)
	items := p["content"].([]ToolContentItem)
	if len(items) != 1 || items[0].Text != "hello" {
		t.Error("fallback content should be text item")
	}
}

func TestDeep_StructuredTextContentEmpty(t *testing.T) {
	items := StructuredTextContent(nil, "fallback")
	if len(items) != 1 || items[0].Text != "fallback" {
		t.Error("empty payload should use fallback")
	}
}

func TestDeep_StructuredTextContentNil(t *testing.T) {
	items := StructuredTextContent(nil, "")
	if items != nil {
		t.Error("nil payload + empty fallback should return nil")
	}
}

func TestDeep_AuditToolCall(t *testing.T) {
	c := NewToolCatalog()
	receipt, err := c.AuditToolCall("tool1", map[string]any{"a": 1}, "result")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ToolName != "tool1" {
		t.Error("receipt tool name mismatch")
	}
}
