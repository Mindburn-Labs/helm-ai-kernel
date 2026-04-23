package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
)

// ────────────────────────────────────────────────────────────────────────
// Catalog with 500 tools
// ────────────────────────────────────────────────────────────────────────

func TestStress_Catalog500ToolRegistration(t *testing.T) {
	cat := NewToolCatalog()
	for i := 0; i < 500; i++ {
		err := cat.Register(context.Background(), ToolRef{Name: fmt.Sprintf("tool-%d", i), Description: "desc"})
		if err != nil {
			t.Fatalf("register tool %d: %v", i, err)
		}
	}
	results, _ := cat.Search(context.Background(), "")
	if len(results) != 500 {
		t.Fatalf("expected 500 tools, got %d", len(results))
	}
}

func TestStress_Catalog500ToolSearch(t *testing.T) {
	cat := NewToolCatalog()
	for i := 0; i < 500; i++ {
		_ = cat.Register(context.Background(), ToolRef{Name: fmt.Sprintf("tool-%d", i), Description: fmt.Sprintf("desc-%d", i)})
	}
	results, _ := cat.Search(context.Background(), "tool-42")
	found := false
	for _, r := range results {
		if r.Name == "tool-42" {
			found = true
		}
	}
	if !found {
		t.Fatal("tool-42 not found in search results")
	}
}

func TestStress_CatalogLookupAfterBulkRegister(t *testing.T) {
	cat := NewToolCatalog()
	for i := 0; i < 500; i++ {
		_ = cat.Register(context.Background(), ToolRef{Name: fmt.Sprintf("t-%d", i), Description: "d"})
	}
	for i := 0; i < 500; i++ {
		if _, ok := cat.Lookup(fmt.Sprintf("t-%d", i)); !ok {
			t.Fatalf("tool t-%d not found", i)
		}
	}
}

func TestStress_CatalogConcurrentRegisterAndSearch(t *testing.T) {
	cat := NewToolCatalog()
	var wg sync.WaitGroup
	for i := 0; i < 250; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			_ = cat.Register(context.Background(), ToolRef{Name: fmt.Sprintf("c-%d", n), Description: "d"})
		}(i)
		go func(n int) {
			defer wg.Done()
			_, _ = cat.Search(context.Background(), fmt.Sprintf("c-%d", n))
		}(i)
	}
	wg.Wait()
}

func TestStress_CatalogToolRefValidateEmpty(t *testing.T) {
	ref := ToolRef{Name: ""}
	if ref.Validate() == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestStress_CatalogRegisterInvalidRef(t *testing.T) {
	cat := NewToolCatalog()
	err := cat.Register(context.Background(), ToolRef{Name: ""})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestStress_CatalogAuditToolCall(t *testing.T) {
	cat := NewToolCatalog()
	receipt, err := cat.AuditToolCall("tool-a", map[string]any{"key": "val"}, "result")
	if err != nil || receipt.ToolName != "tool-a" {
		t.Fatalf("audit failed: err=%v receipt=%+v", err, receipt)
	}
}

func TestStress_CatalogRegisterCommonTools(t *testing.T) {
	cat := NewToolCatalog()
	cat.RegisterCommonTools()
	_, ok := cat.Lookup("file_read")
	if !ok {
		t.Fatal("file_read not found after RegisterCommonTools")
	}
}

// ────────────────────────────────────────────────────────────────────────
// 200 concurrent sessions
// ────────────────────────────────────────────────────────────────────────

func TestStress_SessionStore200ConcurrentCreate(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Create(LatestProtocolVersion, "client")
			if err != nil {
				t.Errorf("create session: %v", err)
			}
		}()
	}
	wg.Wait()
	if store.Len() != 200 {
		t.Fatalf("expected 200 sessions, got %d", store.Len())
	}
}

func TestStress_SessionStore200ConcurrentGet(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()
	ids := make([]string, 200)
	for i := 0; i < 200; i++ {
		ids[i], _ = store.Create(LatestProtocolVersion, "c")
	}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(sid string) {
			defer wg.Done()
			if store.Get(sid) == nil {
				t.Errorf("session %s not found", sid)
			}
		}(id)
	}
	wg.Wait()
}

func TestStress_SessionStoreDeleteConcurrent(t *testing.T) {
	store := NewSessionStore(5 * time.Minute)
	defer store.Stop()
	ids := make([]string, 100)
	for i := 0; i < 100; i++ {
		ids[i], _ = store.Create(LatestProtocolVersion, "c")
	}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(sid string) {
			defer wg.Done()
			store.Delete(sid)
		}(id)
	}
	wg.Wait()
	if store.Len() != 0 {
		t.Fatalf("expected 0 sessions after delete, got %d", store.Len())
	}
}

// ────────────────────────────────────────────────────────────────────────
// Session reaping under load
// ────────────────────────────────────────────────────────────────────────

func TestStress_SessionReapExpired(t *testing.T) {
	store := NewSessionStore(1 * time.Millisecond)
	defer store.Stop()
	for i := 0; i < 50; i++ {
		_, _ = store.Create(LatestProtocolVersion, "c")
	}
	time.Sleep(20 * time.Millisecond)
	// Trigger reaping by getting a nonexistent session
	store.Get("nonexistent")
	time.Sleep(20 * time.Millisecond)
	if store.Len() > 50 {
		t.Fatalf("sessions should have been reaped, got %d", store.Len())
	}
}

func TestStress_SessionGetExpiredReturnsNil(t *testing.T) {
	store := NewSessionStore(1 * time.Millisecond)
	defer store.Stop()
	id, _ := store.Create(LatestProtocolVersion, "c")
	time.Sleep(10 * time.Millisecond)
	if store.Get(id) != nil {
		t.Fatal("expected nil for expired session")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Governance firewall with 100 requests
// ────────────────────────────────────────────────────────────────────────

type mockPolicyEvaluator struct {
	verdict string
	reason  string
}

func (m *mockPolicyEvaluator) EvaluateDecision(_ context.Context, _ guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	return &contracts.DecisionRecord{Verdict: m.verdict, Reason: m.reason}, nil
}

func TestStress_GovernanceFirewall100Allows(t *testing.T) {
	fw := NewGovernanceFirewall(&mockPolicyEvaluator{verdict: string(contracts.VerdictAllow)}, NewToolCatalog())
	for i := 0; i < 100; i++ {
		err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{ToolName: fmt.Sprintf("tool-%d", i), SessionID: "s"})
		if err != nil {
			t.Fatalf("expected allow for tool-%d, got %v", i, err)
		}
	}
}

func TestStress_GovernanceFirewall100Denies(t *testing.T) {
	fw := NewGovernanceFirewall(&mockPolicyEvaluator{verdict: string(contracts.VerdictDeny), reason: "policy"}, NewToolCatalog())
	for i := 0; i < 100; i++ {
		err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{ToolName: "t", SessionID: "s"})
		if err == nil {
			t.Fatalf("expected deny at iteration %d", i)
		}
	}
}

func TestStress_GovernanceFirewallEscalateReturnsError(t *testing.T) {
	fw := NewGovernanceFirewall(&mockPolicyEvaluator{verdict: string(contracts.VerdictEscalate), reason: "needs approval"}, NewToolCatalog())
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{ToolName: "t", SessionID: "s"})
	if err == nil {
		t.Fatal("expected escalate error")
	}
}

func TestStress_GovernanceFirewallDelegationScopeViolation(t *testing.T) {
	fw := NewGovernanceFirewall(&mockPolicyEvaluator{verdict: string(contracts.VerdictAllow)}, NewToolCatalog())
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "forbidden-tool",
		SessionID:              "s",
		DelegationAllowedTools: []string{"tool-a", "tool-b"},
	})
	if err == nil {
		t.Fatal("expected delegation scope violation")
	}
}

func TestStress_GovernanceFirewallDelegationScopeAllowed(t *testing.T) {
	fw := NewGovernanceFirewall(&mockPolicyEvaluator{verdict: string(contracts.VerdictAllow)}, NewToolCatalog())
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "tool-a",
		SessionID:              "s",
		DelegationAllowedTools: []string{"tool-a", "tool-b"},
	})
	if err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

func TestStress_GovernanceFirewallInterceptPlanAllAllow(t *testing.T) {
	fw := NewGovernanceFirewall(&mockPolicyEvaluator{verdict: string(contracts.VerdictAllow)}, NewToolCatalog())
	steps := make([]ToolExecutionRequest, 10)
	for i := range steps {
		steps[i] = ToolExecutionRequest{ToolName: fmt.Sprintf("t-%d", i), SessionID: "s"}
	}
	pd, err := fw.InterceptPlan(context.Background(), ToolExecutionPlan{PlanID: "p1", Steps: steps})
	if err != nil || pd.Status != string(contracts.VerdictAllow) {
		t.Fatalf("expected all-allow plan, got status=%s err=%v", pd.Status, err)
	}
}

func TestStress_GovernanceFirewallInterceptPlanOneDeny(t *testing.T) {
	eval := &mockPolicyEvaluator{verdict: string(contracts.VerdictDeny)}
	fw := NewGovernanceFirewall(eval, NewToolCatalog())
	steps := []ToolExecutionRequest{{ToolName: "t", SessionID: "s"}}
	pd, _ := fw.InterceptPlan(context.Background(), ToolExecutionPlan{PlanID: "p1", Steps: steps})
	if pd.Status != string(contracts.VerdictDeny) {
		t.Fatalf("expected DENY plan status, got %s", pd.Status)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Protocol version tests
// ────────────────────────────────────────────────────────────────────────

func TestStress_NegotiateLatestVersion(t *testing.T) {
	v, ok := NegotiateProtocolVersion(LatestProtocolVersion)
	if !ok || v != LatestProtocolVersion {
		t.Fatalf("expected %s, got %s (ok=%v)", LatestProtocolVersion, v, ok)
	}
}

func TestStress_NegotiateLegacyVersion(t *testing.T) {
	v, ok := NegotiateProtocolVersion(LegacyProtocolVersion)
	if !ok || v != LegacyProtocolVersion {
		t.Fatalf("expected %s, got %s", LegacyProtocolVersion, v)
	}
}

func TestStress_NegotiateMiddleVersion(t *testing.T) {
	v, ok := NegotiateProtocolVersion("2025-06-18")
	if !ok || v != "2025-06-18" {
		t.Fatalf("expected 2025-06-18, got %s", v)
	}
}

func TestStress_NegotiateEmptyDefault(t *testing.T) {
	v, ok := NegotiateProtocolVersion("")
	if !ok || v != LatestProtocolVersion {
		t.Fatalf("expected latest for empty request, got %s", v)
	}
}

func TestStress_NegotiateUnsupported(t *testing.T) {
	_, ok := NegotiateProtocolVersion("1999-01-01")
	if ok {
		t.Fatal("expected unsupported version rejection")
	}
}

func TestStress_AllSupportedVersionsNegotiate(t *testing.T) {
	for _, v := range SupportedProtocolVersions {
		negotiated, ok := NegotiateProtocolVersion(v)
		if !ok || negotiated != v {
			t.Fatalf("version %s failed negotiation", v)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────
// Annotation hints
// ────────────────────────────────────────────────────────────────────────

func TestStress_AnnotationReadOnlyHint(t *testing.T) {
	a := &ToolAnnotations{ReadOnlyHint: true}
	p := toolAnnotationsPayload(a)
	if p["readOnlyHint"] != true {
		t.Fatal("readOnlyHint not set")
	}
}

func TestStress_AnnotationDestructiveHint(t *testing.T) {
	a := &ToolAnnotations{DestructiveHint: true}
	p := toolAnnotationsPayload(a)
	if p["destructiveHint"] != true {
		t.Fatal("destructiveHint not set")
	}
}

func TestStress_AnnotationIdempotentHint(t *testing.T) {
	a := &ToolAnnotations{IdempotentHint: true}
	p := toolAnnotationsPayload(a)
	if p["idempotentHint"] != true {
		t.Fatal("idempotentHint not set")
	}
}

func TestStress_AnnotationOpenWorldHint(t *testing.T) {
	a := &ToolAnnotations{OpenWorldHint: true}
	p := toolAnnotationsPayload(a)
	if p["openWorldHint"] != true {
		t.Fatal("openWorldHint not set")
	}
}

func TestStress_AnnotationNilReturnsNil(t *testing.T) {
	p := toolAnnotationsPayload(nil)
	if p != nil {
		t.Fatal("expected nil for nil annotations")
	}
}

func TestStress_AnnotationAllFalseReturnsEmpty(t *testing.T) {
	a := &ToolAnnotations{}
	p := toolAnnotationsPayload(a)
	if len(p) != 0 {
		t.Fatalf("expected empty payload, got %v", p)
	}
}

func TestStress_ToolDescriptorPayloadTitle(t *testing.T) {
	ref := ToolRef{Name: "t", Description: "d", Title: "T"}
	p := ToolDescriptorPayload(ref)
	if p["title"] != "T" {
		t.Fatal("title not set in descriptor")
	}
}

func TestStress_ToolDescriptorPayloadOutputSchema(t *testing.T) {
	ref := ToolRef{Name: "t", Description: "d", OutputSchema: map[string]any{"type": "object"}}
	p := ToolDescriptorPayload(ref)
	if p["outputSchema"] == nil {
		t.Fatal("outputSchema not set in descriptor")
	}
}

func TestStress_ToolResultPayloadFallbackContent(t *testing.T) {
	resp := ToolExecutionResponse{Content: "hello", IsError: false}
	p := ToolResultPayload(resp)
	content := p["content"].([]ToolContentItem)
	if len(content) != 1 || content[0].Text != "hello" {
		t.Fatal("fallback content not set")
	}
}

func TestStress_StructuredTextContentEmpty(t *testing.T) {
	items := StructuredTextContent(nil, "fallback")
	if len(items) != 1 || items[0].Text != "fallback" {
		t.Fatal("expected fallback for nil payload")
	}
}

func TestStress_StructuredTextContentWithPayload(t *testing.T) {
	items := StructuredTextContent(map[string]any{"key": "val"}, "")
	if len(items) != 1 {
		t.Fatal("expected one content item")
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(items[0].Text), &m)
	if m["key"] != "val" {
		t.Fatal("payload not properly serialized")
	}
}

func TestStress_ElicitationVerdictEscalate(t *testing.T) {
	if !IsElicitationVerdict("ESCALATE") {
		t.Fatal("ESCALATE should be elicitation verdict")
	}
}

func TestStress_ElicitationVerdictPending(t *testing.T) {
	if !IsElicitationVerdict("PENDING") {
		t.Fatal("PENDING should be elicitation verdict")
	}
}

func TestStress_ElicitationVerdictAllow(t *testing.T) {
	if IsElicitationVerdict("ALLOW") {
		t.Fatal("ALLOW should not be elicitation verdict")
	}
}

func TestStress_MarshalElicitationNotification(t *testing.T) {
	data, err := MarshalElicitationNotification("req-1", ElicitationRequest{Message: "approve?"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	if m["method"] != "elicitation/create" {
		t.Fatal("method not set correctly")
	}
}
