package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/golang-jwt/jwt/v5"
)

// ---- Protocol version tests ----

func TestLatestProtocolVersionValue(t *testing.T) {
	if LatestProtocolVersion != "2025-11-25" {
		t.Fatalf("expected 2025-11-25, got %s", LatestProtocolVersion)
	}
}

func TestLegacyProtocolVersionValue(t *testing.T) {
	if LegacyProtocolVersion != "2025-03-26" {
		t.Fatalf("expected 2025-03-26, got %s", LegacyProtocolVersion)
	}
}

func TestSupportedProtocolVersionsLength(t *testing.T) {
	if len(SupportedProtocolVersions) != 3 {
		t.Fatalf("expected 3 supported versions, got %d", len(SupportedProtocolVersions))
	}
}

func TestNegotiateProtocolVersion_EmptyRequestReturnsLatest(t *testing.T) {
	v, ok := NegotiateProtocolVersion("")
	if !ok || v != LatestProtocolVersion {
		t.Fatalf("expected (%s, true), got (%s, %v)", LatestProtocolVersion, v, ok)
	}
}

func TestNegotiateProtocolVersion_LatestAccepted(t *testing.T) {
	v, ok := NegotiateProtocolVersion(LatestProtocolVersion)
	if !ok || v != LatestProtocolVersion {
		t.Fatalf("latest version should be accepted")
	}
}

func TestNegotiateProtocolVersion_LegacyAccepted(t *testing.T) {
	v, ok := NegotiateProtocolVersion(LegacyProtocolVersion)
	if !ok || v != LegacyProtocolVersion {
		t.Fatalf("legacy version should be accepted")
	}
}

func TestNegotiateProtocolVersion_MiddleVersionAccepted(t *testing.T) {
	v, ok := NegotiateProtocolVersion("2025-06-18")
	if !ok || v != "2025-06-18" {
		t.Fatalf("middle version should be accepted")
	}
}

func TestNegotiateProtocolVersion_UnknownRejected(t *testing.T) {
	v, ok := NegotiateProtocolVersion("2000-01-01")
	if ok || v != "" {
		t.Fatalf("unknown version should be rejected, got (%s, %v)", v, ok)
	}
}

// ---- ToolDescriptorPayload tests ----

func TestToolDescriptorPayload_BasicFields(t *testing.T) {
	ref := ToolRef{Name: "echo", Description: "echoes input", Schema: map[string]any{"type": "object"}}
	p := ToolDescriptorPayload(ref)
	if p["name"] != "echo" || p["description"] != "echoes input" {
		t.Fatalf("basic fields mismatch: %v", p)
	}
}

func TestToolDescriptorPayload_TitleIncludedWhenSet(t *testing.T) {
	ref := ToolRef{Name: "a", Title: "Alpha Tool", Description: "d"}
	p := ToolDescriptorPayload(ref)
	if p["title"] != "Alpha Tool" {
		t.Fatalf("expected title in payload")
	}
}

func TestToolDescriptorPayload_TitleOmittedWhenEmpty(t *testing.T) {
	ref := ToolRef{Name: "a", Description: "d"}
	p := ToolDescriptorPayload(ref)
	if _, exists := p["title"]; exists {
		t.Fatalf("title should not be in payload when empty")
	}
}

func TestToolDescriptorPayload_OutputSchemaIncluded(t *testing.T) {
	ref := ToolRef{Name: "a", Description: "d", OutputSchema: map[string]any{"type": "string"}}
	p := ToolDescriptorPayload(ref)
	if p["outputSchema"] == nil {
		t.Fatalf("outputSchema should be present")
	}
}

func TestToolDescriptorPayload_AnnotationsIncluded(t *testing.T) {
	ref := ToolRef{Name: "a", Description: "d", Annotations: &ToolAnnotations{ReadOnlyHint: true}}
	p := ToolDescriptorPayload(ref)
	ann, ok := p["annotations"].(map[string]any)
	if !ok || ann["readOnlyHint"] != true {
		t.Fatalf("annotations mismatch: %v", p["annotations"])
	}
}

func TestToolDescriptorPayload_NoAnnotationsWhenNil(t *testing.T) {
	ref := ToolRef{Name: "a", Description: "d"}
	p := ToolDescriptorPayload(ref)
	if _, exists := p["annotations"]; exists {
		t.Fatalf("annotations should not be present when nil")
	}
}

// ---- ToolResultPayload tests ----

func TestToolResultPayload_FallsBackToContentString(t *testing.T) {
	resp := ToolExecutionResponse{Content: "hello", IsError: false}
	p := ToolResultPayload(resp)
	items := p["content"].([]ToolContentItem)
	if len(items) != 1 || items[0].Text != "hello" || items[0].Type != "text" {
		t.Fatalf("expected single text item, got %v", items)
	}
}

func TestToolResultPayload_UsesContentItemsWhenPresent(t *testing.T) {
	resp := ToolExecutionResponse{
		ContentItems: []ToolContentItem{{Type: "text", Text: "custom"}},
		Content:      "ignored",
	}
	p := ToolResultPayload(resp)
	items := p["content"].([]ToolContentItem)
	if items[0].Text != "custom" {
		t.Fatalf("expected ContentItems to take precedence")
	}
}

func TestToolResultPayload_IsErrorField(t *testing.T) {
	resp := ToolExecutionResponse{Content: "fail", IsError: true}
	p := ToolResultPayload(resp)
	if p["isError"] != true {
		t.Fatalf("isError should be true")
	}
}

func TestToolResultPayload_StructuredContentIncluded(t *testing.T) {
	resp := ToolExecutionResponse{Content: "x", StructuredContent: map[string]any{"key": "val"}}
	p := ToolResultPayload(resp)
	sc := p["structuredContent"].(map[string]any)
	if sc["key"] != "val" {
		t.Fatalf("structuredContent mismatch")
	}
}

func TestToolResultPayload_ReceiptIDIncluded(t *testing.T) {
	resp := ToolExecutionResponse{Content: "x", ReceiptID: "rec-123"}
	p := ToolResultPayload(resp)
	if p["receipt_id"] != "rec-123" {
		t.Fatalf("receipt_id mismatch")
	}
}

func TestToolResultPayload_ReceiptIDOmittedWhenEmpty(t *testing.T) {
	resp := ToolExecutionResponse{Content: "x"}
	p := ToolResultPayload(resp)
	if _, exists := p["receipt_id"]; exists {
		t.Fatalf("receipt_id should not be present when empty")
	}
}

// ---- StructuredTextContent tests ----

func TestStructuredTextContent_EmptyPayloadWithFallback(t *testing.T) {
	items := StructuredTextContent(nil, "fallback text")
	if len(items) != 1 || items[0].Text != "fallback text" {
		t.Fatalf("expected fallback, got %v", items)
	}
}

func TestStructuredTextContent_EmptyPayloadNoFallback(t *testing.T) {
	items := StructuredTextContent(nil, "")
	if items != nil {
		t.Fatalf("expected nil, got %v", items)
	}
}

func TestStructuredTextContent_ValidPayloadMarshaledToJSON(t *testing.T) {
	items := StructuredTextContent(map[string]any{"k": "v"}, "fb")
	if len(items) != 1 || items[0].Type != "text" {
		t.Fatalf("expected one text item")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(items[0].Text), &parsed); err != nil {
		t.Fatalf("text should be valid JSON: %v", err)
	}
	if parsed["k"] != "v" {
		t.Fatalf("parsed value mismatch")
	}
}

// ---- ToolRef validation tests ----

func TestToolRefValidate_EmptyNameFails(t *testing.T) {
	ref := ToolRef{Description: "no name"}
	if err := ref.Validate(); err == nil {
		t.Fatalf("expected error for empty name")
	}
}

func TestToolRefValidate_NonEmptyNameSucceeds(t *testing.T) {
	ref := ToolRef{Name: "tool"}
	if err := ref.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- ToolCatalog Register/Search/Lookup tests ----

func TestToolCatalog_RegisterAndLookup(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "mytool", Description: "d"})
	ref, ok := c.Lookup("mytool")
	if !ok || ref.Name != "mytool" {
		t.Fatalf("lookup failed")
	}
}

func TestToolCatalog_LookupMissing(t *testing.T) {
	c := NewToolCatalog()
	_, ok := c.Lookup("nonexistent")
	if ok {
		t.Fatalf("expected not found")
	}
}

func TestToolCatalog_RegisterEmptyNameReturnsError(t *testing.T) {
	c := NewToolCatalog()
	err := c.Register(context.Background(), ToolRef{})
	if err == nil {
		t.Fatalf("expected error for empty name")
	}
}

func TestToolCatalog_SearchByNameSubstring(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "file_read", Description: "read files"})
	_ = c.Register(context.Background(), ToolRef{Name: "file_write", Description: "write files"})
	results, err := c.Search(context.Background(), "file_")
	if err != nil || len(results) != 2 {
		t.Fatalf("expected 2 results, got %d (err=%v)", len(results), err)
	}
}

func TestToolCatalog_SearchByDescriptionSubstring(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "a", Description: "special unique thing"})
	results, _ := c.Search(context.Background(), "unique")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestToolCatalog_SearchCaseInsensitive(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "MyTool", Description: "desc"})
	results, _ := c.Search(context.Background(), "mytool")
	if len(results) != 1 {
		t.Fatalf("search should be case insensitive")
	}
}

func TestToolCatalog_SearchEmptyQueryReturnsAll(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "a", Description: "da"})
	_ = c.Register(context.Background(), ToolRef{Name: "b", Description: "db"})
	results, _ := c.Search(context.Background(), "")
	if len(results) != 2 {
		t.Fatalf("empty query should return all tools, got %d", len(results))
	}
}

func TestToolCatalog_RegisterCommonToolsPopulates(t *testing.T) {
	c := NewToolCatalog()
	c.RegisterCommonTools()
	_, okR := c.Lookup("file_read")
	_, okW := c.Lookup("file_write")
	if !okR || !okW {
		t.Fatalf("RegisterCommonTools should register file_read and file_write")
	}
}

func TestToolCatalog_RegisterOverwritesExisting(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "t", Description: "v1"})
	_ = c.Register(context.Background(), ToolRef{Name: "t", Description: "v2"})
	ref, _ := c.Lookup("t")
	if ref.Description != "v2" {
		t.Fatalf("register should overwrite existing entry")
	}
}

// ---- ToolCallReceipt / AuditToolCall tests ----

func TestAuditToolCall_ReceiptContainsToolName(t *testing.T) {
	c := NewToolCatalog()
	receipt, err := c.AuditToolCall("myaction", map[string]any{"x": 1}, "ok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receipt.ToolName != "myaction" {
		t.Fatalf("expected ToolName=myaction, got %s", receipt.ToolName)
	}
}

func TestAuditToolCall_ReceiptIDHasPrefix(t *testing.T) {
	c := NewToolCatalog()
	receipt, _ := c.AuditToolCall("t", map[string]any{}, nil)
	if len(receipt.ID) < 5 || receipt.ID[:5] != "call-" {
		t.Fatalf("receipt ID should start with call-, got %s", receipt.ID)
	}
}

func TestAuditToolCall_TimestampIsRecent(t *testing.T) {
	c := NewToolCatalog()
	receipt, _ := c.AuditToolCall("t", map[string]any{}, nil)
	if time.Since(receipt.Timestamp) > 2*time.Second {
		t.Fatalf("receipt timestamp is too old")
	}
}

// ---- SessionStore tests ----

func TestSessionStore_CreateReturnsUniqueIDs(t *testing.T) {
	s := NewSessionStore(5 * time.Minute)
	defer s.Stop()
	id1, _ := s.Create("v1", "c1")
	id2, _ := s.Create("v1", "c2")
	if id1 == id2 {
		t.Fatalf("session IDs should be unique")
	}
}

func TestSessionStore_GetNonexistentReturnsNil(t *testing.T) {
	s := NewSessionStore(5 * time.Minute)
	defer s.Stop()
	if s.Get("does-not-exist") != nil {
		t.Fatalf("expected nil for nonexistent session")
	}
}

func TestSessionStore_DeleteRemovesSession(t *testing.T) {
	s := NewSessionStore(5 * time.Minute)
	defer s.Stop()
	id, _ := s.Create("v1", "c")
	s.Delete(id)
	if s.Get(id) != nil {
		t.Fatalf("session should be deleted")
	}
}

func TestSessionStore_DeleteNonexistentIsNoop(t *testing.T) {
	s := NewSessionStore(5 * time.Minute)
	defer s.Stop()
	s.Delete("bogus") // should not panic
}

func TestSessionStore_GetExpiredReturnsNil(t *testing.T) {
	s := NewSessionStore(50 * time.Millisecond)
	defer s.Stop()
	id, _ := s.Create("v1", "c")
	time.Sleep(60 * time.Millisecond)
	if s.Get(id) != nil {
		t.Fatalf("expired session should return nil")
	}
}

func TestSessionStore_ReapRemovesExpired(t *testing.T) {
	s := NewSessionStore(50 * time.Millisecond)
	defer s.Stop()
	_, _ = s.Create("v1", "a")
	_, _ = s.Create("v1", "b")
	time.Sleep(60 * time.Millisecond)
	s.reap()
	if s.Len() != 0 {
		t.Fatalf("reap should remove all expired sessions, got %d", s.Len())
	}
}

func TestSessionStore_TTLDefaultsWhenZero(t *testing.T) {
	s := NewSessionStore(0)
	defer s.Stop()
	if s.ttl != DefaultSessionTTL {
		t.Fatalf("expected default TTL %v, got %v", DefaultSessionTTL, s.ttl)
	}
}

func TestSessionStore_TTLDefaultsWhenNegative(t *testing.T) {
	s := NewSessionStore(-1 * time.Second)
	defer s.Stop()
	if s.ttl != DefaultSessionTTL {
		t.Fatalf("expected default TTL for negative input")
	}
}

func TestSessionStore_SessionProtocolVersionStored(t *testing.T) {
	s := NewSessionStore(5 * time.Minute)
	defer s.Stop()
	id, _ := s.Create(LatestProtocolVersion, "test")
	session := s.Get(id)
	if session.ProtocolVersion != LatestProtocolVersion {
		t.Fatalf("protocol version mismatch")
	}
}

func TestSessionStore_SessionClientNameStored(t *testing.T) {
	s := NewSessionStore(5 * time.Minute)
	defer s.Stop()
	id, _ := s.Create("v1", "my-client")
	session := s.Get(id)
	if session.ClientName != "my-client" {
		t.Fatalf("client name mismatch")
	}
}

// ---- GovernanceFirewall tests ----

func TestGovernanceFirewall_AllowPassesThrough(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictAllow)}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{ToolName: "t", SessionID: "s"})
	if err != nil {
		t.Fatalf("ALLOW should pass: %v", err)
	}
}

func TestGovernanceFirewall_DenyBlocks(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictDeny), reason: "bad"}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{ToolName: "t", SessionID: "s"})
	if err == nil {
		t.Fatalf("DENY should block")
	}
}

func TestGovernanceFirewall_EscalateBlocks(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictEscalate), reason: "needs review"}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{ToolName: "t", SessionID: "s"})
	if err == nil {
		t.Fatalf("ESCALATE should block")
	}
}

func TestGovernanceFirewall_DelegationScopeRejectsOutOfScope(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictAllow)}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "forbidden_tool",
		SessionID:              "s",
		DelegationAllowedTools: []string{"safe_tool"},
	})
	if err == nil {
		t.Fatalf("out-of-scope tool should be rejected")
	}
}

func TestGovernanceFirewall_DelegationScopeAllowsInScope(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictAllow)}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:               "safe_tool",
		SessionID:              "s",
		DelegationAllowedTools: []string{"safe_tool"},
	})
	if err != nil {
		t.Fatalf("in-scope tool should pass: %v", err)
	}
}

func TestGovernanceFirewall_NoDelegationAllowsAll(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictAllow)}
	fw := NewGovernanceFirewall(eval, nil)
	err := fw.InterceptToolExecution(context.Background(), ToolExecutionRequest{
		ToolName:  "anything",
		SessionID: "s",
	})
	if err != nil {
		t.Fatalf("no delegation scope should allow all: %v", err)
	}
}

// ---- Gateway config / types tests ----

func TestGatewayConfig_DefaultAuthMode(t *testing.T) {
	gw := NewGateway(NewToolCatalog(), GatewayConfig{})
	defer gw.sessions.Stop()
	if gw.authMode() != "none" {
		t.Fatalf("expected default auth mode 'none', got %s", gw.authMode())
	}
}

func TestGatewayConfig_OAuthAuthMode(t *testing.T) {
	gw := NewGateway(NewToolCatalog(), GatewayConfig{AuthMode: "oauth"})
	defer gw.sessions.Stop()
	if gw.authMode() != "oauth" {
		t.Fatalf("expected auth mode 'oauth', got %s", gw.authMode())
	}
}

func TestMCPToolCallRequest_JSONRoundTrip(t *testing.T) {
	req := MCPToolCallRequest{Method: "file_read", Params: map[string]any{"path": "/tmp"}}
	data, _ := json.Marshal(req)
	var decoded MCPToolCallRequest
	_ = json.Unmarshal(data, &decoded)
	if decoded.Method != "file_read" {
		t.Fatalf("method mismatch after roundtrip")
	}
}

func TestMCPToolCallResponse_JSONRoundTrip(t *testing.T) {
	resp := MCPToolCallResponse{Decision: "ALLOW", ReceiptID: "r1", ProtocolVersion: LatestProtocolVersion}
	data, _ := json.Marshal(resp)
	var decoded MCPToolCallResponse
	_ = json.Unmarshal(data, &decoded)
	if decoded.Decision != "ALLOW" || decoded.ReceiptID != "r1" {
		t.Fatalf("response roundtrip mismatch")
	}
}

func TestMCPCapabilityManifest_GovernanceField(t *testing.T) {
	m := MCPCapabilityManifest{Governance: "helm:pep:v1"}
	data, _ := json.Marshal(m)
	var decoded MCPCapabilityManifest
	_ = json.Unmarshal(data, &decoded)
	if decoded.Governance != "helm:pep:v1" {
		t.Fatalf("governance field mismatch")
	}
}

// ---- Elicitation tests ----

func TestIsElicitationVerdict_ESCALATE(t *testing.T) {
	if !IsElicitationVerdict("ESCALATE") {
		t.Fatalf("ESCALATE should be an elicitation verdict")
	}
}

func TestIsElicitationVerdict_PENDING(t *testing.T) {
	if !IsElicitationVerdict("PENDING") {
		t.Fatalf("PENDING should be an elicitation verdict")
	}
}

func TestIsElicitationVerdict_ALLOW(t *testing.T) {
	if IsElicitationVerdict("ALLOW") {
		t.Fatalf("ALLOW should not be an elicitation verdict")
	}
}

func TestMarshalElicitationNotification_ValidJSON(t *testing.T) {
	data, err := MarshalElicitationNotification("req-1", ElicitationRequest{
		Message: "approve?",
		Action:  "approve",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var n ElicitationNotification
	if err := json.Unmarshal(data, &n); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if n.Method != "elicitation/create" || n.Params.RequestID != "req-1" {
		t.Fatalf("notification fields mismatch: method=%s, requestID=%s", n.Method, n.Params.RequestID)
	}
}

// ---- ToolAnnotations payload tests ----

func TestToolAnnotationsPayload_NilReturnsNil(t *testing.T) {
	result := toolAnnotationsPayload(nil)
	if result != nil {
		t.Fatalf("nil annotations should return nil map")
	}
}

func TestToolAnnotationsPayload_OnlySetFieldsIncluded(t *testing.T) {
	ann := &ToolAnnotations{DestructiveHint: true}
	result := toolAnnotationsPayload(ann)
	if _, ok := result["readOnlyHint"]; ok {
		t.Fatalf("readOnlyHint should not be present when false")
	}
	if result["destructiveHint"] != true {
		t.Fatalf("destructiveHint should be true")
	}
}

// ---- JWKS error type tests ----

func TestJWKSValidationError_ErrorString(t *testing.T) {
	e := &JWKSValidationError{Kind: JWKSErrExpiredToken, Message: "token expired at X"}
	s := e.Error()
	if s != "expired_token: token expired at X" {
		t.Fatalf("unexpected error string: %s", s)
	}
}

func TestJWKSClaimsResourceIndicatorsDeduplicateSources(t *testing.T) {
	claims := &jwksClaims{
		Resource:  "https://gateway.example/mcp",
		Resources: []string{"https://gateway.example/mcp", "https://gateway.example/mcp/v2"},
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"https://gateway.example/mcp", "https://other.example/api"},
		},
	}

	resources := claims.resourceIndicators()
	if len(resources) != 3 {
		t.Fatalf("expected three deduplicated resource indicators, got %v", resources)
	}
	for _, expected := range []string{
		"https://gateway.example/mcp",
		"https://other.example/api",
		"https://gateway.example/mcp/v2",
	} {
		if !containsString(resources, expected) {
			t.Fatalf("expected %s in resource indicators %v", expected, resources)
		}
	}
}

// ---- InterceptPlan tests ----

func TestGovernanceFirewall_InterceptPlan_AllAllow(t *testing.T) {
	eval := &mockEvaluator{verdict: string(contracts.VerdictAllow)}
	fw := NewGovernanceFirewall(eval, nil)
	plan := ToolExecutionPlan{PlanID: "p1", Steps: []ToolExecutionRequest{{ToolName: "a"}, {ToolName: "b"}}}
	pd, err := fw.InterceptPlan(context.Background(), plan)
	if err != nil || pd.Status != string(contracts.VerdictAllow) {
		t.Fatalf("all-allow plan should have ALLOW status")
	}
}

func TestGovernanceFirewall_InterceptPlan_OneDenyMakesDeny(t *testing.T) {
	eval := &smartMockEvaluator{decisions: map[string]string{
		"good": string(contracts.VerdictAllow),
		"bad":  string(contracts.VerdictDeny),
	}}
	fw := NewGovernanceFirewall(eval, nil)
	plan := ToolExecutionPlan{PlanID: "p2", Steps: []ToolExecutionRequest{{ToolName: "good"}, {ToolName: "bad"}}}
	pd, err := fw.InterceptPlan(context.Background(), plan)
	if err != nil || pd.Status != string(contracts.VerdictDeny) {
		t.Fatalf("plan with one DENY should have DENY status")
	}
}

// ---- WrapToolHandler audit receipt test ----

func TestGovernanceFirewall_WrapHandler_SetsReceiptID(t *testing.T) {
	eval := &mockEvaluator{verdict: guardian.VerdictAllow}
	catalog := NewToolCatalog()
	fw := NewGovernanceFirewall(eval, catalog)
	handler := func(_ context.Context, _ ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "done"}, nil
	}
	wrapped := fw.WrapToolHandler(handler)
	resp, err := wrapped(context.Background(), ToolExecutionRequest{ToolName: "t", SessionID: "s"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ReceiptID == "" {
		t.Fatalf("wrapped handler should set receipt ID when catalog is present")
	}
}

// ---- NewInMemoryCatalog alias test ----

func TestNewInMemoryCatalog_IsAlias(t *testing.T) {
	c := NewInMemoryCatalog()
	if c == nil || c.tools == nil {
		t.Fatalf("NewInMemoryCatalog should return initialized catalog")
	}
}

// ---- findToolRef helper test ----

func TestFindToolRef_ExactMatchRequired(t *testing.T) {
	c := NewToolCatalog()
	_ = c.Register(context.Background(), ToolRef{Name: "file_read", Description: "read"})
	_, ok := findToolRef(c, "file_read")
	if !ok {
		t.Fatalf("exact match should be found")
	}
	_, ok2 := findToolRef(c, "file_rea")
	if ok2 {
		t.Fatalf("partial match should not be found as exact")
	}
}
