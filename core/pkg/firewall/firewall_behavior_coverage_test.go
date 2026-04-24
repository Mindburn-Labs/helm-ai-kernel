package firewall

import (
	"context"
	"strings"
	"testing"
	"time"
)

// --- Helper dispatcher for firewall tests ---

type fakeDispatcher struct {
	result any
	err    error
}

func (s *fakeDispatcher) Dispatch(_ context.Context, _ string, _ map[string]any) (any, error) {
	return s.result, s.err
}

// ==================== EgressChecker: NewEgressChecker ====================

func TestNewEgressChecker_EmptyPolicy(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{})
	result := ec.CheckEgress("example.com", "https", 100)
	if result.Allowed {
		t.Error("empty allowlist should deny")
	}
}

func TestNewEgressChecker_NilPolicy(t *testing.T) {
	ec := NewEgressChecker(nil)
	result := ec.CheckEgress("anything.com", "https", 0)
	if result.Allowed {
		t.Error("nil policy should deny all traffic")
	}
}

func TestNewEgressChecker_InvalidCIDRIgnored(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"not-a-cidr"}})
	if len(ec.parsedCIDRs) != 0 {
		t.Error("invalid CIDR should be silently ignored")
	}
}

func TestNewEgressChecker_ValidCIDRParsed(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.0.0/16"}})
	if len(ec.parsedCIDRs) != 1 {
		t.Errorf("expected 1 parsed CIDR, got %d", len(ec.parsedCIDRs))
	}
}

func TestNewEgressChecker_MultipleCIDRs(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12"}})
	if len(ec.parsedCIDRs) != 2 {
		t.Errorf("expected 2 parsed CIDRs, got %d", len(ec.parsedCIDRs))
	}
}

func TestNewEgressChecker_DomainsLowercased(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"API.Example.COM"}})
	if !ec.allowedSet["api.example.com"] {
		t.Error("allowed domains should be stored lowercased")
	}
}

func TestNewEgressChecker_DeniedDomainsLowercased(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{DeniedDomains: []string{"EVIL.COM"}})
	if !ec.deniedSet["evil.com"] {
		t.Error("denied domains should be stored lowercased")
	}
}

func TestNewEgressChecker_ProtocolsLowercased(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedProtocols: []string{"HTTPS"}})
	if !ec.protoSet["https"] {
		t.Error("protocols should be stored lowercased")
	}
}

// ==================== EgressChecker: CheckEgress — Domain ====================

func TestCheckEgress_AllowedDomainPasses(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"trusted.io"}})
	d := ec.CheckEgress("trusted.io", "https", 50)
	if !d.Allowed {
		t.Error("trusted.io should be allowed")
	}
}

func TestCheckEgress_UnlistedDomainDenied(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"only-this.com"}})
	d := ec.CheckEgress("other.com", "https", 50)
	if d.Allowed {
		t.Error("unlisted domain should be denied (fail-closed)")
	}
}

func TestCheckEgress_DeniedDomainBlocked(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains: []string{"good.com"},
		DeniedDomains:  []string{"bad.com"},
	})
	d := ec.CheckEgress("bad.com", "https", 50)
	if d.Allowed {
		t.Error("explicitly denied domain should be blocked")
	}
}

func TestCheckEgress_DenyPrecedenceOverAllow(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains: []string{"ambiguous.com"},
		DeniedDomains:  []string{"ambiguous.com"},
	})
	d := ec.CheckEgress("ambiguous.com", "https", 10)
	if d.Allowed {
		t.Error("deny should take precedence when domain is in both lists")
	}
}

func TestCheckEgress_CaseInsensitiveDomain(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"Allowed.COM"}})
	d := ec.CheckEgress("allowed.com", "https", 10)
	if !d.Allowed {
		t.Error("domain matching should be case-insensitive")
	}
}

func TestCheckEgress_CaseInsensitiveDomainUpperInput(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"lower.com"}})
	d := ec.CheckEgress("LOWER.COM", "https", 10)
	if !d.Allowed {
		t.Error("uppercase input should match lowercase policy")
	}
}

func TestCheckEgress_DeniedCaseInsensitive(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{DeniedDomains: []string{"BLOCK.COM"}})
	d := ec.CheckEgress("block.com", "https", 10)
	if d.Allowed {
		t.Error("denied domain match should be case-insensitive")
	}
}

// ==================== EgressChecker: CheckEgress — CIDR ====================

func TestCheckEgress_CIDRMatchAllows(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8"}})
	d := ec.CheckEgress("10.5.3.1", "https", 10)
	if !d.Allowed {
		t.Error("10.5.3.1 should match 10.0.0.0/8")
	}
}

func TestCheckEgress_CIDRNoMatch(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8"}})
	d := ec.CheckEgress("192.168.1.1", "https", 10)
	if d.Allowed {
		t.Error("192.168.1.1 should not match 10.0.0.0/8")
	}
}

func TestCheckEgress_CIDRExactBoundary(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.1.0/24"}})
	d := ec.CheckEgress("192.168.1.255", "https", 10)
	if !d.Allowed {
		t.Error("192.168.1.255 should match /24")
	}
}

func TestCheckEgress_CIDROutOfRange(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.1.0/24"}})
	d := ec.CheckEgress("192.168.2.1", "https", 10)
	if d.Allowed {
		t.Error("192.168.2.1 should not match 192.168.1.0/24")
	}
}

func TestCheckEgress_IPNotDomainWhenNoCIDR(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"10.0.0.1"}})
	// "10.0.0.1" is in allowed domains as a string, should match
	d := ec.CheckEgress("10.0.0.1", "https", 10)
	if !d.Allowed {
		t.Error("IP literal in allowed domains should be matched as domain string")
	}
}

func TestCheckEgress_MultipleCIDRsSecondMatches(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12"}})
	d := ec.CheckEgress("172.20.1.1", "https", 10)
	if !d.Allowed {
		t.Error("172.20.1.1 should match second CIDR 172.16.0.0/12")
	}
}

// ==================== EgressChecker: CheckEgress — Protocol ====================

func TestCheckEgress_AllowedProtocolPasses(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.test.com"},
		AllowedProtocols: []string{"https"},
	})
	d := ec.CheckEgress("api.test.com", "https", 10)
	if !d.Allowed {
		t.Error("https should be allowed when in protocol list")
	}
}

func TestCheckEgress_DisallowedProtocolBlocked(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.test.com"},
		AllowedProtocols: []string{"https"},
	})
	d := ec.CheckEgress("api.test.com", "ftp", 10)
	if d.Allowed {
		t.Error("ftp should be blocked when only https is allowed")
	}
}

func TestCheckEgress_NoProtocolRestrictionAllowsAny(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"open.com"}})
	d := ec.CheckEgress("open.com", "custom-proto", 10)
	if !d.Allowed {
		t.Error("empty protocol list should allow any protocol")
	}
}

func TestCheckEgress_ProtocolCaseInsensitive(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"a.com"},
		AllowedProtocols: []string{"GRPC"},
	})
	d := ec.CheckEgress("a.com", "grpc", 10)
	if !d.Allowed {
		t.Error("protocol matching should be case-insensitive")
	}
}

func TestCheckEgress_ProtocolCheckBeforeDomainAllow(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"safe.com"},
		AllowedProtocols: []string{"https"},
	})
	d := ec.CheckEgress("safe.com", "ssh", 10)
	if d.Allowed {
		t.Error("protocol should be checked even if domain is allowed")
	}
}

// ==================== EgressChecker: CheckEgress — Payload ====================

func TestCheckEgress_PayloadWithinLimit(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:  []string{"d.com"},
		MaxPayloadBytes: 1000,
	})
	d := ec.CheckEgress("d.com", "https", 999)
	if !d.Allowed {
		t.Error("payload within limit should be allowed")
	}
}

func TestCheckEgress_PayloadExactLimit(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:  []string{"d.com"},
		MaxPayloadBytes: 500,
	})
	d := ec.CheckEgress("d.com", "https", 500)
	if !d.Allowed {
		t.Error("payload exactly at limit should be allowed")
	}
}

func TestCheckEgress_PayloadExceedsLimit(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:  []string{"d.com"},
		MaxPayloadBytes: 500,
	})
	d := ec.CheckEgress("d.com", "https", 501)
	if d.Allowed {
		t.Error("payload exceeding limit should be denied")
	}
}

func TestCheckEgress_ZeroPayloadLimitMeansUnlimited(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:  []string{"d.com"},
		MaxPayloadBytes: 0,
	})
	d := ec.CheckEgress("d.com", "https", 999999999)
	if !d.Allowed {
		t.Error("zero MaxPayloadBytes means no limit")
	}
}

func TestCheckEgress_PayloadCheckBeforeDomain(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:  []string{"safe.com"},
		MaxPayloadBytes: 100,
	})
	d := ec.CheckEgress("safe.com", "https", 200)
	if d.Allowed {
		t.Error("oversized payload should be blocked even for allowed domain")
	}
}

// ==================== EgressChecker: CheckEgress — Decision fields ====================

func TestCheckEgress_DecisionReasonCodeOnDeny(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{})
	d := ec.CheckEgress("blocked.com", "https", 10)
	if d.ReasonCode != "DATA_EGRESS_BLOCKED" {
		t.Errorf("reason code = %q, want DATA_EGRESS_BLOCKED", d.ReasonCode)
	}
}

func TestCheckEgress_DecisionReasonCodeOnAllow(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"ok.com"}})
	d := ec.CheckEgress("ok.com", "https", 10)
	if d.ReasonCode != "" {
		t.Errorf("allowed decision should have empty reason code, got %q", d.ReasonCode)
	}
}

func TestCheckEgress_DecisionDestinationPreserved(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"test.com"}})
	d := ec.CheckEgress("test.com", "https", 42)
	if d.Destination != "test.com" {
		t.Errorf("destination = %q, want test.com", d.Destination)
	}
}

func TestCheckEgress_DecisionPayloadBytesPreserved(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"t.com"}})
	d := ec.CheckEgress("t.com", "https", 777)
	if d.PayloadBytes != 777 {
		t.Errorf("payload_bytes = %d, want 777", d.PayloadBytes)
	}
}

func TestCheckEgress_DecisionTimestampUsesInjectedClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ec := NewEgressChecker(&EgressPolicy{}).WithClock(func() time.Time { return fixed })
	d := ec.CheckEgress("x.com", "https", 1)
	if d.CheckedAt != fixed {
		t.Errorf("checked_at = %v, want %v", d.CheckedAt, fixed)
	}
}

// ==================== EgressChecker: Stats ====================

func TestStats_InitiallyZero(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{})
	total, allowed, denied := ec.Stats()
	if total != 0 || allowed != 0 || denied != 0 {
		t.Errorf("initial stats should be 0/0/0, got %d/%d/%d", total, allowed, denied)
	}
}

func TestStats_IncrementOnAllow(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}})
	ec.CheckEgress("a.com", "https", 1)
	_, allowed, _ := ec.Stats()
	if allowed != 1 {
		t.Errorf("allowed = %d, want 1", allowed)
	}
}

func TestStats_IncrementOnDeny(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{})
	ec.CheckEgress("x.com", "https", 1)
	_, _, denied := ec.Stats()
	if denied != 1 {
		t.Errorf("denied = %d, want 1", denied)
	}
}

func TestStats_TotalMatchesSumOfAllowedAndDenied(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"ok.com"}})
	ec.CheckEgress("ok.com", "https", 1)
	ec.CheckEgress("bad.com", "https", 1)
	ec.CheckEgress("ok.com", "https", 1)
	total, allowed, denied := ec.Stats()
	if total != allowed+denied {
		t.Errorf("total(%d) != allowed(%d) + denied(%d)", total, allowed, denied)
	}
}

// ==================== EgressChecker: String ====================

func TestString_ContainsCounts(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"a.com", "b.com"},
		DeniedDomains:    []string{"c.com"},
		AllowedCIDRs:     []string{"10.0.0.0/8"},
		AllowedProtocols: []string{"https", "grpc"},
	})
	s := ec.String()
	if !strings.Contains(s, "allowed=2") {
		t.Errorf("String() should contain allowed=2, got: %s", s)
	}
	if !strings.Contains(s, "denied=1") {
		t.Errorf("String() should contain denied=1, got: %s", s)
	}
}

// ==================== PolicyFirewall: NewPolicyFirewall ====================

func TestNewPolicyFirewall_NotNil(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{})
	if fw == nil {
		t.Error("NewPolicyFirewall should return a non-nil firewall")
	}
}

func TestNewPolicyFirewall_EmptyAllowlist(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{})
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "anything", nil)
	if err == nil {
		t.Error("fresh firewall should deny all tools")
	}
}

func TestNewPolicyFirewall_NilDispatcherAccepted(t *testing.T) {
	fw := NewPolicyFirewall(nil)
	if fw == nil {
		t.Error("NewPolicyFirewall(nil) should still return a firewall instance")
	}
}

// ==================== PolicyFirewall: AllowTool ====================

func TestAllowTool_EmptySchemaNoError(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{})
	err := fw.AllowTool("tool", "")
	if err != nil {
		t.Errorf("AllowTool with empty schema should not error: %v", err)
	}
}

func TestAllowTool_ValidSchemaCompiles(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{})
	err := fw.AllowTool("tool", `{"type": "object"}`)
	if err != nil {
		t.Errorf("AllowTool with valid schema should not error: %v", err)
	}
}

func TestAllowTool_InvalidJSONErrors(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{})
	err := fw.AllowTool("tool", `{invalid`)
	if err == nil {
		t.Error("AllowTool with invalid JSON should return error")
	}
}

func TestAllowTool_SameToolTwiceOverwrites(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{result: "ok"})
	_ = fw.AllowTool("t", `{"type":"object","required":["a"]}`)
	_ = fw.AllowTool("t", "")
	// After overwrite with empty schema, any params should pass
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t", nil)
	if err != nil {
		t.Errorf("overwritten tool should accept any params: %v", err)
	}
}

// ==================== PolicyFirewall: CallTool — Allowed/Denied ====================

func TestCallTool_AllowedToolPasses(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{result: "ok"})
	_ = fw.AllowTool("permitted", "")
	res, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "permitted", nil)
	if err != nil {
		t.Errorf("allowed tool should pass: %v", err)
	}
	if res != "ok" {
		t.Errorf("result = %v, want ok", res)
	}
}

func TestCallTool_DeniedToolBlocked(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{result: "ok"})
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "forbidden", nil)
	if err == nil {
		t.Error("unapproved tool should be blocked")
	}
}

func TestCallTool_BlockedErrorMentionsToolName(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{})
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "secret_tool", nil)
	if err == nil || !strings.Contains(err.Error(), "secret_tool") {
		t.Error("blocked error should mention the tool name")
	}
}

func TestCallTool_NilDispatcherFailsClosed(t *testing.T) {
	fw := NewPolicyFirewall(nil)
	_ = fw.AllowTool("t", "")
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t", nil)
	if err == nil {
		t.Error("nil dispatcher should fail closed")
	}
}

// ==================== PolicyFirewall: CallTool — Schema Validation ====================

func TestCallTool_SchemaValidParamsPasses(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{result: "done"})
	_ = fw.AllowTool("v", `{"type":"object","properties":{"n":{"type":"string"}},"required":["n"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "v", map[string]any{"n": "hello"})
	if err != nil {
		t.Errorf("valid params should pass schema: %v", err)
	}
}

func TestCallTool_SchemaMissingRequiredFieldRejects(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{result: "done"})
	_ = fw.AllowTool("v", `{"type":"object","required":["name"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "v", map[string]any{"other": 1})
	if err == nil {
		t.Error("missing required field should fail schema validation")
	}
}

func TestCallTool_SchemaWrongTypeRejects(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{result: "done"})
	_ = fw.AllowTool("v", `{"type":"object","properties":{"count":{"type":"integer"}},"required":["count"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "v", map[string]any{"count": "not-an-int"})
	if err == nil {
		t.Error("wrong type should fail schema validation")
	}
}

func TestCallTool_NilParamsWithSchemaRejects(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{})
	_ = fw.AllowTool("v", `{"type":"object","required":["x"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "v", nil)
	if err == nil {
		t.Error("nil params with schema should be rejected")
	}
}

func TestCallTool_NoSchemaAcceptsAnyParams(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{result: "yes"})
	_ = fw.AllowTool("free", "")
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "free", map[string]any{"a": 1, "b": "c"})
	if err != nil {
		t.Errorf("tool without schema should accept any params: %v", err)
	}
}

func TestCallTool_NoSchemaNilParamsPasses(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{result: "yes"})
	_ = fw.AllowTool("free", "")
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "free", nil)
	if err != nil {
		t.Errorf("tool without schema should accept nil params: %v", err)
	}
}

// ==================== PolicyFirewall: CallTool — Dispatcher delegation ====================

func TestCallTool_DispatcherReceivesToolName(t *testing.T) {
	var received string
	fw := NewPolicyFirewall(dispatcherFunc(func(_ context.Context, name string, _ map[string]any) (any, error) {
		received = name
		return nil, nil
	}))
	_ = fw.AllowTool("capture", "")
	_, _ = fw.CallTool(context.Background(), PolicyInputBundle{}, "capture", nil)
	if received != "capture" {
		t.Errorf("dispatcher received %q, want capture", received)
	}
}

func TestCallTool_DispatcherReceivesParams(t *testing.T) {
	var received map[string]any
	fw := NewPolicyFirewall(dispatcherFunc(func(_ context.Context, _ string, p map[string]any) (any, error) {
		received = p
		return nil, nil
	}))
	_ = fw.AllowTool("cap", "")
	_, _ = fw.CallTool(context.Background(), PolicyInputBundle{}, "cap", map[string]any{"k": "v"})
	if received["k"] != "v" {
		t.Error("dispatcher should receive the params map")
	}
}

func TestCallTool_DispatcherErrorPropagates(t *testing.T) {
	fw := NewPolicyFirewall(&fakeDispatcher{err: context.DeadlineExceeded})
	_ = fw.AllowTool("t", "")
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t", nil)
	if err == nil {
		t.Error("dispatcher error should propagate")
	}
}

// ==================== PolicyInputBundle ====================

func TestPolicyInputBundle_ZeroValue(t *testing.T) {
	b := PolicyInputBundle{}
	if b.ActorID != "" || b.Role != "" || b.SessionID != "" {
		t.Error("zero-value bundle should have empty fields")
	}
}

func TestPolicyInputBundle_FieldsSet(t *testing.T) {
	b := PolicyInputBundle{ActorID: "u:1", Role: "viewer", SessionID: "s-99"}
	if b.ActorID != "u:1" || b.Role != "viewer" || b.SessionID != "s-99" {
		t.Error("bundle fields should match assigned values")
	}
}

// ==================== WithClock ====================

func TestWithClock_ReturnsSelf(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{})
	same := ec.WithClock(time.Now)
	if ec != same {
		t.Error("WithClock should return the same EgressChecker instance")
	}
}

// --- Adapter to use a func as Dispatcher ---

type dispatcherFunc func(ctx context.Context, toolName string, params map[string]any) (any, error)

func (f dispatcherFunc) Dispatch(ctx context.Context, toolName string, params map[string]any) (any, error) {
	return f(ctx, toolName, params)
}
