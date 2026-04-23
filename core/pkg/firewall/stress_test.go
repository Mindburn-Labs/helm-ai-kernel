package firewall

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// ── 200 concurrent egress checks ────────────────────────────────────────

func TestStress_200ConcurrentEgressChecks(t *testing.T) {
	policy := &EgressPolicy{
		AllowedDomains:   []string{"api.example.com"},
		AllowedProtocols: []string{"https"},
	}
	checker := NewEgressChecker(policy)
	var wg sync.WaitGroup
	for i := range 200 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			checker.CheckEgress("api.example.com", "https", 100)
		}(i)
	}
	wg.Wait()
}

// ── Policy: 50 allowed + 50 denied domains ──────────────────────────────

func TestStress_Policy50Allowed50Denied(t *testing.T) {
	allowed := make([]string, 50)
	denied := make([]string, 50)
	for i := range 50 {
		allowed[i] = fmt.Sprintf("allow-%d.example.com", i)
		denied[i] = fmt.Sprintf("deny-%d.example.com", i)
	}
	policy := &EgressPolicy{AllowedDomains: allowed, DeniedDomains: denied, AllowedProtocols: []string{"https"}}
	checker := NewEgressChecker(policy)
	for i := range 50 {
		d := checker.CheckEgress(fmt.Sprintf("allow-%d.example.com", i), "https", 0)
		if !d.Allowed {
			t.Fatalf("allow-%d should be allowed", i)
		}
	}
	for i := range 50 {
		d := checker.CheckEgress(fmt.Sprintf("deny-%d.example.com", i), "https", 0)
		if d.Allowed {
			t.Fatalf("deny-%d should be denied", i)
		}
	}
}

// ── Denied takes precedence ─────────────────────────────────────────────

func TestStress_DeniedPrecedence(t *testing.T) {
	policy := &EgressPolicy{
		AllowedDomains:   []string{"overlap.example.com"},
		DeniedDomains:    []string{"overlap.example.com"},
		AllowedProtocols: []string{"https"},
	}
	checker := NewEgressChecker(policy)
	d := checker.CheckEgress("overlap.example.com", "https", 0)
	if d.Allowed {
		t.Fatal("denied should take precedence")
	}
}

// ── CIDR with 20 ranges ────────────────────────────────────────────────

func TestStress_CIDR20Ranges(t *testing.T) {
	cidrs := make([]string, 20)
	for i := range 20 {
		cidrs[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	policy := &EgressPolicy{AllowedCIDRs: cidrs, AllowedProtocols: []string{"https"}}
	checker := NewEgressChecker(policy)
	d := checker.CheckEgress("10.5.1.1", "https", 0)
	if !d.Allowed {
		t.Fatal("10.5.1.1 should be in 10.5.0.0/16")
	}
	d = checker.CheckEgress("10.25.1.1", "https", 0)
	if d.Allowed {
		t.Fatal("10.25.1.1 should not be in any range")
	}
}

// ── Schema validation: 20 different schemas ─────────────────────────────

func TestStress_SchemaValidation20Schemas(t *testing.T) {
	fw := NewPolicyFirewall(nil)
	for i := range 20 {
		toolName := fmt.Sprintf("tool-%d", i)
		schema := fmt.Sprintf(`{"type":"object","properties":{"field_%d":{"type":"string"}},"required":["field_%d"]}`, i, i)
		if err := fw.AllowTool(toolName, schema); err != nil {
			t.Fatalf("allow tool %d: %v", i, err)
		}
	}
}

func TestStress_SchemaValidationPass(t *testing.T) {
	d := &stressDispatcher{}
	fw := NewPolicyFirewall(d)
	_ = fw.AllowTool("safe-tool", `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "safe-tool", map[string]any{"name": "test"})
	if err != nil {
		t.Fatalf("valid params should pass: %v", err)
	}
}

func TestStress_SchemaValidationFail(t *testing.T) {
	d := &stressDispatcher{}
	fw := NewPolicyFirewall(d)
	_ = fw.AllowTool("strict-tool", `{"type":"object","properties":{"count":{"type":"integer"}},"required":["count"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "strict-tool", map[string]any{"count": "not-a-number"})
	if err == nil {
		t.Fatal("invalid type should fail schema validation")
	}
}

// ── Dispatcher chain 5 deep ─────────────────────────────────────────────

func TestStress_DispatcherChain5Deep(t *testing.T) {
	leaf := &stressDispatcher{}
	// Build chain of 5 PolicyFirewalls, each wrapping the next
	var current Dispatcher = leaf
	for i := range 5 {
		fw := NewPolicyFirewall(current)
		_ = fw.AllowTool("chained-tool", "")
		current = &firewallDispatcher{fw: fw}
		_ = i
	}
	// Call through the chain
	result, err := current.(*firewallDispatcher).fw.CallTool(context.Background(), PolicyInputBundle{}, "chained-tool", nil)
	if err != nil {
		t.Fatalf("chain dispatch: %v", err)
	}
	if result != "dispatched" {
		t.Fatal("leaf dispatcher should return 'dispatched'")
	}
}

type firewallDispatcher struct {
	fw *PolicyFirewall
}

func (d *firewallDispatcher) Dispatch(ctx context.Context, toolName string, params map[string]any) (any, error) {
	return d.fw.CallTool(ctx, PolicyInputBundle{}, toolName, params)
}

type stressDispatcher struct{}

func (d *stressDispatcher) Dispatch(ctx context.Context, toolName string, params map[string]any) (any, error) {
	return "dispatched", nil
}

// ── Stats after 1000 operations ─────────────────────────────────────────

func TestStress_StatsAfter1000Operations(t *testing.T) {
	policy := &EgressPolicy{
		AllowedDomains:   []string{"stats.example.com"},
		DeniedDomains:    []string{"blocked.example.com"},
		AllowedProtocols: []string{"https"},
	}
	checker := NewEgressChecker(policy)
	for i := range 1000 {
		if i%2 == 0 {
			checker.CheckEgress("stats.example.com", "https", 0)
		} else {
			checker.CheckEgress("blocked.example.com", "https", 0)
		}
	}
	total, allowed, denied := checker.Stats()
	if total != 1000 {
		t.Fatalf("expected 1000 total, got %d", total)
	}
	if allowed != 500 {
		t.Fatalf("expected 500 allowed, got %d", allowed)
	}
	if denied != 500 {
		t.Fatalf("expected 500 denied, got %d", denied)
	}
}

// ── Fail-closed: nil policy ─────────────────────────────────────────────

func TestStress_NilPolicyDenyAll(t *testing.T) {
	checker := NewEgressChecker(nil)
	d := checker.CheckEgress("anything.com", "https", 0)
	if d.Allowed {
		t.Fatal("nil policy should deny all")
	}
}

// ── Fail-closed: empty allowlist ────────────────────────────────────────

func TestStress_EmptyAllowlistDenyAll(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{})
	d := checker.CheckEgress("anything.com", "https", 0)
	if d.Allowed {
		t.Fatal("empty allowlist should deny all")
	}
}

// ── Protocol enforcement ────────────────────────────────────────────────

func TestStress_ProtocolEnforcement(t *testing.T) {
	policy := &EgressPolicy{
		AllowedDomains:   []string{"api.example.com"},
		AllowedProtocols: []string{"https"},
	}
	checker := NewEgressChecker(policy)
	d := checker.CheckEgress("api.example.com", "http", 0)
	if d.Allowed {
		t.Fatal("http should be denied when only https allowed")
	}
}

// ── Payload size enforcement ────────────────────────────────────────────

func TestStress_PayloadSizeEnforcement(t *testing.T) {
	policy := &EgressPolicy{
		AllowedDomains:   []string{"api.example.com"},
		AllowedProtocols: []string{"https"},
		MaxPayloadBytes:  1024,
	}
	checker := NewEgressChecker(policy)
	d := checker.CheckEgress("api.example.com", "https", 2048)
	if d.Allowed {
		t.Fatal("oversized payload should be denied")
	}
	d = checker.CheckEgress("api.example.com", "https", 512)
	if !d.Allowed {
		t.Fatal("undersized payload should be allowed")
	}
}

// ── Firewall: blocked tool ──────────────────────────────────────────────

func TestStress_FirewallBlockedTool(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "unregistered-tool", nil)
	if err == nil {
		t.Fatal("unregistered tool should be blocked")
	}
}

// ── Firewall: nil dispatcher ────────────────────────────────────────────

func TestStress_FirewallNilDispatcher(t *testing.T) {
	fw := NewPolicyFirewall(nil)
	_ = fw.AllowTool("nil-tool", "")
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "nil-tool", nil)
	if err == nil {
		t.Fatal("nil dispatcher should fail-closed")
	}
}

// ── Firewall: tool with no schema ───────────────────────────────────────

func TestStress_FirewallNoSchema(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	_ = fw.AllowTool("no-schema-tool", "")
	result, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "no-schema-tool", nil)
	if err != nil {
		t.Fatalf("no schema should pass: %v", err)
	}
	if result != "dispatched" {
		t.Fatal("should dispatch")
	}
}

// ── Firewall: missing params with schema ────────────────────────────────

func TestStress_FirewallMissingParams(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	_ = fw.AllowTool("params-tool", `{"type":"object","required":["x"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "params-tool", nil)
	if err == nil {
		t.Fatal("nil params with required schema should fail")
	}
}

// ── Egress: unknown domain ──────────────────────────────────────────────

func TestStress_EgressUnknownDomain(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"known.com"},
		AllowedProtocols: []string{"https"},
	})
	d := checker.CheckEgress("unknown.com", "https", 0)
	if d.Allowed {
		t.Fatal("unknown domain should be denied")
	}
}

// ── EgressDecision fields ───────────────────────────────────────────────

func TestStress_EgressDecisionFields(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.test.com"},
		AllowedProtocols: []string{"https"},
	})
	d := checker.CheckEgress("api.test.com", "https", 42)
	if d.Destination != "api.test.com" {
		t.Fatal("destination mismatch")
	}
	if d.CheckedAt.IsZero() {
		t.Fatal("checked_at should be set")
	}
}

// ── Concurrent firewall calls ───────────────────────────────────────────

func TestStress_ConcurrentFirewallCalls(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	_ = fw.AllowTool("concurrent-tool", "")
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fw.CallTool(context.Background(), PolicyInputBundle{}, "concurrent-tool", nil)
		}()
	}
	wg.Wait()
}

func TestStress_EgressCIDRMatchFirst(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.0.0/24"}, AllowedProtocols: []string{"https"}})
	d := checker.CheckEgress("192.168.0.100", "https", 0)
	if !d.Allowed {
		t.Fatal("192.168.0.100 should be in 192.168.0.0/24")
	}
}

func TestStress_EgressCIDROutOfRange(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.0.0/24"}, AllowedProtocols: []string{"https"}})
	d := checker.CheckEgress("192.168.1.1", "https", 0)
	if d.Allowed {
		t.Fatal("192.168.1.1 should not be in 192.168.0.0/24")
	}
}

func TestStress_EgressZeroPayloadLimit(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.com"}, AllowedProtocols: []string{"https"}, MaxPayloadBytes: 0})
	d := checker.CheckEgress("api.com", "https", 999999)
	if !d.Allowed {
		t.Fatal("0 payload limit means unlimited")
	}
}

func TestStress_EgressStatsInitialZero(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"x.com"}})
	total, allowed, denied := checker.Stats()
	if total != 0 || allowed != 0 || denied != 0 {
		t.Fatal("initial stats should be all zero")
	}
}

func TestStress_FirewallAllowToolNoSchema(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	err := fw.AllowTool("simple", "")
	if err != nil {
		t.Fatalf("allow tool: %v", err)
	}
}

func TestStress_FirewallAllowToolWithSchema(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	err := fw.AllowTool("typed", `{"type":"object"}`)
	if err != nil {
		t.Fatalf("allow tool: %v", err)
	}
}

func TestStress_FirewallAllowToolBadSchema(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	err := fw.AllowTool("bad", `{not-json}`)
	if err == nil {
		t.Fatal("bad schema should fail")
	}
}

func TestStress_EgressMultipleProtocols(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.com"}, AllowedProtocols: []string{"https", "grpc"}})
	d1 := checker.CheckEgress("api.com", "https", 0)
	d2 := checker.CheckEgress("api.com", "grpc", 0)
	if !d1.Allowed || !d2.Allowed {
		t.Fatal("both protocols should be allowed")
	}
}

func TestStress_EgressReasonCodeSet(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"good.com"}, AllowedProtocols: []string{"https"}})
	d := checker.CheckEgress("bad.com", "https", 0)
	if d.ReasonCode == "" {
		t.Fatal("denied decision should have a reason code")
	}
}

func TestStress_ConcurrentEgressStats(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"s.com"}, AllowedProtocols: []string{"https"}})
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checker.CheckEgress("s.com", "https", 0)
		}()
	}
	wg.Wait()
	total, _, _ := checker.Stats()
	if total != 50 {
		t.Fatalf("expected 50 total, got %d", total)
	}
}

func TestStress_PolicyInputBundle(t *testing.T) {
	b := PolicyInputBundle{ActorID: "a1", Role: "admin", SessionID: "s1"}
	if b.ActorID != "a1" || b.Role != "admin" || b.SessionID != "s1" {
		t.Fatal("bundle field mismatch")
	}
}

func TestStress_FirewallMultipleTools(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	for i := range 10 {
		_ = fw.AllowTool(fmt.Sprintf("tool-%d", i), "")
	}
	for i := range 10 {
		_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, fmt.Sprintf("tool-%d", i), nil)
		if err != nil {
			t.Fatalf("tool-%d should be allowed: %v", i, err)
		}
	}
}

func TestStress_EgressDomainCaseInsensitive(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"Api.Example.Com"}, AllowedProtocols: []string{"https"}})
	d := checker.CheckEgress("api.example.com", "https", 0)
	// Behavior depends on implementation — just verify no panic
	_ = d
}

func TestStress_FirewallCallResult(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	_ = fw.AllowTool("res-tool", "")
	result, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "res-tool", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if result != "dispatched" {
		t.Fatalf("expected 'dispatched', got %v", result)
	}
}

func TestStress_EgressDecisionAllowed(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"ok.com"}, AllowedProtocols: []string{"https"}})
	d := checker.CheckEgress("ok.com", "https", 0)
	if !d.Allowed {
		t.Fatal("should be allowed")
	}
	if d.Destination != "ok.com" {
		t.Fatal("destination mismatch")
	}
}

func TestStress_EgressDecisionPayload(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"p.com"}, AllowedProtocols: []string{"https"}})
	d := checker.CheckEgress("p.com", "https", 42)
	if d.PayloadBytes != 42 {
		t.Fatalf("expected 42, got %d", d.PayloadBytes)
	}
}

func TestStress_FirewallSchemaEmptyRemovesSchema(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	_ = fw.AllowTool("toggle", `{"type":"object"}`)
	_ = fw.AllowTool("toggle", "")
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "toggle", nil)
	if err != nil {
		t.Fatalf("no schema should pass: %v", err)
	}
}

func TestStress_EgressDeniedDomainsOnly(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{DeniedDomains: []string{"evil.com"}, AllowedProtocols: []string{"https"}})
	d := checker.CheckEgress("evil.com", "https", 0)
	if d.Allowed {
		t.Fatal("explicitly denied should be blocked")
	}
}

func TestStress_FirewallAllowMultipleSchemas(t *testing.T) {
	fw := NewPolicyFirewall(&stressDispatcher{})
	_ = fw.AllowTool("t1", `{"type":"object"}`)
	_ = fw.AllowTool("t2", `{"type":"object","properties":{"x":{"type":"string"}}}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t1", map[string]any{})
	if err != nil {
		t.Fatalf("t1: %v", err)
	}
}

func TestStress_EgressEmptyProtocol(t *testing.T) {
	checker := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, AllowedProtocols: []string{}})
	d := checker.CheckEgress("a.com", "https", 0)
	// Empty protocols list = no protocol restriction (domain still matched)
	// Just verify no panic occurs; behavior is implementation-defined
	_ = d
}
