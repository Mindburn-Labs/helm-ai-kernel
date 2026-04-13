package firewall

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Helpers ──────────────────────────────────────────────────────

type countingDispatcher struct{ calls atomic.Int64 }

func (d *countingDispatcher) Dispatch(_ context.Context, _ string, _ map[string]any) (any, error) {
	d.calls.Add(1)
	return "ok", nil
}

type errorDispatcher struct{ err error }

func (d *errorDispatcher) Dispatch(_ context.Context, _ string, _ map[string]any) (any, error) {
	return nil, d.err
}

func fixedClock() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// ── 1-5: Concurrent egress ──────────────────────────────────────

func TestDeep_ConcurrentEgress50(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"safe.io"}})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ec.CheckEgress("safe.io", "https", 10)
		}()
	}
	wg.Wait()
	total, allowed, _ := ec.Stats()
	if total != 50 || allowed != 50 {
		t.Fatalf("want 50/50 got total=%d allowed=%d", total, allowed)
	}
}

func TestDeep_ConcurrentEgressMixed(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, DeniedDomains: []string{"b.com"}})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				ec.CheckEgress("a.com", "https", 1)
			} else {
				ec.CheckEgress("b.com", "https", 1)
			}
		}(i)
	}
	wg.Wait()
	total, allowed, denied := ec.Stats()
	if total != 50 {
		t.Fatalf("total=%d want 50", total)
	}
	if allowed != 25 || denied != 25 {
		t.Fatalf("allowed=%d denied=%d want 25/25", allowed, denied)
	}
}

func TestDeep_ConcurrentEgressCIDR(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/24"}})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", i%256)
			ec.CheckEgress(ip, "https", 1)
		}(i)
	}
	wg.Wait()
	_, allowed, _ := ec.Stats()
	if allowed != 50 {
		t.Fatalf("allowed=%d want 50", allowed)
	}
}

func TestDeep_ConcurrentEgressDenyAll(t *testing.T) {
	ec := NewEgressChecker(nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := ec.CheckEgress("any.com", "https", 1)
			if d.Allowed {
				t.Error("nil policy must deny")
			}
		}()
	}
	wg.Wait()
}

func TestDeep_ConcurrentEgressStats(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"x.com"}})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ec.CheckEgress("x.com", "https", 1)
			ec.Stats()
		}()
	}
	wg.Wait()
}

// ── 6-10: CIDR boundary IPs ────────────────────────────────────

func TestDeep_CIDRFirstIP(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.1.0/24"}})
	d := ec.CheckEgress("192.168.1.0", "https", 1)
	if !d.Allowed {
		t.Error("first IP in /24 should be allowed")
	}
}

func TestDeep_CIDRLastIP(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.1.0/24"}})
	d := ec.CheckEgress("192.168.1.255", "https", 1)
	if !d.Allowed {
		t.Error("last IP in /24 should be allowed")
	}
}

func TestDeep_CIDROneBelow(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.1.0/24"}})
	d := ec.CheckEgress("192.168.0.255", "https", 1)
	if d.Allowed {
		t.Error("IP one below range should be denied")
	}
}

func TestDeep_CIDROneAbove(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"192.168.1.0/24"}})
	d := ec.CheckEgress("192.168.2.0", "https", 1)
	if d.Allowed {
		t.Error("IP one above range should be denied")
	}
}

func TestDeep_CIDRSingleHost(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.1/32"}})
	if !ec.CheckEgress("10.0.0.1", "https", 1).Allowed {
		t.Error("/32 exact match must allow")
	}
	if ec.CheckEgress("10.0.0.2", "https", 1).Allowed {
		t.Error("/32 non-match must deny")
	}
}

// ── 11-15: Deny+Allow+CIDR combined ────────────────────────────

func TestDeep_DenyOverridesAllow(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains: []string{"evil.com"},
		DeniedDomains:  []string{"evil.com"},
	})
	if ec.CheckEgress("evil.com", "https", 1).Allowed {
		t.Error("deny must override allow")
	}
}

func TestDeep_DenyOverridesCIDR(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedCIDRs:  []string{"0.0.0.0/0"},
		DeniedDomains: []string{"10.0.0.1"},
	})
	if ec.CheckEgress("10.0.0.1", "https", 1).Allowed {
		t.Error("denied domain must override CIDR")
	}
}

func TestDeep_ProtocolRestriction(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.io"},
		AllowedProtocols: []string{"https"},
	})
	if ec.CheckEgress("api.io", "ssh", 1).Allowed {
		t.Error("ssh not in allowed protocols")
	}
	if !ec.CheckEgress("api.io", "https", 1).Allowed {
		t.Error("https should be allowed")
	}
}

func TestDeep_PayloadLimit(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:  []string{"a.com"},
		MaxPayloadBytes: 100,
	})
	if ec.CheckEgress("a.com", "https", 101).Allowed {
		t.Error("over payload limit must deny")
	}
	if !ec.CheckEgress("a.com", "https", 100).Allowed {
		t.Error("at payload limit must allow")
	}
}

func TestDeep_CaseFolding(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"MiXeD.IO"}})
	if !ec.CheckEgress("mixed.io", "https", 1).Allowed {
		t.Error("case-insensitive check must allow")
	}
}

// ── 16-20: Schema validation with many field types ──────────────

func TestDeep_SchemaStringField(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	schema := `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`
	if err := fw.AllowTool("t1", schema); err != nil {
		t.Fatal(err)
	}
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t1", map[string]any{"name": "ok"})
	if err != nil {
		t.Fatalf("valid string should pass: %v", err)
	}
}

func TestDeep_SchemaIntegerField(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	schema := `{"type":"object","properties":{"count":{"type":"integer"}},"required":["count"]}`
	fw.AllowTool("t2", schema)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t2", map[string]any{"count": 42})
	if err != nil {
		t.Fatalf("valid integer should pass: %v", err)
	}
}

func TestDeep_SchemaBooleanField(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	schema := `{"type":"object","properties":{"flag":{"type":"boolean"}},"required":["flag"]}`
	fw.AllowTool("t3", schema)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t3", map[string]any{"flag": true})
	if err != nil {
		t.Fatalf("valid boolean should pass: %v", err)
	}
}

func TestDeep_SchemaArrayField(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	schema := `{"type":"object","properties":{"items":{"type":"array","items":{"type":"string"}}}}`
	fw.AllowTool("t4", schema)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t4", map[string]any{"items": []any{"a", "b"}})
	if err != nil {
		t.Fatalf("valid array should pass: %v", err)
	}
}

func TestDeep_SchemaNestedObject(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	schema := `{"type":"object","properties":{"meta":{"type":"object","properties":{"k":{"type":"string"}}}}}`
	fw.AllowTool("t5", schema)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t5", map[string]any{"meta": map[string]any{"k": "v"}})
	if err != nil {
		t.Fatalf("valid nested object should pass: %v", err)
	}
}

// ── 21-25: Dispatcher error propagation ─────────────────────────

func TestDeep_DispatcherErrorPropagates(t *testing.T) {
	fw := NewPolicyFirewall(&errorDispatcher{err: fmt.Errorf("db down")})
	fw.AllowTool("tool", "")
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "tool", nil)
	if err == nil || err.Error() != "db down" {
		t.Fatalf("dispatcher error should propagate, got %v", err)
	}
}

func TestDeep_NilDispatcherFailsClosed(t *testing.T) {
	fw := NewPolicyFirewall(nil)
	fw.AllowTool("tool", "")
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "tool", nil)
	if err == nil {
		t.Error("nil dispatcher must fail-closed")
	}
}

func TestDeep_SchemaValidationBlocksBadType(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	fw.AllowTool("strict", `{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "strict", map[string]any{"n": "not-int"})
	if err == nil {
		t.Error("schema mismatch must be blocked")
	}
}

func TestDeep_MissingParamsWithSchema(t *testing.T) {
	fw := NewPolicyFirewall(&testDispatcher{})
	fw.AllowTool("strict", `{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}`)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "strict", nil)
	if err == nil {
		t.Error("nil params with schema must be blocked")
	}
}

func TestDeep_EgressStringRepr(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains: []string{"a.com", "b.com"},
		DeniedDomains:  []string{"c.com"},
		AllowedCIDRs:   []string{"10.0.0.0/8"},
	})
	s := ec.String()
	if s == "" {
		t.Error("String() must not be empty")
	}
	// Verify the IP parse path for non-IP domain destinations
	d := ec.CheckEgress("notanip.com", "https", 1)
	if d.Allowed {
		t.Error("non-IP non-allowed domain must deny")
	}
	_ = net.ParseIP("invalid")
}
