package firewall

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ── Multiple CIDR Ranges ────────────────────────────────────

func TestEgress_ThreeCIDRRanges(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}})
	if len(ec.parsedCIDRs) != 3 {
		t.Errorf("expected 3 CIDRs, got %d", len(ec.parsedCIDRs))
	}
}

func TestEgress_IPv6CIDR(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"fd00::/8"}})
	d := ec.CheckEgress("fd00::1", "https", 10)
	if !d.Allowed {
		t.Error("fd00::1 should match fd00::/8")
	}
}

func TestEgress_CIDRDoesNotMatchDomain(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8"}})
	d := ec.CheckEgress("example.com", "https", 10)
	if d.Allowed {
		t.Error("domain name should not match CIDR-only policy")
	}
}

// ── Overlapping Deny/Allow ──────────────────────────────────

func TestEgress_DenyOverridesAllow(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains: []string{"dual.com"},
		DeniedDomains:  []string{"dual.com"},
	})
	d := ec.CheckEgress("dual.com", "https", 10)
	if d.Allowed {
		t.Error("deny list should override allow list")
	}
}

func TestEgress_AllowedDomainWithDisallowedProtocol(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.com"},
		AllowedProtocols: []string{"https"},
	})
	d := ec.CheckEgress("api.com", "http", 10)
	if d.Allowed {
		t.Error("wrong protocol should be blocked even for allowed domain")
	}
}

func TestEgress_AllowedDomainExceedsPayload(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:  []string{"api.com"},
		MaxPayloadBytes: 100,
	})
	d := ec.CheckEgress("api.com", "https", 200)
	if d.Allowed {
		t.Error("oversized payload should be blocked")
	}
}

// ── Concurrent CheckEgress (100 goroutines) ─────────────────

func TestEgress_Concurrent100Goroutines(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"safe.io"}})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			dest := "safe.io"
			if idx%2 == 0 {
				dest = "blocked.io"
			}
			ec.CheckEgress(dest, "https", 10)
		}(i)
	}
	wg.Wait()
	total, allowed, denied := ec.Stats()
	if total != 100 {
		t.Errorf("expected 100 total checks, got %d", total)
	}
	if allowed+denied != 100 {
		t.Errorf("allowed(%d)+denied(%d) != 100", allowed, denied)
	}
}

func TestEgress_ConcurrentStatsConsistency(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ec.CheckEgress("a.com", "https", 1)
		}()
	}
	wg.Wait()
	_, allowed, _ := ec.Stats()
	if allowed != 50 {
		t.Errorf("expected 50 allowed, got %d", allowed)
	}
}

// ── Very Large Payload ──────────────────────────────────────

func TestEgress_VeryLargePayloadDenied(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:  []string{"d.com"},
		MaxPayloadBytes: 1 << 30, // 1 GiB
	})
	d := ec.CheckEgress("d.com", "https", (1<<30)+1)
	if d.Allowed {
		t.Error("payload exceeding 1 GiB limit should be denied")
	}
}

func TestEgress_ZeroPayloadAllowed(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"d.com"}})
	d := ec.CheckEgress("d.com", "https", 0)
	if !d.Allowed {
		t.Error("zero-byte payload to allowed domain should pass")
	}
}

// ── Empty String Inputs ─────────────────────────────────────

func TestEgress_EmptyDestinationDenied(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}})
	d := ec.CheckEgress("", "https", 10)
	if d.Allowed {
		t.Error("empty destination should be denied (fail-closed)")
	}
}

func TestEgress_EmptyProtocolAllowedWhenNoRestriction(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}})
	d := ec.CheckEgress("a.com", "", 10)
	if !d.Allowed {
		t.Error("empty protocol with no protocol restriction should be allowed")
	}
}

func TestEgress_EmptyProtocolDeniedWhenRestricted(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"a.com"},
		AllowedProtocols: []string{"https"},
	})
	d := ec.CheckEgress("a.com", "", 10)
	if d.Allowed {
		t.Error("empty protocol should not match 'https' restriction")
	}
}

// ── PolicyFirewall Chain of Multiple Dispatchers ────────────

func TestFirewall_ChainedDispatchers(t *testing.T) {
	inner := &stubDispatcher{result: "inner"}
	fw1 := NewPolicyFirewall(inner)
	_ = fw1.AllowTool("tool-a", "")
	fw2 := NewPolicyFirewall(dispatcherFunc(func(ctx context.Context, name string, params map[string]any) (any, error) {
		return fw1.CallTool(ctx, PolicyInputBundle{}, name, params)
	}))
	_ = fw2.AllowTool("tool-a", "")
	result, err := fw2.CallTool(context.Background(), PolicyInputBundle{}, "tool-a", nil)
	if err != nil || result != "inner" {
		t.Errorf("chained dispatch should reach inner, got result=%v err=%v", result, err)
	}
}

func TestFirewall_ChainDeniesAtOuterLayer(t *testing.T) {
	inner := &stubDispatcher{result: "ok"}
	fw1 := NewPolicyFirewall(inner)
	_ = fw1.AllowTool("tool-a", "")
	fw2 := NewPolicyFirewall(dispatcherFunc(func(ctx context.Context, name string, params map[string]any) (any, error) {
		return fw1.CallTool(ctx, PolicyInputBundle{}, name, params)
	}))
	// fw2 does NOT allow tool-a
	_, err := fw2.CallTool(context.Background(), PolicyInputBundle{}, "tool-a", nil)
	if err == nil {
		t.Error("outer firewall should deny tool-a")
	}
}

func TestFirewall_MultipleToolsAllowed(t *testing.T) {
	fw := NewPolicyFirewall(&stubDispatcher{result: "ok"})
	for i := 0; i < 20; i++ {
		_ = fw.AllowTool(fmt.Sprintf("tool-%d", i), "")
	}
	res, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "tool-19", nil)
	if err != nil || res != "ok" {
		t.Errorf("tool-19 should be allowed: err=%v", err)
	}
}

func TestFirewall_SchemaValidationWithAdditionalProperties(t *testing.T) {
	fw := NewPolicyFirewall(&stubDispatcher{result: "ok"})
	schema := `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}`
	_ = fw.AllowTool("strict", schema)
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "strict", map[string]any{"name": "a", "extra": "b"})
	if err == nil {
		t.Error("additional properties should fail strict schema")
	}
}

func TestFirewall_BlockedErrorContainsAllowlist(t *testing.T) {
	fw := NewPolicyFirewall(&stubDispatcher{})
	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "hidden", nil)
	if err == nil || !strings.Contains(err.Error(), "not in allowlist") {
		t.Error("error should mention allowlist")
	}
}

func TestEgress_NegativePayloadTreatedAsWithinLimit(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"d.com"}, MaxPayloadBytes: 100})
	d := ec.CheckEgress("d.com", "https", -1)
	if !d.Allowed {
		t.Error("negative payload bytes should be within limit")
	}
}

func TestFirewall_CallToolReturnsDispatcherResult(t *testing.T) {
	fw := NewPolicyFirewall(&stubDispatcher{result: map[string]string{"key": "val"}})
	_ = fw.AllowTool("t", "")
	result, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]string)
	if !ok || m["key"] != "val" {
		t.Error("dispatcher result should be returned faithfully")
	}
}
