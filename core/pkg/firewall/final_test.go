package firewall

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_EgressPolicyJSON(t *testing.T) {
	p := EgressPolicy{AllowedDomains: []string{"api.example.com"}, AllowedProtocols: []string{"https"}}
	data, _ := json.Marshal(p)
	var p2 EgressPolicy
	json.Unmarshal(data, &p2)
	if len(p2.AllowedDomains) != 1 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_EgressDecisionJSON(t *testing.T) {
	d := EgressDecision{Allowed: true, Destination: "api.example.com", ReasonCode: ""}
	data, _ := json.Marshal(d)
	var d2 EgressDecision
	json.Unmarshal(data, &d2)
	if !d2.Allowed {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_NewEgressCheckerNilPolicy(t *testing.T) {
	ec := NewEgressChecker(nil)
	d := ec.CheckEgress("anything.com", "https", 100)
	if d.Allowed {
		t.Fatal("nil policy should deny all")
	}
}

func TestFinal_NewEgressCheckerEmptyPolicy(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{})
	d := ec.CheckEgress("anything.com", "https", 100)
	if d.Allowed {
		t.Fatal("empty allowlist should deny all")
	}
}

func TestFinal_EgressCheckerAllowedDomain(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.example.com"}})
	d := ec.CheckEgress("api.example.com", "https", 100)
	if !d.Allowed {
		t.Fatal("allowed domain should pass")
	}
}

func TestFinal_EgressCheckerDeniedDomain(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.example.com"}, DeniedDomains: []string{"api.example.com"}})
	d := ec.CheckEgress("api.example.com", "https", 100)
	if d.Allowed {
		t.Fatal("denied domain takes precedence")
	}
}

func TestFinal_EgressCheckerProtocolRestriction(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.example.com"}, AllowedProtocols: []string{"https"}})
	d := ec.CheckEgress("api.example.com", "ssh", 100)
	if d.Allowed {
		t.Fatal("wrong protocol should be denied")
	}
}

func TestFinal_EgressCheckerPayloadLimit(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.example.com"}, MaxPayloadBytes: 50})
	d := ec.CheckEgress("api.example.com", "https", 100)
	if d.Allowed {
		t.Fatal("oversized payload should be denied")
	}
}

func TestFinal_EgressCheckerCIDR(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8"}})
	d := ec.CheckEgress("10.1.2.3", "https", 100)
	if !d.Allowed {
		t.Fatal("IP in CIDR should be allowed")
	}
}

func TestFinal_EgressCheckerCIDROutside(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8"}})
	d := ec.CheckEgress("192.168.1.1", "https", 100)
	if d.Allowed {
		t.Fatal("IP outside CIDR should be denied")
	}
}

func TestFinal_EgressCheckerStats(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"ok.com"}})
	ec.CheckEgress("ok.com", "https", 10)
	ec.CheckEgress("bad.com", "https", 10)
	total, allowed, denied := ec.Stats()
	if total != 2 || allowed != 1 || denied != 1 {
		t.Fatalf("stats mismatch: total=%d allowed=%d denied=%d", total, allowed, denied)
	}
}

func TestFinal_EgressCheckerString(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, DeniedDomains: []string{"b.com"}})
	s := ec.String()
	if s == "" {
		t.Fatal("String should not be empty")
	}
}

func TestFinal_EgressCheckerWithClock(t *testing.T) {
	fixed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}}).WithClock(func() time.Time { return fixed })
	d := ec.CheckEgress("a.com", "https", 10)
	if d.CheckedAt != fixed {
		t.Fatal("should use custom clock")
	}
}

func TestFinal_EgressCheckerCaseInsensitive(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"API.EXAMPLE.COM"}})
	d := ec.CheckEgress("api.example.com", "https", 10)
	if !d.Allowed {
		t.Fatal("domain check should be case-insensitive")
	}
}

func TestFinal_ConcurrentEgressCheck(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"ok.com"}})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ec.CheckEgress("ok.com", "https", 10)
		}()
	}
	wg.Wait()
}

func TestFinal_PolicyFirewallZeroValue(t *testing.T) {
	pf := &PolicyFirewall{}
	if pf == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_EgressReasonCode(t *testing.T) {
	ec := NewEgressChecker(nil)
	d := ec.CheckEgress("x.com", "https", 10)
	if d.ReasonCode != "DATA_EGRESS_BLOCKED" {
		t.Fatalf("want DATA_EGRESS_BLOCKED, got %s", d.ReasonCode)
	}
}

func TestFinal_EgressCheckerDeterminism(t *testing.T) {
	policy := &EgressPolicy{AllowedDomains: []string{"a.com"}}
	ec1 := NewEgressChecker(policy)
	ec2 := NewEgressChecker(policy)
	d1 := ec1.CheckEgress("b.com", "https", 10)
	d2 := ec2.CheckEgress("b.com", "https", 10)
	if d1.Allowed != d2.Allowed || d1.ReasonCode != d2.ReasonCode {
		t.Fatal("same policy should produce same result")
	}
}

func TestFinal_PolicyInputBundleFields(t *testing.T) {
	pib := PolicyInputBundle{ActorID: "a1", Role: "admin", SessionID: "s1"}
	if pib.ActorID != "a1" || pib.Role != "admin" {
		t.Fatal("field mismatch")
	}
}

func TestFinal_DispatcherInterface(t *testing.T) {
	var _ Dispatcher = (Dispatcher)(nil)
}

func TestFinal_EgressAllowedReasonEmpty(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"ok.com"}})
	d := ec.CheckEgress("ok.com", "https", 10)
	if d.ReasonCode != "" {
		t.Fatal("allowed decision should have empty reason code")
	}
}
