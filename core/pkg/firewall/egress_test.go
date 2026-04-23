package firewall

import (
	"testing"
	"time"
)

func testPolicy() *EgressPolicy {
	return &EgressPolicy{
		AllowedDomains:   []string{"api.github.com", "registry.npmjs.org"},
		DeniedDomains:    []string{"evil.com"},
		AllowedCIDRs:     []string{"10.0.0.0/8"},
		AllowedProtocols: []string{"https", "grpc"},
		MaxPayloadBytes:  1024 * 1024, // 1MB
	}
}

func TestEgressChecker_AllowedDomain(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	d := ec.CheckEgress("api.github.com", "https", 100)
	if !d.Allowed {
		t.Errorf("api.github.com should be allowed, got reason: %s", d.ReasonCode)
	}
}

func TestEgressChecker_DeniedDomain(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	d := ec.CheckEgress("evil.com", "https", 100)
	if d.Allowed {
		t.Error("evil.com should be denied")
	}
	if d.ReasonCode != "DATA_EGRESS_BLOCKED" {
		t.Errorf("reason = %s, want DATA_EGRESS_BLOCKED", d.ReasonCode)
	}
}

func TestEgressChecker_UnknownDomainDenied(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	d := ec.CheckEgress("unknown-server.io", "https", 100)
	if d.Allowed {
		t.Error("unknown domain should be denied (fail-closed)")
	}
	if d.ReasonCode != "DATA_EGRESS_BLOCKED" {
		t.Errorf("reason = %s, want DATA_EGRESS_BLOCKED", d.ReasonCode)
	}
}

func TestEgressChecker_DeniedTakesPrecedence(t *testing.T) {
	policy := &EgressPolicy{
		AllowedDomains: []string{"dual.example.com"},
		DeniedDomains:  []string{"dual.example.com"},
	}
	ec := NewEgressChecker(policy)
	d := ec.CheckEgress("dual.example.com", "https", 100)
	if d.Allowed {
		t.Error("denied list should take precedence over allowed")
	}
}

func TestEgressChecker_ProtocolRestriction(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	d := ec.CheckEgress("api.github.com", "ssh", 100)
	if d.Allowed {
		t.Error("ssh should be blocked when only https/grpc allowed")
	}
}

func TestEgressChecker_PayloadSizeLimit(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	d := ec.CheckEgress("api.github.com", "https", 2*1024*1024) // 2MB > 1MB limit
	if d.Allowed {
		t.Error("oversized payload should be blocked")
	}
}

func TestEgressChecker_CIDRAllowed(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	d := ec.CheckEgress("10.0.1.5", "https", 100)
	if !d.Allowed {
		t.Error("10.0.1.5 should match 10.0.0.0/8 CIDR")
	}
}

func TestEgressChecker_CIDRDenied(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	d := ec.CheckEgress("192.168.1.1", "https", 100)
	if d.Allowed {
		t.Error("192.168.1.1 should not match any allowed CIDR")
	}
}

func TestEgressChecker_NilPolicyDenyAll(t *testing.T) {
	ec := NewEgressChecker(nil)
	d := ec.CheckEgress("any-domain.com", "https", 100)
	if d.Allowed {
		t.Error("nil policy should deny all (fail-closed)")
	}
}

func TestEgressChecker_EmptyPolicyDenyAll(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{})
	d := ec.CheckEgress("any-domain.com", "https", 100)
	if d.Allowed {
		t.Error("empty policy should deny all (fail-closed)")
	}
}

func TestEgressChecker_NoProtocolRestriction(t *testing.T) {
	policy := &EgressPolicy{
		AllowedDomains: []string{"open.example.com"},
		// No AllowedProtocols = no protocol restriction
	}
	ec := NewEgressChecker(policy)
	d := ec.CheckEgress("open.example.com", "ssh", 100)
	if !d.Allowed {
		t.Error("no protocol restriction should allow any protocol")
	}
}

func TestEgressChecker_Stats(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	ec.CheckEgress("api.github.com", "https", 100) // allow
	ec.CheckEgress("evil.com", "https", 100)       // deny
	ec.CheckEgress("unknown.io", "https", 100)     // deny

	total, allowed, denied := ec.Stats()
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if allowed != 1 {
		t.Errorf("allowed = %d, want 1", allowed)
	}
	if denied != 2 {
		t.Errorf("denied = %d, want 2", denied)
	}
}

func TestEgressChecker_CaseInsensitive(t *testing.T) {
	ec := NewEgressChecker(testPolicy())
	d := ec.CheckEgress("API.GITHUB.COM", "HTTPS", 100)
	if !d.Allowed {
		t.Error("domain matching should be case-insensitive")
	}
}

func TestEgressChecker_Timestamp(t *testing.T) {
	ts := time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC)
	ec := NewEgressChecker(testPolicy()).WithClock(func() time.Time { return ts })

	d := ec.CheckEgress("api.github.com", "https", 100)
	if d.CheckedAt != ts {
		t.Errorf("checked_at = %v, want %v", d.CheckedAt, ts)
	}
}
