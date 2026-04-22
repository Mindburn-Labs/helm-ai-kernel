package sandbox

import (
	"testing"
)

func TestFSAllowed(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	r := e.CheckFS("/tmp/sandbox/data.txt", false)
	if !r.Allowed {
		t.Fatalf("expected allowed, got: %s", r.Reason)
	}
}

func TestFSDenylistBlocks(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	r := e.CheckFS("/etc/passwd", false)
	if r.Allowed {
		t.Fatal("expected denial for /etc/passwd")
	}
}

func TestFSNotInAllowlist(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	r := e.CheckFS("/home/user/secrets", false)
	if r.Allowed {
		t.Fatal("expected denial for path outside allowlist")
	}
}

func TestFSReadOnlyBlocksWrite(t *testing.T) {
	p := DefaultPolicy()
	p.ReadOnly = true
	e := NewPolicyEnforcer(p)
	r := e.CheckFS("/tmp/sandbox/output.txt", true)
	if r.Allowed {
		t.Fatal("expected write blocked in read-only sandbox")
	}
}

func TestNetworkDenyAll(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy()) // NetworkDenyAll=true
	r := e.CheckNetwork("evil.com")
	if r.Allowed {
		t.Fatal("expected network denied")
	}
}

func TestNetworkAllowlist(t *testing.T) {
	p := DefaultPolicy()
	p.NetworkDenyAll = false
	p.NetworkAllowlist = []string{"api.example.com", "internal.corp"}
	e := NewPolicyEnforcer(p)

	r1 := e.CheckNetwork("api.example.com")
	if !r1.Allowed {
		t.Fatal("expected allowed for allowlisted host")
	}

	r2 := e.CheckNetwork("evil.com")
	if r2.Allowed {
		t.Fatal("expected denial for non-allowlisted host")
	}
}

func TestCapabilityAllowed(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	r := e.CheckCapability("read")
	if !r.Allowed {
		t.Fatal("expected read capability allowed")
	}
}

func TestCapabilityDenied(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	r := e.CheckCapability("admin")
	if r.Allowed {
		t.Fatal("expected admin capability denied")
	}
}

func TestMemoryLimit(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy()) // 256MB
	r1 := e.CheckMemory(100 * 1024 * 1024)
	if !r1.Allowed {
		t.Fatal("expected 100MB allowed")
	}

	r2 := e.CheckMemory(500 * 1024 * 1024)
	if r2.Allowed {
		t.Fatal("expected 500MB denied")
	}
}

func TestViolationTracking(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	e.CheckFS("/etc/passwd", false)
	e.CheckNetwork("evil.com")
	violations := e.GetViolations()
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}
}

func TestBrokerIssueToken(t *testing.T) {
	b := NewCredentialBroker(300)
	b.SetScopeAllowlist("sandbox-1", []string{"read:data", "write:output"})

	token, err := b.IssueToken(TokenRequest{
		SandboxID:       "sandbox-1",
		RequestedScopes: []string{"read:data"},
		TTLSeconds:      60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if token.TokenID == "" {
		t.Fatal("expected token ID")
	}
	if token.TokenHash == "" {
		t.Fatal("expected token hash")
	}
}

func TestBrokerDeniesUnallowedScope(t *testing.T) {
	b := NewCredentialBroker(300)
	b.SetScopeAllowlist("sandbox-1", []string{"read:data"})

	_, err := b.IssueToken(TokenRequest{
		SandboxID:       "sandbox-1",
		RequestedScopes: []string{"admin:all"},
		TTLSeconds:      60,
	})
	if err == nil {
		t.Fatal("expected error for unallowed scope")
	}
}

func TestBrokerNoAllowlist(t *testing.T) {
	b := NewCredentialBroker(300)
	_, err := b.IssueToken(TokenRequest{
		SandboxID:       "unknown",
		RequestedScopes: []string{"read:data"},
		TTLSeconds:      60,
	})
	if err == nil {
		t.Fatal("expected error for unknown sandbox")
	}
}

func TestBrokerTokenValidation(t *testing.T) {
	b := NewCredentialBroker(300)
	b.SetScopeAllowlist("sandbox-1", []string{"read:data"})

	token, _ := b.IssueToken(TokenRequest{
		SandboxID:       "sandbox-1",
		RequestedScopes: []string{"read:data"},
		TTLSeconds:      60,
	})

	valid, _ := b.ValidateToken(token.TokenID)
	if !valid {
		t.Fatal("expected valid token")
	}
}

func TestBrokerTokenRevocation(t *testing.T) {
	b := NewCredentialBroker(300)
	b.SetScopeAllowlist("sandbox-1", []string{"read:data"})

	token, _ := b.IssueToken(TokenRequest{
		SandboxID:       "sandbox-1",
		RequestedScopes: []string{"read:data"},
		TTLSeconds:      60,
	})

	_ = b.RevokeToken(token.TokenID)
	valid, reason := b.ValidateToken(token.TokenID)
	if valid {
		t.Fatal("expected revoked token to be invalid")
	}
	if reason != "token revoked" {
		t.Fatalf("expected 'token revoked', got '%s'", reason)
	}
}

func TestBrokerAuditTrail(t *testing.T) {
	b := NewCredentialBroker(300)
	b.SetScopeAllowlist("sandbox-1", []string{"read:data"})

	b.IssueToken(TokenRequest{SandboxID: "sandbox-1", RequestedScopes: []string{"read:data"}, TTLSeconds: 60})
	b.IssueToken(TokenRequest{SandboxID: "sandbox-1", RequestedScopes: []string{"read:data"}, TTLSeconds: 60})

	issuances := b.GetIssuances()
	if len(issuances) != 2 {
		t.Fatalf("expected 2 issuances, got %d", len(issuances))
	}
}
