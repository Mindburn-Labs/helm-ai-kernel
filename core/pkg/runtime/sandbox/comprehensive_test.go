package sandbox

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

func TestInProcessSandboxRun(t *testing.T) {
	s := NewInProcessSandbox()
	out, err := s.Run(context.Background(), trust.PackRef{Name: "test"}, []byte("hi"))
	if err != nil || string(out) != "echo: hi" {
		t.Fatalf("err=%v out=%q", err, out)
	}
}

func TestInProcessSandboxCancel(t *testing.T) {
	s := NewInProcessSandbox()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Run(ctx, trust.PackRef{}, []byte("hi"))
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestInProcessSandboxClose(t *testing.T) {
	s := NewInProcessSandbox()
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestSandboxErrorFormat(t *testing.T) {
	e := &SandboxError{Code: ErrComputeTimeExhausted, Message: "timeout"}
	if e.Error() != "ERR_COMPUTE_TIME_EXHAUSTED: timeout" {
		t.Fatalf("unexpected: %s", e.Error())
	}
}

func TestIsMemoryErrorTrue(t *testing.T) {
	cases := []string{"memory limit exceeded", "memory grow failed", "out of memory limit"}
	for _, msg := range cases {
		if !isMemoryError(&testErr{msg}) {
			t.Fatalf("expected true for %q", msg)
		}
	}
}

func TestIsMemoryErrorFalse(t *testing.T) {
	if isMemoryError(&testErr{"some other error"}) {
		t.Fatal("expected false")
	}
	if isMemoryError(nil) {
		t.Fatal("expected false for nil")
	}
}

func TestDefaultPolicyValues(t *testing.T) {
	p := DefaultPolicy()
	if p.PolicyID != "default" || !p.NetworkDenyAll || p.MaxMemoryBytes != 256*1024*1024 {
		t.Fatal("unexpected default policy values")
	}
}

func TestPolicyEnforcerFSAllowed(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	r := e.CheckFS("/tmp/sandbox/file.txt", false)
	if !r.Allowed {
		t.Fatal("expected allowed")
	}
}

func TestPolicyEnforcerFSDenylistPriority(t *testing.T) {
	p := DefaultPolicy()
	p.FSAllowlist = []string{"/etc"}
	e := NewPolicyEnforcer(p)
	r := e.CheckFS("/etc/passwd", false)
	if r.Allowed {
		t.Fatal("denylist should take priority over allowlist")
	}
}

func TestPolicyEnforcerReadOnlyWrite(t *testing.T) {
	p := DefaultPolicy()
	p.ReadOnly = true
	e := NewPolicyEnforcer(p)
	r := e.CheckFS("/tmp/sandbox/out.txt", true)
	if r.Allowed {
		t.Fatal("expected write blocked")
	}
}

func TestPolicyEnforcerNetworkDenyAll(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	r := e.CheckNetwork("example.com")
	if r.Allowed {
		t.Fatal("expected network denied")
	}
}

func TestPolicyEnforcerNetworkAllowlistSubdomain(t *testing.T) {
	p := &SandboxPolicy{NetworkAllowlist: []string{"example.com"}, FSAllowlist: []string{"/"}}
	e := NewPolicyEnforcer(p)
	r := e.CheckNetwork("api.example.com")
	if !r.Allowed {
		t.Fatal("expected subdomain allowed")
	}
}

func TestPolicyEnforcerCapabilityGranted(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	if !e.CheckCapability("execute").Allowed {
		t.Fatal("expected execute allowed")
	}
}

func TestPolicyEnforcerCapabilityDenied(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	if e.CheckCapability("network").Allowed {
		t.Fatal("expected network capability denied")
	}
}

func TestPolicyEnforcerMemoryWithinLimit(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	if !e.CheckMemory(100 * 1024 * 1024).Allowed {
		t.Fatal("expected 100MB allowed")
	}
}

func TestPolicyEnforcerMemoryExceedsLimit(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	if e.CheckMemory(500 * 1024 * 1024).Allowed {
		t.Fatal("expected 500MB denied")
	}
}

func TestPolicyEnforcerViolationTracking(t *testing.T) {
	e := NewPolicyEnforcer(DefaultPolicy())
	e.CheckFS("/etc/shadow", false)
	e.CheckCapability("admin")
	violations := e.GetViolations()
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}
}

func TestBrokerIssueAndValidateToken(t *testing.T) {
	b := NewCredentialBroker(300)
	b.SetScopeAllowlist("sbx-1", []string{"read"})
	tok, err := b.IssueToken(TokenRequest{SandboxID: "sbx-1", RequestedScopes: []string{"read"}, TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := b.ValidateToken(tok.TokenID)
	if !valid {
		t.Fatal("expected valid")
	}
}

func TestBrokerTokenExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := NewCredentialBroker(60).WithClock(func() time.Time { return now })
	b.SetScopeAllowlist("sbx-1", []string{"read"})
	tok, _ := b.IssueToken(TokenRequest{SandboxID: "sbx-1", RequestedScopes: []string{"read"}, TTLSeconds: 60})
	b.WithClock(func() time.Time { return now.Add(2 * time.Minute) })
	valid, reason := b.ValidateToken(tok.TokenID)
	if valid {
		t.Fatal("expected expired")
	}
	if reason != "token expired" {
		t.Fatalf("expected 'token expired', got %q", reason)
	}
}

func TestBrokerRevokeToken(t *testing.T) {
	b := NewCredentialBroker(300)
	b.SetScopeAllowlist("sbx-1", []string{"write"})
	tok, _ := b.IssueToken(TokenRequest{SandboxID: "sbx-1", RequestedScopes: []string{"write"}, TTLSeconds: 60})
	b.RevokeToken(tok.TokenID)
	valid, _ := b.ValidateToken(tok.TokenID)
	if valid {
		t.Fatal("expected revoked")
	}
}

func TestBrokerRevokeNonexistent(t *testing.T) {
	b := NewCredentialBroker(300)
	if err := b.RevokeToken("nope"); err == nil {
		t.Fatal("expected error")
	}
}

type testErr struct{ msg string }

func (e *testErr) Error() string { return e.msg }
