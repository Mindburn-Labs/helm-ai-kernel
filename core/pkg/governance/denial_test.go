package governance

import (
	"testing"
)

func TestDenialLedgerDeny(t *testing.T) {
	l := NewDenialLedger()
	r := l.Deny("alice", "deploy:prod", DenialPolicy, "envelope expired")
	if r.ReceiptID == "" {
		t.Fatal("expected receipt ID")
	}
	if r.Reason != DenialPolicy {
		t.Fatalf("expected POLICY, got %s", r.Reason)
	}
	if r.ContentHash == "" {
		t.Fatal("expected content hash")
	}
}

func TestDenialLedgerDenyWithContext(t *testing.T) {
	l := NewDenialLedger()
	r := l.DenyWithContext("bob", "t1", "write:db", "run-42", DenialTenant, "cross-tenant access", "pol-1", "env-1")
	if r.TenantID != "t1" {
		t.Fatal("expected tenant t1")
	}
	if r.PolicyRef != "pol-1" {
		t.Fatal("expected policy ref")
	}
	if r.EnvelopeRef != "env-1" {
		t.Fatal("expected envelope ref")
	}
}

func TestDenialLedgerQueryByReason(t *testing.T) {
	l := NewDenialLedger()
	l.Deny("a", "x", DenialBudget, "over budget")
	l.Deny("b", "y", DenialPolicy, "no policy")
	l.Deny("c", "z", DenialBudget, "budget exhausted")

	results := l.QueryByReason(DenialBudget)
	if len(results) != 2 {
		t.Fatalf("expected 2 budget denials, got %d", len(results))
	}
}

func TestDenialLedgerQueryByPrincipal(t *testing.T) {
	l := NewDenialLedger()
	l.Deny("alice", "x", DenialPolicy, "a")
	l.Deny("bob", "y", DenialPolicy, "b")
	l.Deny("alice", "z", DenialSandbox, "c")

	results := l.QueryByPrincipal("alice")
	if len(results) != 2 {
		t.Fatalf("expected 2 alice denials, got %d", len(results))
	}
}

func TestDenialLedgerGet(t *testing.T) {
	l := NewDenialLedger()
	r := l.Deny("alice", "x", DenialJurisdiction, "wrong region")

	got, err := l.Get(r.ReceiptID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reason != DenialJurisdiction {
		t.Fatal("reason mismatch")
	}
}

func TestDenialLedgerGetNotFound(t *testing.T) {
	l := NewDenialLedger()
	_, err := l.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDenialLedgerLength(t *testing.T) {
	l := NewDenialLedger()
	l.Deny("a", "x", DenialPolicy, "a")
	l.Deny("b", "y", DenialBudget, "b")
	if l.Length() != 2 {
		t.Fatalf("expected 2, got %d", l.Length())
	}
}

func TestDenialReasonTypes(t *testing.T) {
	reasons := []DenialReason{
		DenialPolicy, DenialProvenance, DenialBudget, DenialSandbox,
		DenialTenant, DenialJurisdiction, DenialVerification, DenialEnvelope,
	}
	l := NewDenialLedger()
	for _, r := range reasons {
		receipt := l.Deny("test", "test-action", r, "test")
		if receipt.Reason != r {
			t.Fatalf("expected %s, got %s", r, receipt.Reason)
		}
	}
	if l.Length() != 8 {
		t.Fatalf("expected 8, got %d", l.Length())
	}
}
