package executor

import "testing"

// ReceiptIDForDecision names the receipts the server mints
// (receipt_routes.go, local_first_run_routes.go). Two tenants that reuse a
// decision ID must never share a receipt ID.
func TestReceiptIDForDecisionIsTenantQualified(t *testing.T) {
	a := ReceiptIDForDecision("tenant-a", "dec-1")
	b := ReceiptIDForDecision("tenant-b", "dec-1")
	if a == b {
		t.Fatalf("tenants share a receipt id for the same decision: %s", a)
	}
	if a != ReceiptIDForDecision("tenant-a", "dec-1") {
		t.Fatal("receipt id is not deterministic")
	}
	if got := ReceiptIDForDecision("  ", "dec-1"); got != "rcpt-dec-1" {
		t.Fatalf("blank tenant: got %q, want the legacy rcpt-<decision> form", got)
	}
	// Length-prefixing keeps the tenant/decision boundary unambiguous.
	if ReceiptIDForDecision("ab", "c") == ReceiptIDForDecision("a", "bc") {
		t.Fatal("tenant/decision boundary is ambiguous")
	}
	if a == "rcpt-dec-1" {
		t.Fatal("a tenant-scoped receipt id fell back to the unscoped form")
	}
}
