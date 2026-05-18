package provision

import "testing"

func TestCloudIdempotencyKey(t *testing.T) {
	key := IdempotencyKey("digitalocean", "launch-1", "sha256:plan")
	if key == "" || key == IdempotencyKey("hetzner", "launch-1", "sha256:plan") {
		t.Fatal("expected provider-scoped idempotency key")
	}
}

func TestAmbiguousOutcomeRequiresReconcileBeforeRetry(t *testing.T) {
	outcome := ReconcileBeforeRetry(true)
	if outcome.Status != ReconcileRequired || outcome.RequiresRetry {
		t.Fatalf("expected reconcile-required without retry, got %+v", outcome)
	}
}
