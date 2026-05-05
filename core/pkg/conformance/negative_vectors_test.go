package conformance

import "testing"

func TestDefaultNegativeBoundaryVectorsContainRequiredGates(t *testing.T) {
	required := []string{
		"policy-not-ready",
		"stale-policy-bundle",
		"stale-rebac-tuples",
		"mcp-tool-list-call-mismatch",
		"direct-upstream-bypass",
		"pdp-outage",
		"missing-credentials",
		"malformed-tool-args",
		"schema-drift",
		"sandbox-overgrant",
		"blocked-egress",
		"deny-receipt-emission",
	}
	vectors := DefaultNegativeBoundaryVectors()
	seen := map[string]NegativeBoundaryVector{}
	for _, vector := range vectors {
		if vector.ID == "" {
			t.Fatal("negative vector has empty id")
		}
		if _, exists := seen[vector.ID]; exists {
			t.Fatalf("duplicate negative vector id %q", vector.ID)
		}
		seen[vector.ID] = vector
	}
	for _, id := range required {
		if _, ok := seen[id]; !ok {
			t.Fatalf("missing required negative vector %q", id)
		}
	}
}

func TestDefaultNegativeBoundaryVectorsFailClosed(t *testing.T) {
	for _, vector := range DefaultNegativeBoundaryVectors() {
		t.Run(vector.ID, func(t *testing.T) {
			if vector.ExpectedVerdict != "DENY" {
				t.Fatalf("expected verdict = %s, want DENY", vector.ExpectedVerdict)
			}
			if vector.ExpectedReasonCode == "" {
				t.Fatal("expected reason code is required")
			}
			if !vector.MustEmitReceipt {
				t.Fatal("negative vector must emit a receipt")
			}
			if !vector.MustNotDispatch {
				t.Fatal("negative vector must not dispatch")
			}
			if len(vector.MustBindEvidence) == 0 {
				t.Fatal("negative vector must bind at least one evidence field")
			}
		})
	}
}
