package releasepermit

import "testing"

// Pins the exact permit_id for a fixed ALLOW quorum so any change to the
// permit schema, field set, or canonicalization fails loudly instead of
// silently re-deriving every permit ID in the wild.
const goldenAllowPermitID = "sha256:e3fa07cabfae339ecdcc92bfaceeb953da2252cd21a84524a349bc2b72a65f1a"

func TestEvaluatePermitIDGoldenVector(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if permit.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want %q; reasons = %#v", permit.Decision, DecisionAllow, permit.Reasons)
	}
	if permit.PermitID != goldenAllowPermitID {
		t.Fatalf("PermitID = %q, want golden %q — permit canonical form changed; this invalidates issued permit IDs and requires a schema version bump", permit.PermitID, goldenAllowPermitID)
	}
}
