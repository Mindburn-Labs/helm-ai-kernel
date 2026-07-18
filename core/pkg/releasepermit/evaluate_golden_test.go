package releasepermit

import "testing"

// Pins the exact permit_id for a fixed ALLOW quorum so any change to the
// permit schema, field set, or canonicalization fails loudly instead of
// silently re-deriving every permit ID in the wild.
const goldenAllowPermitID = "sha256:864f7fa3ed1d06ac3cbfae5b6a08da2ab8124f0125699c22782bafacaf6ecc6c"

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
