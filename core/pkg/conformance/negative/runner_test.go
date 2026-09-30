package negative

import (
	"context"
	"testing"
)

func TestDefaultCasesHoldTheirVectors(t *testing.T) {
	report := Run(context.Background(), DefaultCases())

	t.Logf("negative boundary vectors: %d total, %d bound, %d passed, %d failed",
		report.Total, report.Bound, report.Passed, report.Failed)

	if len(report.UnknownIDs) > 0 {
		t.Errorf("cases reference vector ids absent from the catalog: %v", report.UnknownIDs)
	}
	if report.Bound == 0 {
		t.Fatal("no vector is bound; the suite measures nothing")
	}

	// Coverage ratchet (T-07): these vectors are bound and must stay bound.
	// Checking only Bound != 0 let coverage fall from 4 to 1 unnoticed. Add an
	// id here when a vector gains a harness; never remove one.
	bound := map[string]bool{}
	for _, result := range report.Results {
		if result.Bound {
			bound[result.VectorID] = true
		}
	}
	for _, id := range []string{"policy-not-ready", "pdp-outage", "missing-credentials", "blocked-egress"} {
		if !bound[id] {
			t.Errorf("vector %q is no longer bound to a harness; bound coverage regressed", id)
		}
	}

	for _, result := range report.Results {
		if !result.Bound || result.Pass {
			continue
		}
		t.Errorf("vector %q did not hold (verdict %q, reason %q): %v",
			result.VectorID, result.GotVerdict, result.GotReasonCode, result.Failures)
	}
}

// The catalog is the denominator. If a vector is added without a harness this
// still passes — but the recorded coverage moves, and that number is the whole
// point of the suite.
func TestReportAccountsForEveryVector(t *testing.T) {
	report := Run(context.Background(), DefaultCases())

	if got := report.Bound + len(report.UnboundIDs); got != report.Total {
		t.Errorf("bound (%d) + unbound (%d) = %d, want %d vectors",
			report.Bound, len(report.UnboundIDs), got, report.Total)
	}
	if got := report.Passed + report.Failed; got != report.Bound {
		t.Errorf("passed (%d) + failed (%d) = %d, want %d bound", report.Passed, report.Failed, got, report.Bound)
	}
	if len(report.Results) != report.Total {
		t.Errorf("report carries %d results, want one per %d vectors", len(report.Results), report.Total)
	}
}
