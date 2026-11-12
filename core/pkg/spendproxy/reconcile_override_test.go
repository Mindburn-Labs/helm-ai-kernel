package spendproxy

import (
	"strings"
	"testing"
)

// TestReconcileOverrideRecordsWhy (helm-tracker#313 r2, finding 4): a
// settlement below the recorded actual goes through only with an override
// reason, which the usage receipt records, signed.
func TestReconcileOverrideRecordsWhy(t *testing.T) {
	f, _, intent := settleFailedOverage(t)
	_ = f.server.Close()
	f.raiseOpening(t, "60", "20000")
	opts := f.reconcileOptions(t, intent)
	opts.SettleCents, opts.Reason = 100, "the provider credited most of the call"
	opts.OverrideReason = "provider credit note CN-1 covers 4901 cents"
	res, err := Reconcile(opts)
	if err != nil || res.DebitedCents != 100 || res.RecordedActualCents != 5001 || res.OverrideReason != opts.OverrideReason {
		t.Fatalf("reconcile with an override: %+v, %v", res, err)
	}
	f.start(t)
	for _, rec := range f.records(t) {
		if rec.Kind == RecordUsage && rec.SpendIntentID == intent {
			if got := rec.Usage.Metadata[MetadataReconcileOverride]; !strings.Contains(got, "CN-1") || rec.PayloadSignature == "" {
				t.Fatalf("the usage receipt records override %q (signed %v)", got, rec.PayloadSignature != "")
			}
			return
		}
	}
	t.Fatal("no usage line for the reconciled intent")
}
