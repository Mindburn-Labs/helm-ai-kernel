package inferencegateway

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// settleOne drives one governed dispatch end-to-end (quote -> settle) and returns
// the committed usage receipt, which is the internal evidence a provider invoice
// reconciles against.
func settleOne(t *testing.T, h *harness, idem, providerReqID string, providerCostCents int64) *economic.UsageReceipt {
	t.Helper()
	q, err := h.engine.Quote(h.env, h.req(idem, "gpt-6-sol", 100_000, 100_000))
	if err != nil {
		t.Fatalf("quote %s: %v", idem, err)
	}
	settle, err := h.engine.Settle(q.Quote, providerReqID, providerCostCents, 100_000, 100_000)
	if err != nil {
		t.Fatalf("settle %s: %v", idem, err)
	}
	if settle.UsageReceipt == nil {
		t.Fatalf("settle %s produced no usage receipt", idem)
	}
	return settle.UsageReceipt
}
