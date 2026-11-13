package modelgw

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// freshWorker shares only the database and provider configuration with the
// original gateway. Its admission service and HTTP handler are new instances.
func freshWorker(t *testing.T, e *env) *httptest.Server {
	t.Helper()
	ledger, err := admission.New(e.runtime, admission.Config{ReceiptSigner: testReceiptSigner, Adapters: []adapters.Adapter{NewAdapter()}})
	must(t, err)
	peer := *e
	gateway := *e.gw
	gateway.Ledger = ledger
	peer.gw = &gateway
	return peer.serve(true)
}

// Two cents permit two 7503-micro-dollar calls; each subsequent request must
// observe the durable consumption even with a fresh gateway and no local log.
func TestPostgresModelBudgetSurvivesGatewayRecreation(t *testing.T) {
	e := newEnvWindow(t, 20_000, "none")
	e.anthropic.on(jsonHandler(budgetUsage(500)))
	for i := range 10 {
		worker := freshWorker(t, e)
		result := post(t, worker.URL, "/v1/messages", workerHeaders(tokenAgent), budgetMessage(fmt.Sprintf("request-%02d", i), 500))
		worker.Close()
		if i < 2 {
			if result.Status != 200 {
				t.Fatalf("funded call %d: %s", i, result)
			}
		} else if result.Status != 403 || result.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonBudgetExceeded) {
			t.Fatalf("call %d reused the budget after gateway recreation: %s", i, result)
		}
	}
	if calls := e.anthropic.calls.Load(); calls != 2 {
		t.Fatalf("ten calls against two cents reached the provider %d times, want 2", calls)
	}
	e.ledgerBalances()
}
