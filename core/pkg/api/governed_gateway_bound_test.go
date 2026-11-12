package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/inferencegateway"
)

// limitEnvelope sets the fixture envelope's period limit in place, where the
// gateway's resolver reads it.
func (f *gatewayFixture) limitEnvelope(maxCents int64) {
	env := *f.env
	env.MaxAmountCents = maxCents
	env.PerRequestMaxCents = maxCents
	*f.env = *rebuildEnvelope(&env)
}

func (f *gatewayFixture) postBody(t *testing.T, idem, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	for k, v := range helmHeaders(idem, "gpt-6-sol") {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)
	return rr
}

// TestGatewayEnvelopeLimitIsConsumed (helm-tracker#313, audit H7): ten
// requests against a 2-cent envelope stop at the limit, sequential or
// concurrent, and a refused request carries no allowing quote or receipt.
func TestGatewayEnvelopeLimitIsConsumed(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprintf("concurrent=%v", concurrent), func(t *testing.T) {
			f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 1)
			f.limitEnvelope(2)
			var mu sync.Mutex
			allowed := 0
			var wg sync.WaitGroup
			for i := range 10 {
				send := func() {
					rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders(fmt.Sprintf("idem-env-%d", i), "gpt-6-sol"))
					meta := decodeHELM(t, rec)
					mu.Lock()
					defer mu.Unlock()
					switch rec.Code {
					case http.StatusOK:
						allowed++
						if meta.RouteReceipt == nil || meta.RouteReceipt.ReasonCode != economic.SpendReasonOKWithinEnvelope {
							t.Errorf("an admitted request without its OK_WITHIN_ENVELOPE receipt")
						}
					case http.StatusForbidden:
						if meta.RouteReceipt != nil || (meta.Quote != nil && meta.Quote.BudgetVerdict == economic.BudgetVerdictAllow) {
							t.Errorf("a refused request carries an allowing quote or a receipt")
						}
					default:
						t.Errorf("status %d: %s", rec.Code, rec.Body.String())
					}
				}
				if concurrent {
					wg.Add(1)
					go func() { defer wg.Done(); send() }()
				} else {
					send()
				}
			}
			wg.Wait()
			if allowed != 2 || f.dispatch.called != 2 {
				t.Fatalf("a 2-cent envelope admitted %d requests and dispatched %d, want 2", allowed, f.dispatch.called)
			}
		})
	}
}

// TestGatewayDispatchThatMayHaveReachedTheProviderIsDebitedAtItsHold (audit
// H8): a dispatch error that is not a proven not-sent debits the whole hold
// and spends the key; the provider is never called twice for it.
func TestGatewayDispatchThatMayHaveReachedTheProviderIsDebitedAtItsHold(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	f.dispatch.fail = errors.New("the upstream connection was reset after the request was written")
	rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-cut", "gpt-6-sol"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", rec.Code, rec.Body.String())
	}
	meta := decodeHELM(t, rec)
	if !meta.SettledAtHold || meta.Quote == nil || meta.ActualAmountCents != meta.Quote.MaxAmountCents {
		t.Fatalf("meta = %+v, want a settlement at the whole hold", meta)
	}
	if f.ledger.HoldCents() != 0 || f.ledger.BalanceCents() != 100_000-meta.Quote.MaxAmountCents {
		t.Fatalf("hold/balance = %d/%d, want the hold debited", f.ledger.HoldCents(), f.ledger.BalanceCents())
	}
	f.dispatch.fail = nil
	if rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-cut", "gpt-6-sol")); rec.Code != http.StatusConflict {
		t.Fatalf("retry status = %d, want 409", rec.Code)
	}
	if f.dispatch.called != 1 {
		t.Fatalf("dispatches = %d, want 1", f.dispatch.called)
	}
}

// TestGatewayDispatchNeverSentReleases: an error before any request byte left
// the process frees the hold, and the key may be retried.
func TestGatewayDispatchNeverSentReleases(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	f.dispatch.fail = fmt.Errorf("dial tcp: connection refused: %w", ErrDispatchNotSent)
	if rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-unsent", "gpt-6-sol")); rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if f.ledger.HoldCents() != 0 || f.ledger.BalanceCents() != 100_000 {
		t.Fatalf("hold/balance = %d/%d, want the hold released", f.ledger.HoldCents(), f.ledger.BalanceCents())
	}
	f.dispatch.fail = nil
	if rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-unsent", "gpt-6-sol")); rec.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// TestGatewayAnswerWithoutUsageSettlesAtTheHold: a provider answer whose usage
// cannot be read is returned and debited at the hold.
func TestGatewayAnswerWithoutUsageSettlesAtTheHold(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	f.dispatch.usageUnknown = true
	rec := f.do(t, http.MethodPost, "/v1/chat/completions", "gpt-6-sol", helmHeaders("idem-nousage", "gpt-6-sol"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	meta := decodeHELM(t, rec)
	if !meta.SettledAtHold || meta.ActualAmountCents != meta.Quote.MaxAmountCents {
		t.Fatalf("meta = %+v, want a settlement at the hold", meta)
	}
}

// TestGatewayRefusesRoutingMembers (audit M18): members that let the upstream
// choose the billed model, or bill more than one completion, never reach it.
func TestGatewayRefusesRoutingMembers(t *testing.T) {
	f := newGatewayFixture(t, inferencegateway.StalePriceFailClosed, inferencegateway.CostCapClamp, 2)
	for member, value := range map[string]string{
		"models": `["gpt-6-sol","claude-haiku"]`, "provider": `{"order":["x"]}`, "plugins": `[{"id":"web"}]`,
		"route": `"fallback"`, "n": `2`,
	} {
		body := `{"model":"gpt-6-sol","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"` + member + `":` + value + `}`
		rec := f.postBody(t, "idem-"+member, body)
		if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte(member)) {
			t.Errorf("%s: status %d (%s), want 400 naming it", member, rec.Code, rec.Body.String())
		}
	}
	if f.dispatch.called != 0 {
		t.Fatalf("dispatches = %d, want 0", f.dispatch.called)
	}
	if rec := f.postBody(t, "idem-n1", `{"model":"gpt-6-sol","max_tokens":64,"n":1,"messages":[{"role":"user","content":"hi"}]}`); rec.Code != http.StatusOK {
		t.Fatalf("n=1: status %d, want 200", rec.Code)
	}
	var sent map[string]json.RawMessage
	_ = json.Unmarshal(f.dispatch.body, &sent)
	if string(sent["n"]) != "1" {
		t.Fatalf("forwarded n = %s, want 1", sent["n"])
	}
}
