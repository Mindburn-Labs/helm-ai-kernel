package modelgw

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

type capturedModelClaim struct {
	Ledger
	claims chan *admission.ModelCallClaim
}

func (l *capturedModelClaim) ClaimModelCall(ctx context.Context, caller admission.Caller, id string, ttl time.Duration) (*admission.ModelCallClaim, admission.Attempt, error) {
	claim, attempt, err := l.Ledger.ClaimModelCall(ctx, caller, id, ttl)
	if claim != nil && err == nil {
		l.claims <- claim
	}
	return claim, attempt, err
}

// T82 exercises the actual HTTP dispatch and restricted PostgreSQL ledger.
// The late report enters through the trusted internal settlement port, using
// the original claim; this does not assert a provider webhook/retrieval API.
func TestPostgresModelGatewayLateUsageCorrectsAnEstimateWithoutRedispatch(t *testing.T) {
	for _, cut := range []bool{false, true} {
		name := "completed_without_usage"
		if cut {
			name = "cut_stream"
		}
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 1_000_000)
			ledger := &capturedModelClaim{Ledger: e.svc, claims: make(chan *admission.ModelCallClaim, 1)}
			g := *e.gw
			g.Ledger = ledger
			url := servedHandler(t, &g, e)
			stream := strings.ReplaceAll(anthropicStream, `,"usage":{"input_tokens":25,"output_tokens":1}`, "")
			stream = strings.ReplaceAll(stream, `,"usage":{"output_tokens":15}`, "")
			if cut {
				stream = stream[:strings.Index(stream, "event: message_delta")]
			}
			e.anthropic.on(func(w http.ResponseWriter, r *http.Request) {
				// A positive reservation must already exist when the provider
				// receives the request, even when it will omit final usage.
				if used, held := e.counters(); used != 0 || held <= 0 {
					t.Errorf("provider called before reservation: used=%d held=%d", used, held)
				}
				sseHandler(stream)(w, r)
			})
			resp, err := requestOnce(url+"/v1/messages", workerHeaders(tokenAgent), messagesRequest)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if !cut && (readErr != nil || resp.StatusCode != 200 || string(body) != stream) {
				t.Fatalf("completed stream: status%d err%v body%q", resp.StatusCode, readErr, body)
			}
			if cut && readErr == nil {
				t.Fatal("truncated stream appeared complete")
			}
			claim := <-ledger.claims
			waitFor(t, "initial estimate", func() bool {
				return e.onlyAttempt().ModelCall.State == admission.SettlementEstimated
			})
			a := e.onlyAttempt()
			if cut && a.State != "UNKNOWN" {
				t.Fatalf("cut state=%s", a.State)
			}
			if used, held := e.counters(); used != a.ModelCall.HeldMicros || held != 0 {
				t.Fatalf("initial estimate: used%d reserved%d", used, held)
			}
			e.ledgerBalances()
			// Cost is delivered twice by the trusted internal producer, with
			// the same claim. Neither delivery may call the provider again.
			out := admission.ModelCallOutcome{Result: admission.ModelCallConfirmed, ConfirmedMicros: anthropicStreamCost,
				Usage: []byte(`{"input_tokens":25,"output_tokens":15}`)}
			for range 2 {
				confirmed, err := e.svc.SettleModelCall(context.Background(), claim, out)
				must(t, err)
				if confirmed.State != "SETTLED" || confirmed.ModelCall.State != admission.SettlementConfirmed || *confirmed.ModelCall.ConfirmedMicros != anthropicStreamCost || confirmed.ModelCall.BillableMicros != min(anthropicStreamCost, confirmed.ModelCall.HeldMicros) {
					t.Fatalf("late usage: %+v %+v", confirmed, confirmed.ModelCall)
				}
				if used, held := e.counters(); used != anthropicStreamCost || held != 0 {
					t.Fatalf("confirmed counters: used%d reserved%d", used, held)
				}
				e.ledgerBalances()
			}
			if n := e.anthropic.calls.Load(); n != 1 {
				t.Fatalf("provider dispatched %d times", n)
			}
		})
	}
}
