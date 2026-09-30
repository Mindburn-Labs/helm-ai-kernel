package modelgw

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
)

// stubLedger is a Ledger whose answers a test scripts. A call the test did not
// script fails it: a refused request must never reach the ledger.
type stubLedger struct {
	t *testing.T

	OnGrants  func(admission.Caller) (admission.Grants, error)
	OnPropose func(admission.Caller, admission.ProposeInput) (admission.Attempt, bool, error)
	OnCancel  func(admission.Caller, string) (admission.Attempt, bool, error)
	OnClaim   func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error)
	OnSettle  func(*admission.ModelCallClaim, admission.ModelCallOutcome) (admission.Attempt, error)
	OnReplay  func(admission.Caller, string) (*admission.ModelCallReplay, error)

	mu       sync.Mutex
	proposed []admission.ProposeInput
	settled  []admission.ModelCallOutcome
	cancels  []string
}

func (s *stubLedger) ModelGrants(_ context.Context, c admission.Caller, _ string) (admission.Grants, error) {
	if s.OnGrants == nil {
		s.t.Errorf("an unexpected ModelGrants call for %s", c.PrincipalID)
		return admission.Grants{}, context.Canceled
	}
	return s.OnGrants(c)
}

func (s *stubLedger) Propose(_ context.Context, c admission.Caller, in admission.ProposeInput) (admission.Attempt, bool, error) {
	s.mu.Lock()
	s.proposed = append(s.proposed, in)
	s.mu.Unlock()
	if s.OnPropose == nil {
		s.t.Errorf("an unexpected Propose call")
		return admission.Attempt{}, false, context.Canceled
	}
	return s.OnPropose(c, in)
}

func (s *stubLedger) Cancel(_ context.Context, c admission.Caller, _ admission.Token, id string) (admission.Attempt, bool, error) {
	s.mu.Lock()
	s.cancels = append(s.cancels, id)
	s.mu.Unlock()
	if s.OnCancel == nil {
		s.t.Errorf("an unexpected Cancel call")
		return admission.Attempt{}, false, context.Canceled
	}
	return s.OnCancel(c, id)
}

func (s *stubLedger) ClaimModelCall(_ context.Context, c admission.Caller, id string, _ time.Duration) (*admission.ModelCallClaim, admission.Attempt, error) {
	if s.OnClaim == nil {
		s.t.Errorf("an unexpected ClaimModelCall call")
		return nil, admission.Attempt{}, context.Canceled
	}
	return s.OnClaim(c, id)
}

func (s *stubLedger) SettleModelCall(_ context.Context, claim *admission.ModelCallClaim, out admission.ModelCallOutcome) (admission.Attempt, error) {
	s.mu.Lock()
	s.settled = append(s.settled, out)
	s.mu.Unlock()
	if s.OnSettle == nil {
		s.t.Errorf("an unexpected SettleModelCall call")
		return admission.Attempt{}, context.Canceled
	}
	return s.OnSettle(claim, out)
}

func (s *stubLedger) ModelCallReplay(_ context.Context, c admission.Caller, id string) (*admission.ModelCallReplay, error) {
	if s.OnReplay == nil {
		s.t.Errorf("an unexpected ModelCallReplay call")
		return nil, context.Canceled
	}
	return s.OnReplay(c, id)
}

// agentGrants is the grants of an agent whose one mandate covers every route.
func agentGrants(units ...string) func(admission.Caller) (admission.Grants, error) {
	return func(admission.Caller) (admission.Grants, error) {
		return admission.Grants{PrincipalKind: "agent", PrincipalActive: true, SumUnits: units,
			Leaves: []admission.LeafGrant{{MandateID: "01a0f278-0000-7000-8000-000000000001", Active: true, AnyTarget: true}}}, nil
	}
}

// stubbed serves a gateway over l on the worker listener, with the
// authentication of the harness's worker validator, and returns its URL. The
// providers are never reached.
func stubbed(t *testing.T, l Ledger, worker bool) string {
	t.Helper()
	e := &env{t: t}
	cfg := testConfig(t, "http://127.0.0.1:9", "http://127.0.0.1:9/v1", "http://127.0.0.1:9/v1")
	keys := keyProviderFor(map[string]string{"anthropic": keyAnthropic, "openai": keyOpenAI, "openrouter": keyOpenRouter})
	gw := &Gateway{Config: cfg, Ledger: l, Keys: keys}
	name := "main"
	if worker {
		name = "worker"
	}
	srv := httptest.NewServer(server.WithTLSState(gw.Handler(Listener{Name: name, Auth: e.authenticator(worker), Worker: worker})))
	t.Cleanup(srv.Close)
	return srv.URL
}

type keyProviderFor map[string]string

func (k keyProviderFor) Key(_ context.Context, id string) (string, error) { return k[id], nil }
