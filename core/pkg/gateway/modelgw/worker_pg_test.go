package modelgw

// quantum_posture: computes SHA-256 digests to compare with stored ones; signs
// nothing.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

func TestPostgresTokensAreRefusedOnTheWrongListener(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.anthropic.on(sseHandler(anthropicStream))
	body := `{"model":"claude-sonnet-5-5","max_tokens":100,"messages":[]}`
	// The Control Plane's token on the worker listener, and a worker's on the
	// main listener: each is 401 and touches nothing.
	if r := post(t, e.worker.URL, "/v1/messages", bearerHeader(tokenService), body); r.Status != 401 {
		t.Fatalf("a main token on the worker listener: %s", r)
	}
	if r := post(t, e.main.URL, "/v1/messages", bearerHeader(tokenAgent), body); r.Status != 401 {
		t.Fatalf("a worker token on the main listener: %s", r)
	}
	if r := get(t, e.main.URL+"/v1/models", bearerHeader(tokenAgent)); r.Status != 401 {
		t.Fatalf("a worker token on the main listener's models: %s", r)
	}
	if len(e.attempts()) != 0 || e.anthropic.calls.Load() != 0 {
		t.Fatal("a token refused at the door left an attempt or a provider call")
	}
	// A worker token with no episode is not an episode token.
	if r := post(t, e.worker.URL, "/v1/messages", bearerHeader(tokenNoEpisode), body); r.Status != 403 {
		t.Fatalf("a worker token with no episode: %s", r)
	}
	// Only agents call on the worker listener; a service or a human does not,
	// even with a well-formed episode token.
	for _, token := range []string{"canary-svc-worker", "canary-human-worker"} {
		if r := post(t, e.worker.URL, "/v1/messages", bearerHeader(token), body); r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonInsufficientPrivilege) {
			t.Fatalf("%s: %s %v", token, r, r.Header)
		}
	}
	// On the main listener a human does not call either: a workload calls for them.
	if r := post(t, e.main.URL, "/v1/messages", bearerHeader(tokenHuman), body); r.Status != 403 {
		t.Fatalf("a human on the main listener: %s", r)
	}
	if len(e.attempts()) != 0 {
		t.Fatal("a refused principal left an attempt")
	}
}

func TestPostgresTenantsAreSeparateAndTheTenantComesFromTheToken(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.anthropic.on(sseHandler(anthropicStream))
	var superuser, bypassRLS bool
	must(t, e.runtime.QueryRow(`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS))
	if superuser || bypassRLS {
		t.Fatal("the gateway test role bypasses tenant row security")
	}
	// The same seat in tenant B, same episode, same request: its own attempt
	// under its own tenant, with its own budget, and no replay across tenants.
	first := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if first.Status != 200 {
		t.Fatalf("tenant A: %s", first)
	}
	r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenOtherTen), messagesRequest)
	if r.Status != 200 || r.Header.Get("X-Helm-Replayed") != "" || e.anthropic.calls.Load() != 2 {
		t.Fatalf("tenant B: %s, %d provider calls", r, e.anthropic.calls.Load())
	}
	if first.Header.Get(headerAttemptID) == "" || first.Header.Get(headerAttemptID) == r.Header.Get(headerAttemptID) {
		t.Fatal("the two tenants did not receive distinct attempts")
	}
	for _, table := range []string{"authority_effect_attempts", "authority_model_calls", "authority_model_replays"} {
		var enabled, forced bool
		must(t, e.runtime.QueryRow(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, table).Scan(&enabled, &forced))
		if !enabled || !forced {
			t.Fatalf("%s is not under FORCE RLS", table)
		}
		for _, tenant := range []string{tenantA, tenantB} {
			// Without a WHERE clause this checks the installed RLS policy;
			// the explicit predicate also checks the row's stored tenant.
			if n := e.count(tenant, `SELECT count(*) FROM `+table); n != 1 {
				t.Fatalf("%s sees %d rows in %s", tenant, n, table)
			}
			if n := e.count(tenant, `SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, tenant); n != 1 {
				t.Fatalf("%s has %d rows in %s", tenant, n, table)
			}
			if n := e.count(tenant, `SELECT count(*) FROM `+table+` WHERE tenant_id <> $1`, tenant); n != 0 {
				t.Fatalf("%s sees %d other-tenant rows in %s", tenant, n, table)
			}
		}
		if n := e.count("", `SELECT count(*) FROM `+table); n != 0 {
			t.Fatalf("an unbound tenant sees %d rows in %s", n, table)
		}
	}
	for _, token := range []string{tokenAgent, tokenOtherTen} {
		replay := post(t, e.worker.URL, "/v1/messages", workerHeaders(token), messagesRequest)
		if replay.Status != 200 || replay.Header.Get("X-Helm-Replayed") != "true" || e.anthropic.calls.Load() != 2 {
			t.Fatalf("tenant replay: %s, %d provider calls", replay, e.anthropic.calls.Load())
		}
	}
	// A request body cannot name a tenant, a principal or a case: only the token does.
	spoofed := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), strings.Replace(messagesRequest, `"stream":true`, `"stream":true,"tenant_id":"tenant-b","principal_id":"human-a","metadata":{"user_id":"human-a"}`, 1))
	if spoofed.Status != 200 || e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE tenant_id = $1`, tenantA) != 2 || e.count(tenantB, `SELECT count(*) FROM authority_effect_attempts WHERE tenant_id = $1`, tenantB) != 1 {
		t.Fatalf("request-body tenant spoof: %s", spoofed)
	}
	for _, a := range e.attempts() {
		if a.RequesterPrincipalID != "agt:seat-1" || a.CaseID != "work-ep-1" {
			t.Fatalf("attempt = %+v", a)
		}
	}
}

func TestPostgresAStopFencesModelCalls(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.anthropic.on(sseHandler(anthropicStream))
	ctx := context.Background()
	stop, err := e.rows.Stop(ctx, tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopePrincipal, Key: "agt:seat-1"}, Reason: "runaway", IssuedBy: "human-a"})
	must(t, err)
	r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("a stopped seat: %s %v", r, r.Header)
	}
	if e.anthropic.calls.Load() != 0 {
		t.Fatal("a stopped seat's call reached the provider")
	}
	must(t, e.rows.Lift(ctx, tenantA, stop.ID, authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"}))
	if r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest); r.Status != 200 {
		t.Fatalf("after the lift: %s", r)
	}
}

func TestPostgresAModelCallStopsAtAStopIssuedAfterItsProposal(t *testing.T) {
	// A stop committed between the proposal and the claim refuses the claim:
	// the call never reaches the provider, and the hold is given back.
	e := newEnv(t, 1_000_000)
	e.anthropic.on(sseHandler(anthropicStream))
	stopped := &stoppingLedger{Ledger: e.svc, before: func() {
		_, err := e.rows.Stop(context.Background(), tenantA, authorityrows.StopSpec{Scope: authorityrows.Scope{Kind: authorityrows.ScopeTenant, Key: tenantA}, Reason: "halt", IssuedBy: "human-a"})
		must(t, err)
	}}
	e.gw.Ledger = stopped
	r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), messagesRequest)
	if r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("a stop between the proposal and the claim: %s %v", r, r.Header)
	}
	if e.anthropic.calls.Load() != 0 {
		t.Fatal("the call reached the provider")
	}
	a := e.onlyAttempt()
	if a.State != "CANCELLED" || a.ReasonCode != string(contracts.ReasonEmergencyStopFenced) || a.ModelCall != nil {
		t.Fatalf("attempt = %+v", a)
	}
	if used, reserved := e.counters(); used != 0 || reserved != 0 {
		t.Fatalf("a refused claim kept its hold: %d %d", used, reserved)
	}
}

// stoppingLedger runs before once, between a proposal and the claim that follows.
type stoppingLedger struct {
	Ledger
	before func()
	once   sync.Once
}

func (s *stoppingLedger) ClaimModelCall(ctx context.Context, c admission.Caller, id string, fence time.Duration) (*admission.ModelCallClaim, admission.Attempt, error) {
	s.once.Do(s.before)
	return s.Ledger.ClaimModelCall(ctx, c, id, fence)
}

func TestPostgresASeatWithSeveralMandatesReachesEachRouteThroughItsOwn(t *testing.T) {
	e := newEnv(t, 1_000_000)
	ctx := context.Background()
	// A second seat whose two mandates cover one route each: the request must
	// select the mandate that covers its route, or the first one would deny it.
	must(t, e.rows.CreatePrincipal(ctx, tenantA, "agt:seat-two", authorityrows.PrincipalAgent))
	widen := authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"}
	terms := func(route string) authorityrows.Terms {
		return authorityrows.Terms{EffectTypes: []string{effectargs.ModelInference}, ValidFrom: e.now.Add(-time.Hour), ValidUntil: e.now.Add(24 * time.Hour), Targets: []string{route}}
	}
	for _, route := range []string{routeGPT, routeSonnet} {
		m, err := e.rows.CreateMandate(ctx, tenantA, "agt:seat-two", terms(route), widen)
		must(t, err)
		_, err = e.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{MandateID: &m.ID, Unit: admission.UnitUSDMicros, Measure: "sum", Window: "day", Value: 1_000_000, Span: 1})
		must(t, err)
	}
	authenticator := e.authenticator(true)
	authenticator.Validator.(testValidator)["canary-seat-two"] = claims("agt:seat-two", "helm-gateway-worker:test", "helm.gateway.propose",
		e.episodeClaim("ep-1"))
	e.anthropic.on(jsonHandler(`{"usage":{"input_tokens":1,"output_tokens":1}}`))
	e.openai.on(jsonHandler(`{"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	url := newTestServer(t, e.gw.Handler(Listener{Name: "worker", Auth: authenticator, Worker: true}))
	for name, test := range map[string]struct{ path, body string }{
		"the first route in mandate order":  {"/v1/chat/completions", `{"model":"gpt-6-sol","messages":[]}`},
		"the second route in mandate order": {"/v1/messages", `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[]}`},
	} {
		r := post(t, url, test.path, workerHeaders("canary-seat-two"), test.body)
		if r.Status != 200 {
			t.Errorf("%s: %s", name, r)
		}
	}
	// A route neither mandate names is still denied.
	r := post(t, url, "/v1/messages", workerHeaders("canary-seat-two"), `{"model":"claude-haiku-4-5-20251001","max_tokens":10,"messages":[]}`)
	if r.Status != 403 || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonEffectOutOfScope) {
		t.Fatalf("an uncovered route: %s", r)
	}
	// And the models list shows the union of both.
	list := get(t, url+"/v1/models", workerHeaders("canary-seat-two"))
	var got []string
	for _, id := range []string{"gpt-6-sol", "claude-sonnet-5-5", "claude-haiku-4-5-20251001", "claude-opus-5-5"} {
		if strings.Contains(string(list.Body), `"`+id+`"`) {
			got = append(got, id)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "claude-sonnet-5-5,gpt-6-sol" {
		t.Fatalf("models = %v: %s", got, list.Body)
	}
}

func (e *env) episodeClaim(id string) *jwks.EpisodeClaim {
	return &jwks.EpisodeClaim{EpisodeID: id, WorkItemID: "work-" + id, OrganizationVersionID: "ver-1"}
}

// The p95 of the time before the gateway sends a request to the provider must
// stay under 75 ms at 20 requests a second (HELM-752 L4): the price of
// authenticating, inspecting, quoting, proposing and claiming, in one
// PostgreSQL transaction each.
func TestPostgresPreDispatchOverheadStaysUnderSeventyFiveMillisecondsAtTwentyRequestsASecond(t *testing.T) {
	e := newEnv(t, 1_000_000_000)
	e.anthropic.on(jsonHandler(`{"usage":{"input_tokens":10,"output_tokens":5}}`))
	const rate, total = 20, 200
	var (
		mu        sync.Mutex
		overheads []float64
		wg        sync.WaitGroup
		failures  []string
		arrival   []string
	)
	ticker := time.NewTicker(time.Second / rate)
	defer ticker.Stop()
	for i := 0; i < total; i++ {
		<-ticker.C
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each call is a different request: a fresh attempt every time.
			body := fmt.Sprintf(`{"model":"claude-sonnet-5-5","max_tokens":256,"messages":[{"role":"user","content":"request %d %s"}]}`, i, strings.Repeat("x", 2000))
			r := post(t, e.worker.URL, "/v1/messages", workerHeaders(tokenAgent), body)
			mu.Lock()
			defer mu.Unlock()
			if r.Status != 200 {
				failures = append(failures, r.String())
				return
			}
			var ms float64
			_, _ = fmt.Sscanf(r.Header.Get("Server-Timing"), "helm-predispatch;dur=%f", &ms)
			overheads = append(overheads, ms)
			arrival = append(arrival, fmt.Sprintf("%d:%.0f", i, ms))
		}()
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("%d of %d calls failed, e.g. %s", len(failures), total, failures[0])
	}
	sort.Float64s(overheads)
	p := func(q float64) float64 { return overheads[int(q*float64(len(overheads)-1))] }
	if os.Getenv("HELM_DEBUG_OVERHEAD") != "" {
		t.Logf("in arrival order: %v", arrival)
	}
	t.Logf("pre-dispatch overhead over %d calls at %d/s: p50 %.1f ms, p95 %.1f ms, p99 %.1f ms, max %.1f ms", len(overheads), rate, p(0.5), p(0.95), p(0.99), overheads[len(overheads)-1])
	if p(0.95) > 75 {
		t.Fatalf("p95 pre-dispatch overhead %.1f ms exceeds 75 ms", p(0.95))
	}
	e.ledgerBalances()
	if n := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE state = 'SETTLED'`); n != total {
		t.Fatalf("%d settled attempts, want %d", n, total)
	}
}
