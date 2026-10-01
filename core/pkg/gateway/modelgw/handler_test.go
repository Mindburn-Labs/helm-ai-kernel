package modelgw

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

func get(t *testing.T, url string, headers map[string]string) reply {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	must(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: []byte(b.String())}
}

// Everything a gateway refuses on its own is refused before the ledger: no
// attempt, no reservation, no provider call.
func TestRefusalsNeverReachTheLedger(t *testing.T) {
	ledger := &stubLedger{t: t, OnGrants: agentGrants()}
	// Grants are read only after a request is inspected: a refusal before that
	// must not read them either.
	ledger.OnGrants = nil
	url := stubbed(t, ledger, true)
	good := `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[]}`
	for name, test := range map[string]struct {
		method, path, body string
		headers            map[string]string
		status             int
		want               string
	}{
		"no token":                      {"POST", "/v1/messages", good, map[string]string{"Content-Type": "application/json"}, 401, `"authentication_error"`},
		"a token no listener knows":     {"POST", "/v1/chat/completions", `{"model":"gpt-6-sol"}`, map[string]string{"Authorization": "Bearer nope", "Content-Type": "application/json"}, 401, `"invalid_api_key"`},
		"a main token on this listener": {"POST", "/v1/messages", good, map[string]string{"Authorization": "Bearer " + tokenService, "Content-Type": "application/json"}, 401, `"authentication_error"`},
		"a token with no episode":       {"POST", "/v1/messages", good, map[string]string{"Authorization": "Bearer " + tokenNoEpisode, "Content-Type": "application/json"}, 403, `"permission_error"`},
		"a read-scoped token":           {"POST", "/v1/messages", good, map[string]string{"Authorization": "Bearer canary-read-worker", "Content-Type": "application/json"}, 403, `"permission_error"`},
		"the wrong content type":        {"POST", "/v1/messages", good, map[string]string{"Authorization": "Bearer " + tokenAgent, "Content-Type": "text/plain"}, 415, "must be application/json"},
		"no content type":               {"POST", "/v1/messages", good, map[string]string{"Authorization": "Bearer " + tokenAgent, "Content-Type": ""}, 415, "must be application/json"},
		"a body that is not JSON":       {"POST", "/v1/messages", `{`, map[string]string{"Authorization": "Bearer " + tokenAgent, "Content-Type": "application/json"}, 400, "not valid JSON"},
		"an unknown model":              {"POST", "/v1/messages", `{"model":"claude-9","messages":[]}`, map[string]string{"Authorization": "Bearer " + tokenAgent, "Content-Type": "application/json"}, 404, "not_found_error"},
		"a hosted tool":                 {"POST", "/v1/responses", `{"model":"gpt-6-sol","tools":[{"type":"web_search_preview"}]}`, map[string]string{"Authorization": "Bearer " + tokenAgent, "Content-Type": "application/json"}, 400, "unsupported_tool"},
		"a body past the limit":         {"POST", "/v1/messages", `{"model":"claude-sonnet-5-5","messages":"` + strings.Repeat("x", 2<<20) + `"}`, map[string]string{"Authorization": "Bearer " + tokenAgent, "Content-Type": "application/json"}, 413, "request_too_large"},
		"a GET on an inference path":    {"GET", "/v1/messages", ``, map[string]string{"Authorization": "Bearer " + tokenAgent}, 405, "use POST"},
		"count_tokens":                  {"POST", "/v1/messages/count_tokens", good, map[string]string{"Authorization": "Bearer " + tokenAgent, "Content-Type": "application/json"}, 404, `"not_found_error"`},
		"an endpoint the gateway lacks": {"POST", "/v1/embeddings", `{}`, map[string]string{"Authorization": "Bearer " + tokenAgent, "Content-Type": "application/json"}, 404, `"not_found"`},
	} {
		var r reply
		if test.method == "GET" {
			r = get(t, url+test.path, test.headers)
		} else {
			r = post(t, url, test.path, test.headers, test.body)
		}
		if r.Status != test.status || !strings.Contains(string(r.Body), test.want) {
			t.Errorf("%s: %s, want %d containing %s", name, r, test.status, test.want)
		}
	}
	if len(ledger.proposed) != 0 {
		t.Fatalf("a refused request proposed %d attempts", len(ledger.proposed))
	}
}

func TestErrorsAreInTheFormatOfTheAPIThatWasCalled(t *testing.T) {
	url := stubbed(t, &stubLedger{t: t}, true)
	a := post(t, url, "/v1/messages", map[string]string{"Content-Type": "application/json"}, `{}`)
	for _, want := range []string{`"type":"error"`, `"authentication_error"`, `"request_id":"req_helm_`} {
		if a.Status != 401 || !strings.Contains(string(a.Body), want) {
			t.Fatalf("an Anthropic error lacks %s: %s", want, a)
		}
	}
	o := post(t, url, "/v1/chat/completions", map[string]string{"Content-Type": "application/json"}, `{}`)
	if o.Status != 401 || !strings.HasPrefix(string(o.Body), `{"error":{`) || strings.Contains(string(o.Body), "request_id") {
		t.Fatalf("an OpenAI error: %s", o)
	}
	// Both are JSON, never cached.
	for _, r := range []reply{a, o} {
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("headers %v", r.Header)
		}
	}
}

func TestOnlyAnthropicClientsMaySendTheirKeyInXAPIKey(t *testing.T) {
	ledger := &stubLedger{t: t, OnGrants: func(admission.Caller) (admission.Grants, error) { return admission.Grants{}, errors.New("stop here") }}
	url := stubbed(t, ledger, true)
	body := `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[]}`
	// The Anthropic SDK given an API key sends x-api-key: it is the token.
	r := post(t, url, "/v1/messages", map[string]string{"X-Api-Key": tokenAgent, "Anthropic-Version": "2023-06-01"}, body)
	if r.Status != 503 { // past authentication, at the scripted ledger failure
		t.Fatalf("x-api-key on /v1/messages: %s", r)
	}
	// On an OpenAI endpoint an x-api-key is not a credential.
	r = post(t, url, "/v1/chat/completions", map[string]string{"X-Api-Key": tokenAgent}, `{"model":"gpt-6-sol","messages":[]}`)
	if r.Status != 401 {
		t.Fatalf("x-api-key on /v1/chat/completions: %s", r)
	}
	// When both are sent, the bearer wins and a bad x-api-key cannot override it.
	r = post(t, url, "/v1/messages", map[string]string{"Authorization": "Bearer nope", "X-Api-Key": tokenAgent}, body)
	if r.Status != 401 {
		t.Fatalf("a bad bearer beside a good x-api-key: %s", r)
	}
}

func TestWhoMayCallOnWhichListener(t *testing.T) {
	body := `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[]}`
	kind := func(k string) *stubLedger {
		return &stubLedger{t: t, OnGrants: func(admission.Caller) (admission.Grants, error) {
			return admission.Grants{PrincipalKind: k, PrincipalActive: true}, nil
		}}
	}
	// The worker listener serves agents only, and a human calls nowhere.
	for _, test := range []struct {
		worker bool
		kind   string
		token  string
		status int
	}{
		{true, "service", "canary-svc-worker", 403},
		{true, "human", "canary-human-worker", 403},
		{false, "human", tokenHuman, 403},
	} {
		url := stubbed(t, kind(test.kind), test.worker)
		r := post(t, url, "/v1/messages", map[string]string{"Authorization": "Bearer " + test.token}, body)
		if r.Status != test.status || r.Header.Get("X-Helm-Reason-Code") != string(contracts.ReasonInsufficientPrivilege) {
			t.Errorf("worker=%v kind=%s: %s %v", test.worker, test.kind, r, r.Header)
		}
	}
}

func TestWorkReferencesComeFromTheEpisodeOnTheWorkerListener(t *testing.T) {
	capture := func(worker bool, token string, headers map[string]string) (admission.ProposeInput, reply) {
		ledger := &stubLedger{t: t, OnGrants: agentGrants(),
			OnPropose: func(_ admission.Caller, in admission.ProposeInput) (admission.Attempt, bool, error) {
				return admission.Attempt{ID: "01a0f278-0000-7000-8000-0000000000aa", State: "DENIED", ReasonCode: string(contracts.ReasonBudgetExceeded)}, false, nil
			}}
		url := stubbed(t, ledger, worker)
		h := map[string]string{"Authorization": "Bearer " + token}
		for k, v := range headers {
			h[k] = v
		}
		r := post(t, url, "/v1/messages", h, `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[]}`)
		ledger.mu.Lock()
		defer ledger.mu.Unlock()
		if len(ledger.proposed) != 1 {
			t.Fatalf("%d proposals: %s", len(ledger.proposed), r)
		}
		return ledger.proposed[0], r
	}
	// A worker's work reference and scope are its episode's, whatever it sends.
	in, _ := capture(true, tokenAgent, map[string]string{"X-Helm-Case-Id": "somebody-elses-case", "X-Helm-Idempotency-Scope": "elsewhere"})
	if in.CaseID != "work-ep-1" || !strings.HasPrefix(in.IdempotencyKey, "mi:ep-1:") || in.EffectType != "model.inference" || in.Target != routeSonnet {
		t.Fatalf("worker proposal = %+v", in)
	}
	// The main listener lets the Control Plane name them.
	in, _ = capture(false, tokenService, map[string]string{"X-Helm-Case-Id": "compile:7", "X-Helm-Idempotency-Scope": "job-7"})
	if in.CaseID != "compile:7" || !strings.HasPrefix(in.IdempotencyKey, "mi:job-7:") {
		t.Fatalf("main proposal = %+v", in)
	}
	// Without them: the token's id scopes the call, and the case is generic.
	in, _ = capture(false, tokenService, nil)
	if in.CaseID != "model-call" || !strings.HasPrefix(in.IdempotencyKey, "mi:jti-svc:helm-org-compiler:") {
		t.Fatalf("main proposal without headers = %+v", in)
	}
	// A header that is not a plain reference is refused.
	ledger := &stubLedger{t: t}
	url := stubbed(t, ledger, false)
	r := post(t, url, "/v1/messages", map[string]string{"Authorization": "Bearer " + tokenService, "X-Helm-Case-Id": "a b"}, `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[]}`)
	if r.Status != 400 || !strings.Contains(string(r.Body), "X-Helm-Case-Id must be") {
		t.Fatalf("a bad case header: %s", r)
	}
	// A long scope is hashed so the stored key stays within its bound.
	if got := keyScope(strings.Repeat("s", 300)); len(got) > 100 || !strings.HasPrefix(got, "h") {
		t.Fatalf("keyScope = %q", got)
	}
	if keyScope("ep-1") != "ep-1" || keyScope("a b") == "a b" {
		t.Fatal("keyScope changes a plain scope, or lets a bad one through")
	}
}

// The quote carries an amount for every unit the chain sums, and the request
// selects the mandate that covers its route.
func TestTheQuotePricesTheWorstCaseAndZeroFillsOtherSummedUnits(t *testing.T) {
	ledger := &stubLedger{t: t,
		OnGrants: func(admission.Caller) (admission.Grants, error) {
			return admission.Grants{PrincipalKind: "agent", PrincipalActive: true, SumUnits: []string{"tokens", "usd_micros"},
				Leaves: []admission.LeafGrant{
					{MandateID: "m-haiku", Active: true, Targets: []string{routeHaiku}},
					{MandateID: "m-sonnet", Active: true, Targets: []string{routeSonnet}},
				}}, nil
		},
		OnPropose: func(admission.Caller, admission.ProposeInput) (admission.Attempt, bool, error) {
			return admission.Attempt{ID: "01a0f278-0000-7000-8000-0000000000aa", State: "DENIED", ReasonCode: string(contracts.ReasonBudgetExceeded)}, false, nil
		}}
	url := stubbed(t, ledger, true)
	body := `{"model":"claude-sonnet-5-5","max_tokens":1000,"messages":[]}`
	post(t, url, "/v1/messages", map[string]string{"Authorization": "Bearer " + tokenAgent}, body)
	in := ledger.proposed[0]
	sonnet := mustRoute(t, routeSonnet)
	want, err := sonnet.Quote(int64(len(body)), 1000, false)
	must(t, err)
	if in.MandateID != "m-sonnet" {
		t.Fatalf("mandate = %q, want the one that covers the route", in.MandateID)
	}
	if len(in.Quote) != 2 || in.Quote[0] != (admission.Amount{Unit: "usd_micros", Amount: want}) || in.Quote[1] != (admission.Amount{Unit: "tokens", Amount: 0}) {
		t.Fatalf("quote = %+v, want usd_micros %d and a zero for tokens", in.Quote, want)
	}
	if want != (int64(len(body))*3_000_000+1000*15_000_000+999_999)/1_000_000 {
		t.Fatalf("the quote %d is not the worst case", want)
	}
}

func TestModelsListsTheRoutesTheCallerMayUse(t *testing.T) {
	grants := func(admission.Caller) (admission.Grants, error) {
		return admission.Grants{PrincipalKind: "agent", PrincipalActive: true, Leaves: []admission.LeafGrant{
			{MandateID: "m1", Active: true, Targets: []string{routeSonnet, routeGPT}},
		}}, nil
	}
	url := stubbed(t, &stubLedger{t: t, OnGrants: grants}, true)
	r := get(t, url+"/v1/models", map[string]string{"Authorization": "Bearer " + tokenAgent})
	if r.Status != 200 || r.Header.Get("Content-Type") != "application/json" {
		t.Fatal(r)
	}
	body := string(r.Body)
	// Both the provider's model id and the route id name a route.
	for _, want := range []string{`"claude-sonnet-5-5"`, `"anthropic/claude-sonnet-5-5"`, `"gpt-6-sol"`, `"openai/gpt-6-sol"`, `"object":"list"`, `"type":"model"`, `"has_more":false`, `"owned_by":"helm"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the models document lacks %s: %s", want, body)
		}
	}
	for _, unwanted := range []string{"claude-opus-5-5", "claude-haiku-4-5-20251001", "deepseek"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("a route outside the mandate is listed (%s): %s", unwanted, body)
		}
	}
	// The Anthropic SDK sends x-api-key and anthropic-version: the same document,
	// and a read-scoped token works too.
	if r := get(t, url+"/v1/models", map[string]string{"X-Api-Key": tokenAgent, "Anthropic-Version": "2023-06-01"}); r.Status != 200 {
		t.Fatalf("x-api-key: %s", r)
	}
	if r := get(t, url+"/v1/models", map[string]string{"Authorization": "Bearer canary-read-worker"}); r.Status != 200 {
		t.Fatalf("read scope: %s", r)
	}
	if r := get(t, url+"/v1/models", nil); r.Status != 401 {
		t.Fatalf("no token: %s", r)
	}
	if r := post(t, url, "/v1/models", map[string]string{"Authorization": "Bearer " + tokenAgent}, `{}`); r.Status != 405 {
		t.Fatalf("POST /v1/models: %s", r)
	}
	// A principal with no active mandate lists nothing.
	empty := stubbed(t, &stubLedger{t: t, OnGrants: func(admission.Caller) (admission.Grants, error) {
		return admission.Grants{PrincipalKind: "agent", PrincipalActive: true}, nil
	}}, true)
	if r := get(t, empty+"/v1/models", map[string]string{"Authorization": "Bearer " + tokenAgent}); r.Status != 200 || !strings.Contains(string(r.Body), `"data":[]`) {
		t.Fatalf("an empty list: %s", r)
	}
}
