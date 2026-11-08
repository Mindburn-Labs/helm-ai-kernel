package sandboxproviders

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/sandbox"
)

// The cloud providers are proven here against fake provider servers: no
// provider account exists, so the wire shapes are those the provider adapters
// document, unproven against a live service.

type dialect struct {
	name       string
	base       string
	execSuffix string
	authHeader string
	authValue  func(key string) string
}

var dialects = []dialect{
	{"e2b", "/sandboxes", "/process", "X-E2b-Api-Key", func(k string) string { return k }},
	{"daytona", "/sandbox", "/process/execute", "Authorization", func(k string) string { return "Bearer " + k }},
	{"opensandbox", "/api/sandbox", "/exec", "Authorization", func(k string) string { return "Bearer " + k }},
}

type cloudBox struct {
	id, state, runtime string
	labels             map[string]string
}

type seenRequest struct{ method, uri, body string }

type fakeCloud struct {
	t       *testing.T
	d       dialect
	mu      sync.Mutex
	boxes   map[string]*cloudBox
	n       int
	seen    []seenRequest
	badAuth int
	// createFault, when set, applies to the next create.
	createFault string
	redirectTo  string
	// listBody, when set, replaces the list answer.
	listBody string
}

func newFakeCloud(t *testing.T, d dialect) (*fakeCloud, *httptest.Server) {
	f := &fakeCloud{t: t, d: d, boxes: map[string]*cloudBox{}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeCloud) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.boxes)
}

func (f *fakeCloud) requests(method string) (n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.seen {
		if r.method == method {
			n++
		}
	}
	return n
}

func (f *fakeCloud) obj(b *cloudBox) map[string]any {
	switch f.d.name {
	case "e2b":
		return map[string]any{"sandboxID": b.id, "templateID": b.runtime, "state": b.state, "metadata": b.labels}
	case "daytona":
		return map[string]any{"sandboxId": b.id, "state": strings.Replace(b.state, "running", "started", 1), "labels": b.labels, "language": b.runtime}
	}
	return map[string]any{"id": b.id, "status": b.state, "metadata": b.labels, "image": b.runtime}
}

func (f *fakeCloud) createdAnswer(b *cloudBox) map[string]any {
	switch f.d.name {
	case "e2b":
		return map[string]any{"sandboxID": b.id}
	case "daytona":
		return map[string]any{"sandboxId": b.id}
	}
	return map[string]any{"id": b.id, "status": "running"}
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if s, ok := v.(string); ok {
		_, _ = io.WriteString(w, s)
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, seenRequest{r.Method, r.URL.RequestURI(), string(body)})
	if r.Header.Get(f.d.authHeader) != f.d.authValue(testKey) {
		f.badAuth++
		reply(w, 401, `{}`)
		return
	}
	if strings.Contains(string(body), testKey) || strings.Contains(r.URL.RequestURI(), testKey) {
		f.t.Errorf("the provider key appeared in a request body or URL: %s %s", r.Method, r.URL.Path)
	}
	rest := strings.TrimPrefix(r.URL.Path, f.d.base)
	rest = strings.TrimPrefix(rest, "/")
	id, suffix, _ := strings.Cut(rest, "/")
	switch {
	case r.Method == http.MethodPost && rest == "":
		f.create(w, body)
	case r.Method == http.MethodGet && rest == "":
		f.list(w, r)
	case r.Method == http.MethodGet && suffix == "":
		if b, ok := f.boxes[id]; ok {
			reply(w, 200, f.obj(b))
			return
		}
		reply(w, 404, `{}`)
	case r.Method == http.MethodDelete && suffix == "":
		if b, ok := f.boxes[id]; ok {
			b.state = "terminated"
			reply(w, 200, `{}`)
			return
		}
		reply(w, 404, `{}`)
	case r.Method == http.MethodPost && "/"+suffix == f.d.execSuffix:
		f.exec(w, id, body)
	default:
		reply(w, 404, `{}`)
	}
}

func (f *fakeCloud) create(w http.ResponseWriter, body []byte) {
	var in struct {
		TemplateID string            `json:"templateID"`
		Language   string            `json:"language"`
		Image      string            `json:"image"`
		Metadata   map[string]string `json:"metadata"`
		Labels     map[string]string `json:"labels"`
	}
	_ = json.Unmarshal(body, &in)
	labels := in.Metadata
	if f.d.name == "daytona" {
		labels = in.Labels
	}
	runtime := in.TemplateID + in.Language + in.Image
	fault := f.createFault
	f.createFault = ""
	if fault == "refuse" {
		reply(w, 422, `{"error":"quota exceeded for `+testKey[:3]+`"}`)
		return
	}
	if fault == "redirect" {
		http.Redirect(w, &http.Request{}, f.redirectTo, http.StatusTemporaryRedirect)
		return
	}
	f.n++
	b := &cloudBox{id: fmt.Sprintf("fake-%s-%d", f.d.name, f.n), state: "running", runtime: runtime, labels: labels}
	f.boxes[b.id] = b
	switch fault {
	case "lost-answer":
		reply(w, 502, `bad gateway`)
	case "garbage":
		reply(w, 200, `<html>welcome</html>`)
	case "huge":
		reply(w, 200, `{"pad":"`+strings.Repeat("x", 5<<20)+`"}`)
	case "wrong-id":
		reply(w, 200, map[string]any{"sandboxID": "../x", "sandboxId": "../x", "id": "../x"})
	default:
		reply(w, 200, f.createdAnswer(b))
	}
}

func (f *fakeCloud) list(w http.ResponseWriter, r *http.Request) {
	want := map[string]string{}
	switch f.d.name {
	case "e2b":
		q, _ := url.ParseQuery(r.URL.Query().Get("metadata"))
		for k := range q {
			want[k] = q.Get(k)
		}
	case "daytona":
		_ = json.Unmarshal([]byte(r.URL.Query().Get("labels")), &want)
	default:
		for _, kv := range r.URL.Query()["label"] {
			k, v, _ := strings.Cut(kv, "=")
			want[k] = v
		}
	}
	// A sloppy server: it ignores the filter and lists everything. The
	// adapter must filter again.
	if f.listBody != "" {
		reply(w, 200, f.listBody)
		return
	}
	all := []any{}
	for _, b := range f.boxes {
		all = append(all, f.obj(b))
	}
	if f.d.name == "opensandbox" {
		reply(w, 200, map[string]any{"items": all})
		return
	}
	reply(w, 200, all)
}

func (f *fakeCloud) exec(w http.ResponseWriter, id string, body []byte) {
	b, ok := f.boxes[id]
	if !ok || b.state != "running" {
		reply(w, 404, `{}`)
		return
	}
	var argv []string
	switch f.d.name {
	case "opensandbox":
		var in struct {
			Command []string `json:"command"`
		}
		_ = json.Unmarshal(body, &in)
		argv = in.Command
	case "e2b":
		var in struct {
			Cmd string `json:"cmd"`
		}
		_ = json.Unmarshal(body, &in)
		argv = []string{"sh", "-c", in.Cmd}
	default:
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(body, &in)
		argv = []string{"sh", "-c", in.Command}
	}
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- test shell standing in for the sandbox
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			reply(w, 500, `{}`)
			return
		}
	}
	switch f.d.name {
	case "e2b":
		reply(w, 200, map[string]any{"stdout": stdout.String(), "stderr": stderr.String(), "exitCode": code, "durationMs": 1})
	case "daytona":
		reply(w, 200, map[string]any{"output": stdout.String(), "errors": stderr.String(), "exitCode": code, "durationMs": 1})
	default:
		reply(w, 200, map[string]any{"exit_code": code, "stdout": stdout.String(), "stderr": stderr.String(), "duration_ms": 1})
	}
}

// providerAdapter is a real adapter built by Build over the fake server.
func providerAdapter(t *testing.T, d dialect, srv *httptest.Server) *sandbox.Adapter {
	t.Helper()
	pc := sandbox.ProviderConfig{Provider: d.name, KeyFile: "/run/helm/key"}
	switch d.name {
	case "e2b":
		pc.APIURL, pc.TemplateID = srv.URL, "base"
	default:
		pc.BaseURL = srv.URL
	}
	cfg, err := sandbox.ParseConfig(mustJSON(t, sandbox.Config{Providers: []sandbox.ProviderConfig{pc}}))
	require.NoError(t, err)
	backends, err := Build(cfg, BuildOptions{HTTPClient: srv.Client(), AllowUnappliedPolicy: true})
	require.NoError(t, err)
	a, err := sandbox.New(backends)
	require.NoError(t, err)
	return a
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func eachProvider(t *testing.T, fn func(t *testing.T, d dialect, f *fakeCloud, a *sandbox.Adapter, srv *httptest.Server)) {
	for _, d := range dialects {
		t.Run(d.name, func(t *testing.T) {
			f, srv := newFakeCloud(t, d)
			fn(t, d, f, providerAdapter(t, d, srv), srv)
		})
	}
}

func TestCloudProvidersRunTheWholeLifecycleAgainstFakeServers(t *testing.T) {
	eachProvider(t, func(t *testing.T, d dialect, f *fakeCloud, a *sandbox.Adapter, _ *httptest.Server) {
		creds := &staticToken{token: testKey}
		target := "sandbox/" + d.name

		ce := effectFor(sandbox.EffectCreate, target, createArgsJSON, tenantA, attemptID(t))
		require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, ce, digest(createArgsJSON)).Status)
		co := a.Observe(t.Context(), creds, ce)
		require.Equal(t, adapters.OutcomeSucceeded, co.Outcome, co.Detail)
		id := artifactOf(t, co.Observation)["sandbox_id"].(string)
		assert.Equal(t, 1, f.count())

		// The command is an argument vector: its quoting survives each
		// provider's wire, including the two that take one command string.
		args := execArgsJSON(60, "", "sh", "-c", `printf '%s' "$0"`, `it's; "quoted" $HOME`)
		ee := effectFor(sandbox.EffectExec, target+"/"+id, args, tenantA, attemptID(t))
		require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, ee, digest(args)).Status)
		eo := a.Observe(t.Context(), creds, ee)
		require.Equal(t, adapters.OutcomeSucceeded, eo.Outcome, eo.Detail)
		assert.Equal(t, `it's; "quoted" $HOME`, artifactOf(t, eo.Observation)["stdout_excerpt"])
		assert.EqualValues(t, 0, artifactOf(t, eo.Observation)["exit_code"])

		// Another tenant cannot reach it, though it holds the same provider key.
		ee2 := effectFor(sandbox.EffectExec, target+"/"+id, args, tenantB, attemptID(t))
		d2 := a.Dispatch(t.Context(), creds, ee2, digest(args))
		assert.Equal(t, adapters.DispatchNotSent, d2.Status)
		te2 := effectFor(sandbox.EffectTerminate, target+"/"+id, terminateArgsJSON, tenantB, attemptID(t))
		assert.Equal(t, adapters.DispatchNotSent, a.Dispatch(t.Context(), creds, te2, digest(terminateArgsJSON)).Status)
		assert.Zero(t, f.requests(http.MethodDelete), "the other tenant's terminate never reached the provider")

		te := effectFor(sandbox.EffectTerminate, target+"/"+id, terminateArgsJSON, tenantA, attemptID(t))
		require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, te, digest(terminateArgsJSON)).Status)
		to := a.Observe(t.Context(), creds, te)
		require.Equal(t, adapters.OutcomeSucceeded, to.Outcome, to.Detail)

		assert.Zero(t, f.badAuth, "every call carried the key in the provider's auth header")
	})
}

func TestCloudCreateFaultsAreClassifiedAndReconciledByReadBack(t *testing.T) {
	type want struct {
		status   adapters.DispatchStatus
		reason   contracts.ReasonCode
		landed   bool
		outcome  adapters.Outcome
		absent   bool
		checkOut bool
	}
	for fault, w := range map[string]want{
		"refuse":      {adapters.DispatchNotSent, contracts.ReasonProviderError, false, adapters.OutcomeFailed, true, true},
		"lost-answer": {adapters.DispatchIndefinite, contracts.ReasonProviderError, true, adapters.OutcomeSucceeded, false, true},
		"garbage":     {adapters.DispatchIndefinite, contracts.ReasonConnectorContractDrift, true, adapters.OutcomeSucceeded, false, true},
		"wrong-id":    {adapters.DispatchIndefinite, contracts.ReasonConnectorContractDrift, true, adapters.OutcomeSucceeded, false, true},
		"huge":        {adapters.DispatchIndefinite, contracts.ReasonProviderResponseTooLarge, true, adapters.OutcomeSucceeded, false, true},
	} {
		t.Run(fault, func(t *testing.T) {
			eachProvider(t, func(t *testing.T, d dialect, f *fakeCloud, a *sandbox.Adapter, _ *httptest.Server) {
				creds := &staticToken{token: testKey}
				f.createFault = fault
				e := effectFor(sandbox.EffectCreate, "sandbox/"+d.name, createArgsJSON, tenantA, attemptID(t))
				got := a.Dispatch(t.Context(), creds, e, digest(createArgsJSON))
				assert.Equal(t, w.status, got.Status, got.Detail)
				assert.Equal(t, w.reason, got.Reason)
				assert.NotContains(t, got.Detail, testKey)
				assert.NotContains(t, got.Detail, "quota exceeded", "a provider's answer body never reaches a detail")
				assert.Equal(t, w.landed, f.count() == 1)
				o := a.Observe(t.Context(), creds, e)
				assert.Equal(t, w.outcome, o.Outcome, o.Detail)
				assert.Equal(t, w.absent, o.Absent)
			})
		})
	}
}

func TestACreateDoesNotFollowARedirectWithTheKey(t *testing.T) {
	eachProvider(t, func(t *testing.T, d dialect, f *fakeCloud, a *sandbox.Adapter, _ *httptest.Server) {
		var mu sync.Mutex
		var hits []string
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits = append(hits, r.Header.Get("Authorization")+r.Header.Get(d.authHeader))
			mu.Unlock()
		}))
		t.Cleanup(other.Close)
		f.createFault, f.redirectTo = "redirect", other.URL
		e := effectFor(sandbox.EffectCreate, "sandbox/"+d.name, createArgsJSON, tenantA, attemptID(t))
		got := a.Dispatch(t.Context(), &staticToken{token: testKey}, e, digest(createArgsJSON))
		assert.Equal(t, adapters.DispatchIndefinite, got.Status, "a redirect is not a definite refusal")
		mu.Lock()
		defer mu.Unlock()
		assert.Empty(t, hits, "the key was replayed to the redirect target")
	})
}

func TestCloudCreateWithoutAKeyOrWithAWrongKeySendsNothingUseful(t *testing.T) {
	eachProvider(t, func(t *testing.T, d dialect, f *fakeCloud, a *sandbox.Adapter, _ *httptest.Server) {
		e := effectFor(sandbox.EffectCreate, "sandbox/"+d.name, createArgsJSON, tenantA, attemptID(t))
		got := a.Dispatch(t.Context(), &staticToken{token: "sk-wrong"}, e, digest(createArgsJSON))
		assert.Equal(t, adapters.DispatchNotSent, got.Status, "a 401 to the first read is a definite refusal: nothing was written")
		assert.Zero(t, f.count())
		assert.NotContains(t, got.Detail, "sk-wrong")
	})
}

func TestAnUnconfiguredProviderIsNotReachedByItsTarget(t *testing.T) {
	// Only e2b is configured: the target alone picks the provider, and a
	// provider that is not listed is off.
	f, srv := newFakeCloud(t, dialects[0])
	a := providerAdapter(t, dialects[0], srv)
	creds := &staticToken{token: testKey}
	d := a.Dispatch(t.Context(), creds, effectFor(sandbox.EffectCreate, "sandbox/daytona", createArgsJSON, tenantA, attemptID(t)), digest(createArgsJSON))
	assert.Equal(t, adapters.DispatchNotSent, d.Status)
	assert.Equal(t, contracts.ReasonPreconditionFailed, d.Reason)
	assert.Zero(t, f.count())
	assert.Equal(t, []string{"e2b"}, a.Providers())
}

type workerRequest struct {
	auth string
	body struct {
		SandboxID string `json:"sandbox_id"`
		Tenant    string `json:"tenant"`
		Spec      *struct {
			EgressDisabled bool  `json:"egress_disabled"`
			CPUMillis      int64 `json:"cpu_millis"`
			MemoryMB       int64 `json:"memory_mb"`
		} `json:"spec"`
		WorkDir   string   `json:"workdir"`
		Command   []string `json:"command"`
		TimeoutMS int64    `json:"timeout_ms"`
	}
}

type fakeWorker struct {
	*httptest.Server
	mu         sync.Mutex
	reqs       []workerRequest
	bound      map[string]string // sandbox id -> tenant it was first seen with
	terminated []string
}

func (w *fakeWorker) requests() []workerRequest {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]workerRequest(nil), w.reqs...)
}

// newFakeWorker serves the HELM worker exec protocol v1 and runs each command
// in the local shell.
func newFakeWorker(t *testing.T) *fakeWorker {
	w := &fakeWorker{bound: map[string]string{}}
	w.Server = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if (r.URL.Path != "/v1/exec" && r.URL.Path != "/v1/terminate") || r.Method != http.MethodPost {
			reply(rw, 404, `{}`)
			return
		}
		var req workerRequest
		req.auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &req.body); err != nil || (r.URL.Path == "/v1/exec" && len(req.body.Command) == 0) {
			reply(rw, 400, `{}`)
			return
		}
		w.mu.Lock()
		w.reqs = append(w.reqs, req)
		// The worker binds a sandbox id to the tenant it first saw it with.
		bound, seen := w.bound[req.body.SandboxID]
		if !seen {
			w.bound[req.body.SandboxID] = req.body.Tenant
		}
		if r.URL.Path == "/v1/terminate" && (!seen || bound == req.body.Tenant) {
			w.terminated = append(w.terminated, req.body.SandboxID)
		}
		w.mu.Unlock()
		if seen && bound != req.body.Tenant {
			reply(rw, 403, `{}`)
			return
		}
		if r.URL.Path == "/v1/terminate" {
			reply(rw, 200, map[string]any{"terminated": true, "tenant": req.body.Tenant})
			return
		}
		cmd := exec.Command(req.body.Command[0], req.body.Command[1:]...) // #nosec G204 -- the test worker
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				reply(rw, 500, `{}`)
				return
			}
		}
		reply(rw, 200, map[string]any{"exit_code": code, "stdout": stdout.String(), "stderr": stderr.String(), "duration_ms": 1,
			"tenant": req.body.Tenant, "spec_applied": req.body.Spec != nil})
	}))
	t.Cleanup(w.Close)
	return w
}
