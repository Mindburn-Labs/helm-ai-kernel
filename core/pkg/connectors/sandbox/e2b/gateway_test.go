package e2b

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	createLabelField = "metadata"
	authHeader       = "X-E2b-Api-Key"
	runningState     = "running"
)

const execAnswer = `{"stdout":"","stderr":"","exitCode":0,"durationMs":1}`

func gwAdapter(url string) *Adapter {
	return New(Config{APIURL: url, APIKey: testKey, TemplateID: "base", DefaultTimeout: time.Minute, AllowInsecureLoopback: true})
}

func createAnswer(id string) string { return fmt.Sprintf(`{"sandboxID":%q}`, id) }

func sandboxJSON(id, state string, labels map[string]string) string {
	b, _ := json.Marshal(map[string]any{"sandboxID": id, "templateID": "base", "state": state, "metadata": labels})
	return string(b)
}

func listJSON(items []string) string { return "[" + strings.Join(items, ",") + "]" }

func assertExecCommand(t *testing.T, body string, argv []string) {
	t.Helper()
	var req e2bExecReq
	require.NoError(t, json.Unmarshal([]byte(body), &req))
	assert.Equal(t, connsandbox.ShellJoin(argv), req.Cmd)
}

const testKey = "sk-very-secret-key"

type recorded struct {
	Method, URL, Body string
	Header            http.Header
}

type recorder struct {
	mu   sync.Mutex
	reqs []recorded
}

func (r *recorder) add(req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, recorded{Method: req.Method, URL: req.URL.String(), Body: string(b), Header: req.Header.Clone()})
}

func (r *recorder) all() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.reqs...)
}

// fake serves respond's answer for every request and records them.
func fake(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		rec.add(r)
		respond(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func reply(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestGatewayCreateSendsLabelsAndKeepsTheKeyInTheHeader(t *testing.T) {
	srv, rec := fake(t, reply(200, createAnswer("sbx-1")))
	a := gwAdapter(srv.URL)
	labels := map[string]string{connsandbox.LabelTenant: "tenanthash", connsandbox.LabelAttempt: "attempt-1"}
	h, err := a.Create(t.Context(), &actuators.SandboxSpec{Runtime: "default", Labels: labels,
		Resources: actuators.ResourceSpec{Timeout: time.Minute}})
	require.NoError(t, err)
	assert.Equal(t, "sbx-1", h.ID)
	reqs := rec.all()
	require.Len(t, reqs, 1)
	var sent map[string]any
	require.NoError(t, json.Unmarshal([]byte(reqs[0].Body), &sent))
	got, _ := sent[createLabelField].(map[string]any)
	assert.Equal(t, "tenanthash", got[connsandbox.LabelTenant])
	assert.Equal(t, "attempt-1", got[connsandbox.LabelAttempt])
	assert.NotContains(t, reqs[0].Body, testKey)
	assert.NotContains(t, reqs[0].URL, testKey)
	assert.Contains(t, reqs[0].Header.Get(authHeader), testKey)
}

func TestGatewayCreateAnswerOfTheWrongShapeIsDrift(t *testing.T) {
	for name, body := range map[string]string{
		"no id":      `{}`,
		"path id":    createAnswer("../x"),
		"not json":   `<html>`,
		"empty body": ``,
	} {
		srv, _ := fake(t, reply(200, body))
		_, err := gwAdapter(srv.URL).Create(t.Context(), &actuators.SandboxSpec{Runtime: "default"})
		ce := connsandbox.AsCallError(err)
		require.NotNil(t, ce, name)
		assert.True(t, ce.Drift, name)
		assert.False(t, ce.Refused, name)
	}
}

func TestGatewayLookup(t *testing.T) {
	lbl := map[string]string{connsandbox.LabelTenant: "th"}
	srv, rec := fake(t, reply(200, sandboxJSON("sbx-1", runningState, lbl)))
	info, err := gwAdapter(srv.URL).Lookup(t.Context(), "sbx-1")
	require.NoError(t, err)
	assert.Equal(t, "sbx-1", info.ID)
	assert.Equal(t, actuators.StatusRunning, info.Status)
	assert.Equal(t, "th", info.Labels[connsandbox.LabelTenant])
	assert.True(t, strings.HasSuffix(rec.all()[0].URL, "/sbx-1"))

	srv, _ = fake(t, reply(404, `{"error":"gone"}`))
	_, err = gwAdapter(srv.URL).Lookup(t.Context(), "sbx-1")
	assert.ErrorIs(t, err, actuators.ErrSandboxNotFound)

	srv, _ = fake(t, reply(200, sandboxJSON("sbx-1", "wat", lbl)))
	_, err = gwAdapter(srv.URL).Lookup(t.Context(), "sbx-1")
	require.NotNil(t, connsandbox.AsCallError(err))
	assert.True(t, connsandbox.AsCallError(err).Drift)

	srv, _ = fake(t, reply(200, sandboxJSON("sbx-other", runningState, lbl)))
	_, err = gwAdapter(srv.URL).Lookup(t.Context(), "sbx-1")
	require.NotNil(t, connsandbox.AsCallError(err), "an answer for another sandbox is drift")
}

func TestGatewayFindFiltersOnTheClientAndNeverTruncates(t *testing.T) {
	want := map[string]string{connsandbox.LabelTenant: "th", connsandbox.LabelAttempt: "a1"}
	// The server ignores the filter and returns foreign sandboxes too.
	items := []string{
		sandboxJSON("sbx-1", runningState, want),
		sandboxJSON("sbx-2", runningState, map[string]string{connsandbox.LabelTenant: "other", connsandbox.LabelAttempt: "a1"}),
		sandboxJSON("sbx-3", runningState, nil),
		sandboxJSON("sbx-4", runningState, map[string]string{connsandbox.LabelTenant: "th"}),
	}
	srv, rec := fake(t, reply(200, listJSON(items)))
	found, err := gwAdapter(srv.URL).Find(t.Context(), want)
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.Equal(t, "sbx-1", found[0].ID)
	assert.Contains(t, rec.all()[0].URL, "helm.attempt")
	assert.NotContains(t, rec.all()[0].URL, testKey)

	var many []string
	for i := 0; i <= connsandbox.MaxFound; i++ {
		many = append(many, sandboxJSON(fmt.Sprintf("sbx-%d", i), runningState, want))
	}
	srv, _ = fake(t, reply(200, listJSON(many)))
	_, err = gwAdapter(srv.URL).Find(t.Context(), want)
	assert.Error(t, err, "more matches than MaxFound is an error, not a truncated list")

	_, err = gwAdapter(srv.URL).Find(t.Context(), nil)
	assert.Error(t, err, "an empty filter would list every sandbox")

	srv, _ = fake(t, reply(200, listJSON([]string{sandboxJSON("sbx-1", "wat", want)})))
	_, err = gwAdapter(srv.URL).Find(t.Context(), want)
	require.NotNil(t, connsandbox.AsCallError(err))
	assert.True(t, connsandbox.AsCallError(err).Drift)
}

func TestGatewayFailuresAreClassified(t *testing.T) {
	a := func(url string) error { return gwAdapter(url).Terminate(t.Context(), "sbx-1") }

	srv, _ := fake(t, reply(409, `{"detail":"secret `+testKey+`"}`))
	err := a(srv.URL)
	ce := connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	assert.True(t, ce.Refused, "a 4xx is a definite refusal")
	assert.NotContains(t, err.Error(), testKey, "an answer body never reaches an error")

	srv, _ = fake(t, reply(503, `down`))
	ce = connsandbox.AsCallError(a(srv.URL))
	require.NotNil(t, ce)
	assert.False(t, ce.Refused, "a 5xx is not definite")
	assert.Equal(t, 503, ce.Status)

	srv, _ = fake(t, func(w http.ResponseWriter, _ *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	})
	ce = connsandbox.AsCallError(a(srv.URL))
	require.NotNil(t, ce)
	assert.False(t, ce.Refused, "a dropped connection is not definite")
	assert.Zero(t, ce.Status)

	srv, _ = fake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat(" ", int(connsandbox.DefaultLimit)+10)))
	})
	_, err = gwAdapter(srv.URL).Lookup(t.Context(), "sbx-1")
	ce = connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	assert.True(t, ce.TooLarge)

	srv, _ = fake(t, reply(200, `not json`))
	_, err = gwAdapter(srv.URL).Lookup(t.Context(), "sbx-1")
	ce = connsandbox.AsCallError(err)
	require.NotNil(t, ce)
	assert.True(t, ce.Drift)
}

func TestGatewayNeverFollowsARedirect(t *testing.T) {
	elsewhere, seen := fake(t, reply(200, `{}`))
	srv, _ := fake(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/steal", http.StatusTemporaryRedirect)
	})
	err := gwAdapter(srv.URL).Terminate(t.Context(), "sbx-1")
	require.Error(t, err)
	assert.Empty(t, seen.all(), "the credential must not reach a redirect target")
}

func TestGatewayRefusesAPathyIDBeforeAnyRequest(t *testing.T) {
	srv, rec := fake(t, reply(200, `{}`))
	a := gwAdapter(srv.URL)
	for _, id := range []string{"../x", "a/b", "", "-rf", "a b", "a?b"} {
		assert.ErrorIs(t, a.Terminate(t.Context(), id), connsandbox.ErrBadID, id)
		_, err := a.Lookup(t.Context(), id)
		assert.ErrorIs(t, err, connsandbox.ErrBadID, id)
		_, err = a.Exec(t.Context(), id, &actuators.ExecRequest{Command: []string{"true"}})
		assert.ErrorIs(t, err, connsandbox.ErrBadID, id)
		_, err = a.ReadFile(t.Context(), id, "/x")
		assert.ErrorIs(t, err, connsandbox.ErrBadID, id)
		assert.ErrorIs(t, a.WriteFile(t.Context(), id, "/x", nil), connsandbox.ErrBadID, id)
	}
	assert.Empty(t, rec.all())
}

func TestGatewayFilePathsAreEscaped(t *testing.T) {
	srv, rec := fake(t, reply(200, `data`))
	_, err := gwAdapter(srv.URL).ReadFile(t.Context(), "sbx-1", "/a b&x=1/../c")
	require.NoError(t, err)
	u := rec.all()[0].URL
	assert.Contains(t, u, "%26x%3D1")
	assert.NotContains(t, u, "&x=1")
}

func TestGatewayExecKeepsTheArgumentVectorIntact(t *testing.T) {
	srv, rec := fake(t, reply(200, execAnswer))
	argv := []string{"sh", "-c", "echo 'a b'; rm -rf /", `x"y`, "$(id)"}
	_, err := gwAdapter(srv.URL).Exec(t.Context(), "sbx-1", &actuators.ExecRequest{Command: argv, Timeout: time.Second})
	require.NoError(t, err)
	assertExecCommand(t, rec.all()[0].Body, argv)
	assert.NotContains(t, rec.all()[0].Body, testKey)
}
