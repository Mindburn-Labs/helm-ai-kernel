package sandboxproviders

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"net/http/httptest"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/sandbox"
)

type signerStub struct{}

func (signerStub) Sign([]byte) (string, error) { return "sig", nil }
func (signerStub) SignerKeyID() string         { return "gateway-key-1" }

func TestBuildRefusesWhatCannotBeBuilt(t *testing.T) {
	cfg, err := sandbox.ParseConfig([]byte(`{"providers":[{"provider":"claude-managed-agents","key_file":"/k","managed_agents":{"worker_id":"w","remote_endpoint":"https://worker.example"}}]}`))
	require.NoError(t, err)
	_, err = Build(cfg, BuildOptions{})
	assert.ErrorContains(t, err, "signer", "a managed-agent receipt signer is required")

	for name, agents := range map[string]string{
		"unknown field":      `{"worker_id":"w","remote_endpoint":"https://w.example","unknown":1}`,
		"no endpoint":        `{"worker_id":"w"}`,
		"plain http":         `{"worker_id":"w","remote_endpoint":"http://worker.example"}`,
		"credentials in url": `{"worker_id":"w","remote_endpoint":"https://u:p@worker.example"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := sandbox.Config{Providers: []sandbox.ProviderConfig{{Provider: "claude-managed-agents", KeyFile: "/k", ManagedAgents: json.RawMessage(agents)}}}
			_, err := Build(c, BuildOptions{ManagedSigner: signerStub{}})
			assert.Error(t, err)
		})
	}
}

func TestDockerRuntimeMustBePinnedByDigest(t *testing.T) {
	cfg, err := sandbox.ParseConfig([]byte(`{"providers":[{"provider":"docker"}]}`))
	require.NoError(t, err)
	backends, err := Build(cfg, BuildOptions{})
	require.NoError(t, err)
	b := backends[0]
	assert.False(t, b.NeedsKey)
	assert.True(t, b.CompareRuntime)
	digest := "sha256:" + strings.Repeat("a", 64)
	require.NoError(t, b.ValidateRuntime("alpine@"+digest))
	require.NoError(t, b.ValidateRuntime("registry.example/team/img:1.2@"+digest))
	for _, bad := range []string{"alpine", "alpine:latest", "alpine@sha256:abc", "--privileged@" + digest, "alpine@" + digest + " --rm", ""} {
		assert.Error(t, b.ValidateRuntime(bad), bad)
	}
}

// dockerFixture finds an image the local daemon already has, pinned by
// digest, that carries sleep. The live tests never pull.
func dockerFixture(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("the docker daemon is not available: %s", strings.TrimSpace(string(out)))
	}
	for _, name := range []string{"busybox", "alpine"} {
		out, err := exec.Command("docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", name).Output()
		if err != nil {
			continue
		}
		if ref := strings.TrimSpace(string(out)); pinnedImage.MatchString(ref) {
			return ref
		}
	}
	t.Skip("no local busybox or alpine image with a repository digest; the test does not pull")
	return ""
}

func TestLiveDockerBackendRunsTheWholeLifecycle(t *testing.T) {
	image := dockerFixture(t)
	cfg, err := sandbox.ParseConfig([]byte(`{"providers":[{"provider":"docker"}]}`))
	require.NoError(t, err)
	backends, err := Build(cfg, BuildOptions{})
	require.NoError(t, err)
	a, err := sandbox.New(backends)
	require.NoError(t, err)

	creds := &staticToken{token: "must-not-be-read"}
	args := strings.Replace(createArgsJSON, `"runtime":"base"`, `"runtime":"`+image+`"`, 1)
	args = strings.Replace(args, `"timeout_seconds":600`, `"timeout_seconds":120`, 1)
	ce := effectFor(sandbox.EffectCreate, "sandbox/docker", args, tenantA, attemptID(t))
	t.Cleanup(func() {
		// Whatever the test did, remove the container it labelled.
		out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=helm.attempt="+ce.Invocation.AttemptID).Output()
		for _, id := range strings.Fields(string(out)) {
			_ = exec.Command("docker", "rm", "-f", id).Run()
		}
	})
	d := a.Dispatch(t.Context(), creds, ce, digest(args))
	require.Equal(t, adapters.DispatchSent, d.Status, d.Detail)
	co := a.Observe(t.Context(), creds, ce)
	require.Equal(t, adapters.OutcomeSucceeded, co.Outcome, co.Detail)
	id := artifactOf(t, co.Observation)["sandbox_id"].(string)
	assert.Zero(t, creds.calls, "a local provider is never given a credential")

	execArgs := execArgsJSON(60, "", "sh", "-c", `printf '%s' "$0"; echo oops >&2; exit 3`, `a b;c`)
	ee := effectFor(sandbox.EffectExec, "sandbox/docker/"+id, execArgs, tenantA, attemptID(t))
	require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, ee, digest(execArgs)).Status)
	eo := a.Observe(t.Context(), creds, ee)
	require.Equal(t, adapters.OutcomeSucceeded, eo.Outcome, eo.Detail)
	art := artifactOf(t, eo.Observation)
	assert.EqualValues(t, 3, art["exit_code"])
	assert.Equal(t, "a b;c", art["stdout_excerpt"])
	assert.Equal(t, "oops\n", art["stderr_excerpt"])

	// Another tenant cannot reach the container.
	other := effectFor(sandbox.EffectExec, "sandbox/docker/"+id, execArgs, tenantB, attemptID(t))
	assert.Equal(t, adapters.DispatchNotSent, a.Dispatch(t.Context(), creds, other, digest(execArgs)).Status)

	te := effectFor(sandbox.EffectTerminate, "sandbox/docker/"+id, terminateArgsJSON, tenantA, attemptID(t))
	require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, te, digest(terminateArgsJSON)).Status)
	to := a.Observe(t.Context(), creds, te)
	require.Equal(t, adapters.OutcomeSucceeded, to.Outcome, to.Detail)
}

// The fake worker (providers_test.go) stands in for the customer-hosted
// worker: it runs the commands it is sent in the local shell.
func TestClaudeManagedExecutesOnlyOnTheRemoteWorker(t *testing.T) {
	w := newFakeWorker(t)
	root := t.TempDir()
	agents := map[string]any{
		"worker_id": "worker-1", "worker_image_digest": "sha256:" + strings.Repeat("1", 64), "skill_manifest_hash": "sha256:" + strings.Repeat("2", 64),
		"workspace_root": filepath.Join(root, "ws"), "outputs_root": filepath.Join(root, "out"), "remote_endpoint": w.URL,
		"environment_key_configured": true, "environment_key_from_secret_store": true, "egress_enforced": true, "log_retention_enabled": true,
		"tls_required": true, "skills_pinned": true,
	}
	cfg := sandbox.Config{Providers: []sandbox.ProviderConfig{{Provider: "claude-managed-agents", KeyFile: "/run/helm/cma", ManagedAgents: mustJSON(t, agents)}}}
	backends, err := Build(cfg, BuildOptions{HTTPClient: w.Client(), ManagedSigner: signerStub{}})
	require.NoError(t, err)
	a, err := sandbox.New(backends)
	require.NoError(t, err)
	creds := &staticToken{token: testKey}
	hostRoot := root

	ce := effectFor(sandbox.EffectCreate, "sandbox/claude-managed-agents", createArgsJSON, tenantA, attemptID(t))
	require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, ce, digest(createArgsJSON)).Status)
	co := a.Observe(t.Context(), creds, ce)
	require.Equal(t, adapters.OutcomeSucceeded, co.Outcome, co.Detail)
	id := artifactOf(t, co.Observation)["sandbox_id"].(string)

	args := execArgsJSON(60, "", "sh", "-c", `printf '%s' "$0"`, `hello worker`)
	ee := effectFor(sandbox.EffectExec, "sandbox/claude-managed-agents/"+id, args, tenantA, attemptID(t))
	require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, ee, digest(args)).Status)
	eo := a.Observe(t.Context(), creds, ee)
	require.Equal(t, adapters.OutcomeSucceeded, eo.Outcome, eo.Detail)
	assert.Equal(t, "hello worker", artifactOf(t, eo.Observation)["stdout_excerpt"])

	// Every command went to the worker, authenticated with the custody's
	// token, in the sandbox's workspace on the worker, never a host path here.
	reqs := w.requests()
	require.NotEmpty(t, reqs)
	for _, r := range reqs {
		assert.Equal(t, "Bearer "+testKey, r.auth)
		assert.Equal(t, id, r.body.SandboxID)
		assert.NotContains(t, r.body.WorkDir, hostRoot, "the gateway host's directories never reach the worker")
		assert.NotContains(t, strings.Join(r.body.Command, " "), testKey)
	}
	// Another tenant cannot use it.
	other := effectFor(sandbox.EffectExec, "sandbox/claude-managed-agents/"+id, args, tenantB, attemptID(t))
	n := len(w.requests())
	assert.Equal(t, adapters.DispatchNotSent, a.Dispatch(t.Context(), creds, other, digest(args)).Status)
	assert.Equal(t, n, len(w.requests()))

	// The worker was told the tenant and the spec, and the id is random.
	assert.Regexp(t, `^claude-managed-[0-9a-f]{32}$`, id)
	for _, r := range reqs {
		assert.NotEmpty(t, r.body.Tenant)
		require.NotNil(t, r.body.Spec)
		assert.True(t, r.body.Spec.EgressDisabled)
		assert.EqualValues(t, 256, r.body.Spec.MemoryMB)
	}
	assert.Equal(t, "gateway_record", observationTrust(t, co), "the create read-back is the gateway's own record")

	// Terminate reaches the worker, which refuses the other tenant.
	otherTerm := effectFor(sandbox.EffectTerminate, "sandbox/claude-managed-agents/"+id, terminateArgsJSON, tenantB, attemptID(t))
	assert.Equal(t, adapters.DispatchNotSent, a.Dispatch(t.Context(), creds, otherTerm, digest(terminateArgsJSON)).Status)
	assert.Empty(t, w.terminated)
	te := effectFor(sandbox.EffectTerminate, "sandbox/claude-managed-agents/"+id, terminateArgsJSON, tenantA, attemptID(t))
	require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, te, digest(terminateArgsJSON)).Status)
	assert.Equal(t, []string{id}, w.terminated, "the worker was asked to end the sandbox")
	to := a.Observe(t.Context(), creds, te)
	require.Equal(t, adapters.OutcomeSucceeded, to.Outcome, to.Detail)
	assert.Equal(t, "gateway_record", observationTrust(t, to))

	// No sandbox that was never created through the gateway.
	ghost := effectFor(sandbox.EffectExec, "sandbox/claude-managed-agents/ghost-1", args, tenantA, attemptID(t))
	assert.Equal(t, adapters.DispatchNotSent, a.Dispatch(t.Context(), creds, ghost, digest(args)).Status)
}

func TestBuildRefusesPlainHTTPAndInsecureTLSAtStart(t *testing.T) {
	agents := `{"worker_id":"w","remote_endpoint":"http://127.0.0.1:9"}`
	for name, pc := range map[string]sandbox.ProviderConfig{
		"e2b":                  {Provider: "e2b", KeyFile: "/k", APIURL: "http://api.example"},
		"e2b loopback":         {Provider: "e2b", KeyFile: "/k", APIURL: "http://127.0.0.1:9"},
		"daytona":              {Provider: "daytona", KeyFile: "/k", BaseURL: "http://d.example"},
		"opensandbox":          {Provider: "opensandbox", KeyFile: "/k", BaseURL: "http://o.example"},
		"claude loopback":      {Provider: "claude-managed-agents", KeyFile: "/k", ManagedAgents: json.RawMessage(agents)},
		"credentials in url":   {Provider: "daytona", KeyFile: "/k", BaseURL: "https://u:p@d.example"},
		"opensandbox no tls":   {Provider: "opensandbox", KeyFile: "/k", BaseURL: "https://o.example", TLSRequired: boolPtr(false)},
		"daytona schemeless":   {Provider: "daytona", KeyFile: "/k", BaseURL: "d.example"},
		"daytona with a query": {Provider: "daytona", KeyFile: "/k", BaseURL: "https://d.example/?k=v"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Build(sandbox.Config{Providers: []sandbox.ProviderConfig{pc}}, BuildOptions{ManagedSigner: signerStub{}})
			assert.Error(t, err)
		})
	}
	// tls_required: false is also refused when the file is parsed.
	_, err := sandbox.ParseConfig([]byte(`{"providers":[{"provider":"opensandbox","key_file":"/k","base_url":"https://o.example","tls_required":false}]}`))
	assert.ErrorContains(t, err, "tls_required")
	// And https is accepted.
	_, err = Build(sandbox.Config{Providers: []sandbox.ProviderConfig{{Provider: "opensandbox", KeyFile: "/k", BaseURL: "https://o.example", TLSRequired: boolPtr(true)}}}, BuildOptions{})
	assert.NoError(t, err)
}

func boolPtr(b bool) *bool { return &b }

// A provider whose create call does not carry the limits and the egress
// policy is refused at admission and at dispatch, before any request: the
// sandbox would run without the limits its permit named.
func TestE2BAndDaytonaRefuseACreateWhoseLimitsTheyDoNotApply(t *testing.T) {
	for _, d := range dialects[:2] {
		t.Run(d.name, func(t *testing.T) {
			f, srv := newFakeCloud(t, d)
			pc := sandbox.ProviderConfig{Provider: d.name, KeyFile: "/run/helm/key"}
			if d.name == "e2b" {
				pc.APIURL, pc.TemplateID = srv.URL, "base"
			} else {
				pc.BaseURL = srv.URL
			}
			backends, err := Build(sandbox.Config{Providers: []sandbox.ProviderConfig{pc}}, BuildOptions{HTTPClient: srv.Client()})
			require.NoError(t, err)
			a, err := sandbox.New(backends)
			require.NoError(t, err)
			creds := &staticToken{token: testKey}
			e := effectFor(sandbox.EffectCreate, "sandbox/"+d.name, createArgsJSON, tenantA, attemptID(t))
			_, err = a.Prepare(t.Context(), creds, e)
			require.Error(t, err)
			got := a.Dispatch(t.Context(), creds, e, digest(createArgsJSON))
			assert.Equal(t, adapters.DispatchNotSent, got.Status, got.Detail)
			assert.Equal(t, contracts.ReasonPreconditionFailed, got.Reason)
			assert.Zero(t, f.count())
			f.mu.Lock()
			assert.Empty(t, f.seen, "no request, so the key was not sent")
			f.mu.Unlock()
		})
	}
}

// A list answer of the wrong shape is drift, never an empty list: Observe
// must not fail an effect whose sandbox exists.
func TestAListAnswerOfTheWrongShapeLeavesTheCreateUnknown(t *testing.T) {
	eachProvider(t, func(t *testing.T, d dialect, f *fakeCloud, a *sandbox.Adapter, _ *httptest.Server) {
		creds := &staticToken{token: testKey}
		e := effectFor(sandbox.EffectCreate, "sandbox/"+d.name, createArgsJSON, tenantA, attemptID(t))
		require.Equal(t, adapters.DispatchSent, a.Dispatch(t.Context(), creds, e, digest(createArgsJSON)).Status)
		require.Equal(t, 1, f.count())
		f.listBody = "null"
		if d.name == "opensandbox" {
			f.listBody = "{}"
		}
		o := a.Observe(t.Context(), creds, e)
		assert.Equal(t, adapters.OutcomeUnknown, o.Outcome, o.Detail)
		assert.Equal(t, contracts.ReasonConnectorContractDrift, o.Reason)
		assert.False(t, o.Absent)
	})
}

func TestDockerRefusesANetworkedSandboxAtAdmission(t *testing.T) {
	cfg, err := sandbox.ParseConfig([]byte(`{"providers":[{"provider":"docker"}]}`))
	require.NoError(t, err)
	backends, err := Build(cfg, BuildOptions{})
	require.NoError(t, err)
	a, err := sandbox.New(backends)
	require.NoError(t, err)
	args := `{"schema":"helm.sandbox.create.v1","runtime":"alpine@sha256:` + strings.Repeat("a", 64) + `","cpu_millis":500,"memory_mb":256,"disk_mb":0,"timeout_seconds":600,"max_processes":64,"egress_disabled":false}`
	e := effectFor(sandbox.EffectCreate, "sandbox/docker", args, tenantA, attemptID(t))
	_, err = a.Prepare(t.Context(), &staticToken{}, e)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network")
	got := a.Dispatch(t.Context(), &staticToken{}, e, digest(args))
	assert.Equal(t, adapters.DispatchNotSent, got.Status)
}

func observationTrust(t *testing.T, o adapters.ObserveResult) string {
	t.Helper()
	require.NotNil(t, o.Observation)
	return o.Observation.TrustClass
}
