package sandboxproviders

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	// No sandbox that was never created through the gateway.
	ghost := effectFor(sandbox.EffectExec, "sandbox/claude-managed-agents/ghost-1", args, tenantA, attemptID(t))
	assert.Equal(t, adapters.DispatchNotSent, a.Dispatch(t.Context(), creds, ghost, digest(args)).Status)
}
