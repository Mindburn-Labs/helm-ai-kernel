package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	lpruntime "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/runtime"
)

func TestCoverageStatesAndStoreBranches(t *testing.T) {
	for _, state := range []State{StatePlanned, StateValidated, StateEscalated, StateDenied, StateProvisioning, StateInstalling, StateStarting, StateHealthchecking, StateRunning, StateRepairRequired, StateTearingDown, StateDeleted, StateFailed} {
		if !ValidState(state) {
			t.Fatalf("state should be valid: %s", state)
		}
	}
	for _, state := range []State{StateRepairing, State("UNKNOWN")} {
		if ValidState(state) {
			t.Fatalf("state should be invalid: %s", state)
		}
	}

	t.Setenv("HELM_LAUNCHPAD_HOME", "/tmp/helm-launchpad-test")
	if DefaultRoot() != "/tmp/helm-launchpad-test" {
		t.Fatalf("DefaultRoot override mismatch: %s", DefaultRoot())
	}
	t.Setenv("HELM_LAUNCHPAD_HOME", "")
	if got := DefaultRoot(); !strings.Contains(filepath.ToSlash(got), ".helm/launchpad") {
		t.Fatalf("DefaultRoot home fallback mismatch: %s", got)
	}
	defaultStore := NewStore("")
	if defaultStore.Root() == "" {
		t.Fatal("default store root missing")
	}

	store := NewStore(t.TempDir())
	if _, err := store.Get(""); err == nil {
		t.Fatal("expected empty launch id get error")
	}
	if _, err := store.Get("missing"); err == nil {
		t.Fatal("expected missing launch get error")
	}
	if err := store.Save(LaunchRun{LaunchID: "bad", State: State("BAD")}); err == nil {
		t.Fatal("expected unknown state save error")
	}
	if err := store.Save(LaunchRun{LaunchID: "ok", State: StateValidated}); err != nil {
		t.Fatalf("validated save failed: %v", err)
	}
	loaded, err := store.Get("ok")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LaunchID != "ok" || loaded.IdempotencyKeys == nil || loaded.CreatedAt.IsZero() || loaded.UpdatedAt.IsZero() {
		t.Fatalf("saved run missing defaults: %#v", loaded)
	}
	logPath, err := store.AppendLog("ok", "hello")
	if err != nil {
		t.Fatal(err)
	}
	logData, err := store.ReadLog("ok")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "hello") || logPath == "" {
		t.Fatalf("log mismatch: path=%s data=%s", logPath, logData)
	}
	if _, err := store.AppendLog("", "bad"); err == nil {
		t.Fatal("expected empty append log id error")
	}
	if _, err := NewStore(t.TempDir()).List(); err != nil {
		t.Fatalf("missing runs dir should list empty: %v", err)
	}

	listStore := NewStore(t.TempDir())
	if err := os.MkdirAll(listStore.runsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	writeRunJSON(t, listStore.runPath("older"), LaunchRun{LaunchID: "older", State: StateValidated, UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	writeRunJSON(t, listStore.runPath("newer"), LaunchRun{LaunchID: "newer", State: StateValidated, UpdatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)})
	if err := os.WriteFile(filepath.Join(listStore.runsDir(), "ignored.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(listStore.runsDir(), "dir.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	runs, err := listStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].LaunchID != "newer" || runs[1].LaunchID != "older" {
		t.Fatalf("runs not sorted newest first: %#v", runs)
	}
	if err := os.WriteFile(listStore.runPath("bad"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listStore.List(); err == nil {
		t.Fatal("expected list invalid JSON error")
	}
	if _, err := listStore.Get("bad"); err == nil {
		t.Fatal("expected get invalid JSON error")
	}

	blockedRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(blockedRoot, "runs"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(blockedRoot).Save(LaunchRun{LaunchID: "blocked", State: StateValidated}); err == nil {
		t.Fatal("expected save mkdir error")
	}
	if _, err := NewStore(blockedRoot).List(); err == nil {
		t.Fatal("expected list readdir error")
	}
	if err := os.WriteFile(filepath.Join(blockedRoot, "logs"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(blockedRoot).AppendLog("blocked", "line"); err == nil {
		t.Fatal("expected append log mkdir error")
	}
	logCollisionRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(logCollisionRoot, "logs", "blocked.log"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(logCollisionRoot).AppendLog("blocked", "line"); err == nil {
		t.Fatal("expected append log open-file error for directory collision")
	}
	if err := store.Save(LaunchRun{
		LaunchID:      "running-missing-refs",
		State:         StateRunning,
		KernelVerdict: "ALLOW",
	}); err == nil {
		t.Fatal("expected running without launch/health/sandbox refs to fail after ALLOW verdict")
	}
	if err := store.Save(LaunchRun{
		LaunchID:      "deleted-missing-teardown",
		State:         StateDeleted,
		KernelVerdict: "ALLOW",
	}); err == nil {
		t.Fatal("expected deleted without teardown refs to fail after ALLOW verdict")
	}
	for _, state := range []State{StateProvisioning, StateInstalling, StateStarting, StateHealthchecking, StateRunning, StateTearingDown, StateDeleted} {
		if !isSideEffectState(state) {
			t.Fatalf("side-effect state not detected: %s", state)
		}
	}
	if isSideEffectState(StateValidated) {
		t.Fatal("validated should not be side-effect state")
	}
}

func TestCoverageExecutorAdditionalBranches(t *testing.T) {
	if NewExecutor(nil).Store == nil {
		t.Fatal("NewExecutor nil store should allocate a default store")
	}
	if _, err := NewExecutor(NewStore(t.TempDir())).ExecuteLaunch(plan.LaunchPlan{}, ExecuteOptions{}); err == nil {
		t.Fatal("expected missing launch id error")
	}
	run, err := NewExecutor(NewStore(t.TempDir())).ExecuteLaunch(allowPlan(), ExecuteOptions{RuntimeStarter: emptyRuntimeStarter{}})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != StateRepairRequired || !strings.Contains(run.Reason, "required refs") {
		t.Fatalf("expected repair for empty runtime result: %#v", run)
	}

	detached := allowPlan()
	detached.RuntimeDetached = true
	health := &fakeHealthcheck{}
	run, err = NewExecutor(NewStore(t.TempDir())).ExecuteLaunch(detached, ExecuteOptions{RuntimeStarter: &fakeStarter{}, HealthcheckRunner: health})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != StateRunning || health.called {
		t.Fatalf("detached launch should skip external health runner and reach running: state=%s health=%v", run.State, health.called)
	}

	starter := &fakeStarter{}
	fieldHealth := &fakeHealthcheck{}
	executor := Executor{Store: NewStore(t.TempDir()), RuntimeStarter: starter, HealthcheckRunner: fieldHealth}
	secretPlan := allowPlan()
	secretPlan.RequiredSecretRefs = []string{"secret:openrouter"}
	secretPlan.ModelGatewayEnv = []string{"OPENROUTER_API_KEY"}
	secretPlan.ModelGatewayMode = "direct_env"
	run, err = executor.ExecuteLaunch(secretPlan, ExecuteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !starter.called || !fieldHealth.called || len(run.SecretGrantRefs) == 0 || len(run.ModelGatewayGrantRefs) == 0 {
		t.Fatalf("executor field runners or secret/model refs missing: %#v", run)
	}

	for _, item := range []struct {
		name string
		run  LaunchRun
		want string
	}{
		{"e2b_missing_key", LaunchRun{LaunchID: "lp-e2b", SubstrateID: "e2b", RuntimeHandles: RuntimeHandles{ContainerID: "sandbox-live", CloudResourceIDs: map[string]string{"provider": "e2b"}}}, "dry-run-or-key-missing"},
		{"daytona_missing_key", LaunchRun{LaunchID: "lp-daytona", SubstrateID: "daytona", RuntimeHandles: RuntimeHandles{ContainerID: "sandbox-live", CloudResourceIDs: map[string]string{"provider": "daytona"}}}, "dry-run-or-key-missing"},
		{"do_missing_token", LaunchRun{LaunchID: "lp-do", PlanHash: "sha256:plan", SubstrateID: "digitalocean", RuntimeHandles: RuntimeHandles{CloudResourceIDs: map[string]string{"provider": "digitalocean", "droplet": "123"}}}, "DIGITALOCEAN_TOKEN missing"},
		{"hetzner_missing_token", LaunchRun{LaunchID: "lp-hz", PlanHash: "sha256:plan", SubstrateID: "hetzner", RuntimeHandles: RuntimeHandles{CloudResourceIDs: map[string]string{"provider": "hetzner", "server": "123"}}}, "HCLOUD_TOKEN missing"},
		{"already_reconciled", LaunchRun{LaunchID: "lp-reconciled", SubstrateID: "hetzner", RuntimeHandles: RuntimeHandles{CloudResourceIDs: map[string]string{"provider": "hetzner", "teardown_reconciled": "true"}}}, "already-reconciled"},
	} {
		t.Run(item.name, func(t *testing.T) {
			t.Setenv("E2B_API_KEY", "")
			t.Setenv("HELM_LAUNCHPAD_E2B_API_KEY", "")
			t.Setenv("DAYTONA_API_KEY", "")
			t.Setenv("HELM_LAUNCHPAD_DAYTONA_API_KEY", "")
			t.Setenv("DIGITALOCEAN_TOKEN", "")
			t.Setenv("HELM_LAUNCHPAD_DIGITALOCEAN_TOKEN", "")
			t.Setenv("HCLOUD_TOKEN", "")
			t.Setenv("HELM_LAUNCHPAD_HETZNER_TOKEN", "")
			result := teardownRuntimeHandles(item.run)
			joined := marshalString(t, result)
			if !strings.Contains(joined, item.want) {
				t.Fatalf("teardown result missing %q: %s", item.want, joined)
			}
		})
	}
}

func TestCoverageHealthcheckRunnerBranches(t *testing.T) {
	runner := DefaultHealthcheckRunner{}
	p := allowPlan()
	if _, err := runner.Run(p, RuntimeStartResult{}, ExecuteOptions{}); err == nil {
		t.Fatal("expected missing runtime refs error")
	}
	cloudNoCheck := p
	cloudNoCheck.Healthchecks = nil
	if _, err := runner.Run(cloudNoCheck, RuntimeStartResult{ContainerID: "cloud-1", SandboxGrantRef: "grant", Runtime: "e2b"}, ExecuteOptions{}); err == nil {
		t.Fatal("expected cloud runtime without healthcheck spec to fail")
	}
	if _, err := runner.Run(p, RuntimeStartResult{ContainerID: "cloud-1", SandboxGrantRef: "grant", Runtime: "e2b"}, ExecuteOptions{}); err == nil {
		t.Fatal("expected cloud command healthcheck without remote command runner to fail")
	}
	cloudDryRun, err := runner.Run(p, RuntimeStartResult{ContainerID: "cloud-1", SandboxGrantRef: "grant", Runtime: "e2b"}, ExecuteOptions{RuntimeDryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if cloudDryRun.Type != "command" || cloudDryRun.Status != "dry-run-passed" {
		t.Fatalf("cloud dry-run healthcheck mismatch: %#v", cloudDryRun)
	}
	noCheck := p
	noCheck.Healthchecks = nil
	if _, err := runner.Run(noCheck, RuntimeStartResult{ContainerID: "c", SandboxGrantRef: "grant", Runtime: "local-container"}, ExecuteOptions{}); err == nil {
		t.Fatal("expected missing healthcheck spec error")
	}
	unsupported := p
	unsupported.Healthchecks = []registry.HealthcheckSpec{{Type: "tcp", URL: "127.0.0.1:80"}}
	if _, err := runner.Run(unsupported, RuntimeStartResult{ContainerID: "c", SandboxGrantRef: "grant", Runtime: "local-container"}, ExecuteOptions{}); err == nil {
		t.Fatal("expected unsupported healthcheck type error")
	}
	httpProbe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer httpProbe.Close()
	httpPlan := p
	httpPlan.Healthchecks = []registry.HealthcheckSpec{{Type: "http", URL: httpProbe.URL}}
	httpResult, err := runner.Run(httpPlan, RuntimeStartResult{ContainerID: "cloud-1", SandboxGrantRef: "grant", Runtime: "e2b"}, ExecuteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if httpResult.Type != "http" || httpResult.Status != "passed" || httpResult.Metadata["status_code"] != http.StatusNoContent {
		t.Fatalf("http healthcheck mismatch: %#v", httpResult)
	}
	failingHTTPProbe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "starting", http.StatusServiceUnavailable)
	}))
	defer failingHTTPProbe.Close()
	failingHTTPPlan := p
	failingHTTPPlan.Healthchecks = []registry.HealthcheckSpec{{Type: "http", URL: failingHTTPProbe.URL}}
	if _, err := runner.Run(failingHTTPPlan, RuntimeStartResult{ContainerID: "cloud-1", SandboxGrantRef: "grant", Runtime: "e2b"}, ExecuteOptions{}); err == nil {
		t.Fatal("expected failing http healthcheck to block RUNNING")
	}
	dryRun, err := runner.Run(p, RuntimeStartResult{ContainerID: "c", SandboxGrantRef: "grant", Runtime: "local-container"}, ExecuteOptions{RuntimeDryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dryRun.Status != "dry-run-passed" || dryRun.Metadata["command"] == "" {
		t.Fatalf("dry-run healthcheck mismatch: %#v", dryRun)
	}
	missingImage := p
	missingImage.ArtifactImage = ""
	if _, err := runner.Run(missingImage, RuntimeStartResult{ContainerID: "c", SandboxGrantRef: "grant", Runtime: "local-container"}, ExecuteOptions{}); err == nil {
		t.Fatal("expected missing artifact image error")
	}
	networked := p
	networked.NetworkAllowlist = []string{"openrouter.ai:443"}
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL", "")
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE", "")
	if _, err := runner.Run(networked, RuntimeStartResult{ContainerID: "c", SandboxGrantRef: "grant", Runtime: "local-container"}, ExecuteOptions{}); err == nil {
		t.Fatal("expected egress proxy error")
	}
	if !containsImageDigest("repo/app@sha256:abc") || containsImageDigest("repo/app:latest") {
		t.Fatal("containsImageDigest mismatch")
	}
}

func TestCoverageRuntimeStarterBranches(t *testing.T) {
	starter := DefaultRuntimeStarter{}
	for _, substrate := range []string{"digitalocean", "hetzner", "e2b", "daytona"} {
		p := allowPlan()
		p.SubstrateID = substrate
		if _, err := starter.Start(p, ExecuteOptions{}); err == nil {
			t.Fatalf("expected missing credential error for %s", substrate)
		}
	}
	for _, substrate := range []string{"digitalocean", "hetzner", "e2b", "daytona"} {
		t.Run(substrate+"_dry_run", func(t *testing.T) {
			p := allowPlan()
			p.SubstrateID = substrate
			t.Setenv("DIGITALOCEAN_TOKEN", "token")
			t.Setenv("HCLOUD_TOKEN", "token")
			result, err := starter.Start(p, ExecuteOptions{RuntimeDryRun: true})
			if err != nil {
				t.Fatal(err)
			}
			if result.ContainerID == "" || result.SandboxGrantRef == "" || result.CloudResourceIDs["provider"] != substrate {
				t.Fatalf("dry-run result mismatch: %#v", result)
			}
		})
	}
	unsupported := allowPlan()
	unsupported.SubstrateID = "unsupported"
	if _, err := starter.Start(unsupported, ExecuteOptions{RuntimeDryRun: true}); err == nil {
		t.Fatal("expected unsupported substrate error")
	}
	missingImage := allowPlan()
	missingImage.ArtifactImage = ""
	if _, err := starter.Start(missingImage, ExecuteOptions{RuntimeDryRun: true}); err == nil {
		t.Fatal("expected missing artifact image error")
	}
	missingDigest := allowPlan()
	missingDigest.ArtifactDigest = ""
	if _, err := starter.Start(missingDigest, ExecuteOptions{RuntimeDryRun: true}); err == nil {
		t.Fatal("expected missing artifact digest error")
	}
	local := allowPlan()
	local.ArtifactImage = "registry.example/openclaw:latest"
	local.ArtifactDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	t.Setenv("HELM_LAUNCHPAD_ISOLATION_MODE", "")
	result, err := starter.Start(local, ExecuteOptions{RuntimeDryRun: true, WorkspaceMount: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if result.ContainerID == "" || result.SandboxGrantRef == "" || result.Runtime != "local-container" {
		t.Fatalf("local dry-run mismatch: %#v", result)
	}

	isolation := lpruntime.IsolationEvidence{
		Mode:               "gvisor",
		Hardened:           true,
		DetectionStatus:    "detected",
		RuntimeClass:       "runsc",
		DockerRootless:     true,
		DockerUserns:       true,
		DockerECI:          true,
		DedicatedVM:        true,
		DockerRuntimes:     []string{"runsc"},
		DefaultRuntime:     "runc",
		HostileAgentGrade:  true,
		PayloadInspection:  "opaque_connect",
		NetworkProof:       "destination_allowlist_only",
		TokenBrokerEnabled: true,
	}
	converted := runtimeStartResultFromIsolation(isolation)
	if converted.IsolationMode != "gvisor" || !converted.TokenBrokerEnabled || len(converted.DockerRuntimes) != 1 {
		t.Fatalf("isolation conversion mismatch: %#v", converted)
	}
	handleResult := runtimeStartResultFromHandle(lpruntime.ContainerHandle{
		ContainerID:       "container",
		SandboxGrantRef:   "grant",
		EgressReceiptRef:  "egress",
		EgressNetworkName: "net",
		EgressProxyID:     "proxy-id",
		EgressProxyName:   "proxy",
		Isolation:         isolation,
	})
	if handleResult.ContainerID != "container" || handleResult.EgressProxyName != "proxy" {
		t.Fatalf("handle conversion mismatch: %#v", handleResult)
	}

	t.Setenv("HELM_MODEL_GATEWAY_TOKEN", "env-token")
	t.Setenv("HELM_MODEL_GATEWAY_URL", "https://gateway.env")
	secrets := runtimeSecrets(plan.LaunchPlan{ModelGatewayMode: "token_broker"}, ExecuteOptions{})
	if secrets["HELM_MODEL_GATEWAY_TOKEN"] != "env-token" || secrets["HELM_MODEL_GATEWAY_URL"] != "https://gateway.env" {
		t.Fatalf("token broker env secrets mismatch: %#v", secrets)
	}
	t.Setenv("OPENROUTER_API_KEY", "env-openrouter")
	secrets = runtimeSecrets(plan.LaunchPlan{ModelGatewayEnv: []string{"OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"}}, ExecuteOptions{RuntimeSecretEnv: map[string]string{"ANTHROPIC_API_KEY": "opt-anthropic"}})
	if secrets["OPENROUTER_API_KEY"] != "env-openrouter" || secrets["ANTHROPIC_API_KEY"] != "opt-anthropic" {
		t.Fatalf("direct env secrets mismatch: %#v", secrets)
	}
	t.Setenv("HELM_LAUNCHPAD_ISOLATION_MODE", "gvisor")
	if isolationModeFromEnv() != "gvisor" {
		t.Fatal("isolationModeFromEnv mismatch")
	}
	t.Setenv("FIRST_ENV_A", " ")
	t.Setenv("FIRST_ENV_B", " value ")
	if firstEnv("FIRST_ENV_A", "FIRST_ENV_B") != "value" || firstEnv("FIRST_ENV_A") != "" {
		t.Fatal("firstEnv mismatch")
	}
	t.Setenv("FIRST_ENV_VALUE", " override ")
	if firstEnvValue("FIRST_ENV_VALUE", "fallback") != "override" || firstEnvValue("MISSING_FIRST_ENV_VALUE", "fallback") != "fallback" {
		t.Fatal("firstEnvValue mismatch")
	}
	long := allowPlan()
	long.LaunchID = "launch_with_underscores_and_a_very_long_identifier_for_cloud"
	if name := cloudResourceName(long); !strings.HasPrefix(name, "helm-launchpad-launch-with-underscores") || len(strings.TrimPrefix(name, "helm-launchpad-")) > 36 {
		t.Fatalf("cloud resource name mismatch: %s", name)
	}
	tags := cloudTags(allowPlan(), "approval/id")
	labels := cloudLabels(allowPlan(), "approval:id", 12.5)
	if len(tags) != 3 || !strings.Contains(tags[2], "approval-id") || len(labels) != 4 || !strings.Contains(labels[3], "12-50") {
		t.Fatalf("cloud tags/labels mismatch: %#v %#v", tags, labels)
	}
	if sanitizeCloudTag("") != "unset" || len(sanitizeCloudTag(strings.Repeat("x", 80))) != 48 || sanitizeCloudTag("A B/C:D@E.F") != "a-b-c-d-e-f" {
		t.Fatal("sanitizeCloudTag mismatch")
	}
}

func TestCoverageDockerTeardownAndRemainingHelpers(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	dockerPath := filepath.Join(binDir, "docker")
	script := `#!/bin/sh
echo "$@" >> "$DOCKER_LOG"
if [ "$1" = "ps" ]; then
  echo "orphan-a orphan-b"
  exit 0
fi
if [ "$1" = "rm" ]; then
  echo "$@"
  exit 0
fi
if [ "$1" = "network" ]; then
  echo "$@"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(dockerPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "state", "lp-docker")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_LOG", logPath)
	t.Setenv("HELM_LAUNCHPAD_HOME", stateRoot)
	result := teardownRuntimeHandles(LaunchRun{
		LaunchID: "lp-docker",
		RuntimeHandles: RuntimeHandles{
			ContainerID:       "container-1",
			EgressProxyName:   "proxy-1",
			EgressNetworkName: "net-1",
			CloudResourceIDs:  map[string]string{},
		},
	})
	joined := marshalString(t, result)
	for _, want := range []string{"\"docker_available\":true", "container-1", "orphan-a", "state_dir_cleanup", "proxy-1", "net-1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("docker teardown result missing %q: %s", want, joined)
		}
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("state dir should be removed, err=%v", err)
	}

	for _, item := range []struct {
		status string
		state  State
	}{
		{"DENIED", StateDenied},
		{"PLANNED", StatePlanned},
		{"VALIDATED", StateValidated},
	} {
		p := allowPlan()
		p.Status = item.status
		run := newLaunchRun(p, "reason")
		if run.State != item.state || run.Reason != "reason" || run.TeardownCommand == "" {
			t.Fatalf("newLaunchRun mismatch for %s: %#v", item.status, run)
		}
	}
	if err := validateTerminalState(LaunchRun{LaunchID: "deleted", State: StateDeleted, KernelVerdict: "ALLOW", TeardownReceiptRefs: []string{"teardown"}}); err != nil {
		t.Fatalf("deleted with teardown should validate: %v", err)
	}

	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL", "")
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE", "")
	t.Setenv("HELM_LAUNCHPAD_EGRESS_RECEIPT_DIR", t.TempDir())
	proxy, err := egressProxyFromEnv("remote-vm", []string{"openrouter.ai:443"})
	if err != nil || proxy == nil {
		t.Fatalf("expected launch-owned egress proxy for non-namespace substrate: %T %v", proxy, err)
	}
	t.Setenv("HELM_LAUNCHPAD_HOME", "")
	if root := launchpadStateRoot(); !strings.Contains(filepath.ToSlash(root), ".helm/launchpad") {
		t.Fatalf("launchpadStateRoot home fallback mismatch: %s", root)
	}
	blockerRoot := t.TempDir()
	blocker := filepath.Join(blockerRoot, "state")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_LAUNCHPAD_HOME", blockerRoot)
	_, err = materializeFilesystemMounts(plan.LaunchPlan{LaunchID: "lp", AppID: "app", FilesystemMounts: []string{"data:rw:/var/lib/app/data"}}, ExecuteOptions{})
	if err == nil {
		t.Fatal("expected materialize filesystem mkdir error")
	}
	mounts, err := materializeFilesystemMounts(plan.LaunchPlan{LaunchID: "lp-dry", AppID: "app", FilesystemMounts: []string{"workspace:rw:/workspace", "cache:ro:/var/cache/app"}}, ExecuteOptions{RuntimeDryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0].Source != "" || !mounts[0].ReadOnly {
		t.Fatalf("dry-run filesystem mount mismatch: %#v", mounts)
	}
	if _, err := parseFilesystemMount(":rw:/var/lib/app/data", "app"); err == nil {
		t.Fatal("expected empty filesystem mount name error")
	}

	starter := DefaultRuntimeStarter{}
	local := allowPlan()
	local.ArtifactImage = "registry.example/openclaw:latest"
	local.ArtifactDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	t.Setenv("HELM_LAUNCHPAD_ISOLATION_MODE", "")
	resultStart, err := starter.Start(local, ExecuteOptions{RuntimeDryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if resultStart.ContainerID == "" || resultStart.SandboxGrantRef == "" {
		t.Fatalf("local dry-run without workspace mount mismatch: %#v", resultStart)
	}
	t.Setenv("HELM_LAUNCHPAD_ISOLATION_MODE", "not-a-real-mode")
	_, err = starter.Start(local, ExecuteOptions{RuntimeDryRun: true, WorkspaceMount: t.TempDir()})
	if err == nil {
		t.Fatal("expected invalid isolation mode error")
	}
}

func TestCoverageTeardownFailureBranches(t *testing.T) {
	t.Run("docker_missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		result := teardownRuntimeHandles(LaunchRun{
			LaunchID: "lp-no-docker",
			RuntimeHandles: RuntimeHandles{
				ContainerID:      "container-1",
				CloudResourceIDs: map[string]string{},
			},
		})
		if result["docker_available"] != false {
			t.Fatalf("expected docker unavailable result: %#v", result)
		}
	})

	t.Run("docker_cleanup_failures_are_reported", func(t *testing.T) {
		binDir := t.TempDir()
		dockerPath := filepath.Join(binDir, "docker")
		script := `#!/bin/sh
if [ "$1" = "ps" ]; then
  echo "orphan-a"
  exit 0
fi
if [ "$1" = "rm" ]; then
  echo "rm failed: $*"
  exit 1
fi
if [ "$1" = "network" ]; then
  echo "network failed: $*"
  exit 1
fi
exit 0
`
		if err := os.WriteFile(dockerPath, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", binDir)
		t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
		result := teardownRuntimeHandles(LaunchRun{
			LaunchID: "lp-docker-fail",
			RuntimeHandles: RuntimeHandles{
				ContainerID:       "container-1",
				EgressProxyName:   "proxy-1",
				EgressNetworkName: "net-1",
				CloudResourceIDs:  map[string]string{},
			},
		})
		joined := marshalString(t, result)
		for _, want := range []string{"container_cleanup", "orphan_container_cleanup", "egress_proxy_cleanup", "egress_network_cleanup", "rm failed", "network failed"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("docker failure result missing %q: %s", want, joined)
			}
		}
	})

	for _, tc := range []struct {
		name       string
		provider   string
		keyEnv     string
		urlEnv     string
		path       string
		status     int
		wantDelete bool
	}{
		{"e2b_success", "e2b", "E2B_API_KEY", "HELM_LAUNCHPAD_E2B_API_URL", "/sandboxes/sandbox-1", http.StatusNoContent, true},
		{"e2b_error", "e2b", "E2B_API_KEY", "HELM_LAUNCHPAD_E2B_API_URL", "/sandboxes/sandbox-1", http.StatusInternalServerError, false},
		{"daytona_success", "daytona", "DAYTONA_API_KEY", "HELM_LAUNCHPAD_DAYTONA_BASE_URL", "/sandbox/sandbox-1", http.StatusNoContent, true},
		{"daytona_error", "daytona", "DAYTONA_API_KEY", "HELM_LAUNCHPAD_DAYTONA_BASE_URL", "/sandbox/sandbox-1", http.StatusInternalServerError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != tc.path {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				if tc.status >= 400 {
					_, _ = w.Write([]byte("cleanup failed"))
				}
			}))
			t.Cleanup(server.Close)
			t.Setenv(tc.keyEnv, "test-key")
			t.Setenv(tc.urlEnv, server.URL)
			result := teardownRuntimeHandles(LaunchRun{
				LaunchID: "lp-" + tc.name,
				RuntimeHandles: RuntimeHandles{
					ContainerID:      "sandbox-1",
					CloudResourceIDs: map[string]string{"provider": tc.provider},
				},
			})
			if tc.wantDelete {
				if result["cloud_cleanup"] != "deleted" || result["receipt_id"] == "" {
					t.Fatalf("expected cloud delete success: %#v", result)
				}
			} else if result["cloud_cleanup_error"] == "" {
				t.Fatalf("expected cloud delete error: %#v", result)
			}
		})
	}

	for _, tc := range []struct {
		name       string
		provider   string
		tokenEnv   string
		altEnv     string
		urlEnv     string
		resourceID map[string]string
		status     int
		wantDelete bool
	}{
		{"digitalocean_success", "digitalocean", "DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT", map[string]string{"droplet": "123", "firewall": "fw-1"}, http.StatusNoContent, true},
		{"digitalocean_error", "digitalocean", "DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT", map[string]string{"droplet": "123", "firewall": "fw-1"}, http.StatusInternalServerError, false},
		{"hetzner_success", "hetzner", "HCLOUD_TOKEN", "HELM_LAUNCHPAD_HETZNER_TOKEN", "HELM_LAUNCHPAD_HETZNER_ENDPOINT", map[string]string{"server": "456", "firewall": "789"}, http.StatusNoContent, true},
		{"hetzner_error", "hetzner", "HCLOUD_TOKEN", "HELM_LAUNCHPAD_HETZNER_TOKEN", "HELM_LAUNCHPAD_HETZNER_ENDPOINT", map[string]string{"server": "456", "firewall": "789"}, http.StatusInternalServerError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)
			t.Setenv(tc.tokenEnv, "test-token")
			t.Setenv(tc.altEnv, "")
			t.Setenv(tc.urlEnv, server.URL)
			refs := map[string]string{"provider": tc.provider}
			for key, value := range tc.resourceID {
				refs[key] = value
			}
			result := teardownRuntimeHandles(LaunchRun{
				LaunchID: "lp-" + tc.name,
				PlanHash: "sha256:plan",
				RuntimeHandles: RuntimeHandles{
					CloudResourceIDs: refs,
				},
			})
			if tc.wantDelete {
				if result["cloud_cleanup"] != "deleted" || result["receipt_id"] == "" {
					t.Fatalf("expected provider delete success: %#v", result)
				}
			} else if result["cloud_cleanup_error"] == "" {
				t.Fatalf("expected provider delete error: %#v", result)
			}
		})
	}
}

func TestCoverageRuntimeStarterHostedSandboxLiveBranches(t *testing.T) {
	starter := DefaultRuntimeStarter{}
	for _, tc := range []struct {
		name        string
		substrate   string
		keyEnv      string
		urlEnv      string
		path        string
		successBody string
		status      int
		wantID      string
	}{
		{"e2b_success", "e2b", "E2B_API_KEY", "HELM_LAUNCHPAD_E2B_API_URL", "/sandboxes", `{"sandboxID":"e2b-live","clientID":"client-1"}`, http.StatusOK, "e2b-live"},
		{"e2b_error", "e2b", "E2B_API_KEY", "HELM_LAUNCHPAD_E2B_API_URL", "/sandboxes", `{"error":"failed"}`, http.StatusInternalServerError, ""},
		{"daytona_success", "daytona", "DAYTONA_API_KEY", "HELM_LAUNCHPAD_DAYTONA_BASE_URL", "/sandbox", `{"sandboxId":"daytona-live"}`, http.StatusOK, "daytona-live"},
		{"daytona_error", "daytona", "DAYTONA_API_KEY", "HELM_LAUNCHPAD_DAYTONA_BASE_URL", "/sandbox", `{"error":"failed"}`, http.StatusInternalServerError, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != tc.path {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.successBody))
			}))
			t.Cleanup(server.Close)
			t.Setenv(tc.keyEnv, "test-key")
			t.Setenv(tc.urlEnv, server.URL)
			t.Setenv("HELM_LAUNCHPAD_ALLOW_INSECURE_LOOPBACK_API", "true")
			p := allowPlan()
			p.SubstrateID = tc.substrate
			p.ArtifactImage = "custom-template"
			result, err := starter.Start(p, ExecuteOptions{})
			if tc.wantID == "" {
				if err == nil {
					t.Fatalf("expected hosted sandbox start error, got %#v", result)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.ContainerID != tc.wantID || result.CloudResourceIDs["sandbox_id"] != tc.wantID || result.CloudResourceIDs["provider"] != tc.substrate {
				t.Fatalf("hosted sandbox start mismatch: %#v", result)
			}
		})
	}
}

func TestCoverageRuntimeStarterCloudProviderLiveBranches(t *testing.T) {
	starter := DefaultRuntimeStarter{}
	for _, tc := range []struct {
		name      string
		substrate string
		tokenEnv  string
		urlEnv    string
		status    int
		wantID    string
	}{
		{"digitalocean_success", "digitalocean", "DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT", http.StatusCreated, "321"},
		{"digitalocean_error", "digitalocean", "DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT", http.StatusInternalServerError, ""},
		{"hetzner_success", "hetzner", "HCLOUD_TOKEN", "HELM_LAUNCHPAD_HETZNER_ENDPOINT", http.StatusCreated, "987"},
		{"hetzner_error", "hetzner", "HCLOUD_TOKEN", "HELM_LAUNCHPAD_HETZNER_ENDPOINT", http.StatusInternalServerError, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if tc.status >= 400 {
					_, _ = w.Write([]byte(`{"error":"failed"}`))
					return
				}
				switch r.URL.Path {
				case "/v2/droplets":
					_, _ = w.Write([]byte(`{"droplet":{"id":321}}`))
				case "/v2/firewalls":
					_, _ = w.Write([]byte(`{"firewall":{"id":"fw-live"}}`))
				case "/firewalls":
					_, _ = w.Write([]byte(`{"firewall":{"id":654}}`))
				case "/servers":
					_, _ = w.Write([]byte(`{"server":{"id":987}}`))
				default:
					t.Errorf("unexpected provider path: %s", r.URL.Path)
				}
			}))
			t.Cleanup(server.Close)
			t.Setenv(tc.tokenEnv, "test-token")
			t.Setenv(tc.urlEnv, server.URL)
			p := allowPlan()
			p.SubstrateID = tc.substrate
			result, err := starter.Start(p, ExecuteOptions{})
			if tc.wantID == "" {
				if err == nil {
					t.Fatalf("expected cloud provider start error, got %#v", result)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.ContainerID != tc.wantID || result.CloudResourceIDs["provider"] != tc.substrate {
				t.Fatalf("cloud provider start mismatch: %#v", result)
			}
		})
	}
}

func TestCoverageExecutorPersistenceEdges(t *testing.T) {
	blockedRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(blockedRoot, "runs"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewExecutor(NewStore(blockedRoot)).ExecuteLaunch(allowPlan(), ExecuteOptions{}); err == nil {
		t.Fatal("expected execute launch to fail when initial state save is blocked")
	}

	defaultStarterPlan := allowPlan()
	defaultStarterPlan.LaunchID = "default-starter"
	defaultStarterPlan.CPIOutput = &plan.CPIOutput{ResultHash: "sha256:cpi"}
	defaultStarterPlan.ArtifactImage = "registry.example/openclaw:latest"
	defaultStarterPlan.ArtifactDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	run, err := Executor{Store: NewStore(t.TempDir())}.ExecuteLaunch(defaultStarterPlan, ExecuteOptions{RuntimeDryRun: true, WorkspaceMount: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != StateRunning || len(run.CPIRefs) != 1 {
		t.Fatalf("default starter run mismatch: %#v", run)
	}

	rootFile := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(rootFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Executor{Store: NewStore(rootFile)}).persist(LaunchRun{LaunchID: "pack-fail", State: StateValidated, KernelVerdict: "ALLOW"}, map[string][]byte{}); err == nil {
		t.Fatal("expected evidence pack write failure")
	}

	archiveFallbackRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(archiveFallbackRoot, "evidencepacks", "archive-fallback.tar"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (Executor{Store: NewStore(archiveFallbackRoot)}).persist(LaunchRun{LaunchID: "archive-fallback", State: StateValidated, KernelVerdict: "ALLOW"}, map[string][]byte{"runtime_environment.json": []byte("{}")}); err == nil {
		t.Fatal("expected archive creation failure to abort persistence")
	}

	saveFailRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(saveFailRoot, "runs"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Executor{Store: NewStore(saveFailRoot)}).persist(LaunchRun{LaunchID: "save-fail", State: StateValidated, KernelVerdict: "ALLOW"}, map[string][]byte{}); err == nil {
		t.Fatal("expected persist save failure")
	}

	if _, err := NewExecutor(NewStore(t.TempDir())).DeleteLaunch("missing", false); err == nil {
		t.Fatal("expected missing launch delete error")
	}

	env := map[string]string{"EXISTING": "kept"}
	setIfEmpty(env, "EMPTY_VALUE", "")
	setIfEmpty(env, "EXISTING", "replacement")
	if env["EMPTY_VALUE"] != "" || env["EXISTING"] != "kept" {
		t.Fatalf("setIfEmpty guard mismatch: %#v", env)
	}
	projectModelProviderRuntimeMetadata(env, "")
	projectModelProviderRuntimeMetadata(env, "CUSTOM_API_KEY")
	t.Setenv("ANTHROPIC_BASE_URL", "https://anthropic.example")
	secrets := runtimeSecrets(plan.LaunchPlan{ModelGatewayEnv: []string{"ANTHROPIC_API_KEY"}}, ExecuteOptions{RuntimeSecretEnv: map[string]string{"ANTHROPIC_API_KEY": "anthropic-key"}})
	if secrets["ANTHROPIC_BASE_URL"] == "" || secrets["HELM_MODEL_GATEWAY_PROVIDER"] != "anthropic" {
		t.Fatalf("anthropic provider metadata missing: %#v", secrets)
	}
}

type emptyRuntimeStarter struct{}

func (emptyRuntimeStarter) Start(plan.LaunchPlan, ExecuteOptions) (RuntimeStartResult, error) {
	return RuntimeStartResult{}, nil
}

func writeRunJSON(t *testing.T, path string, run LaunchRun) {
	t.Helper()
	data, err := json.Marshal(run)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func marshalString(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
