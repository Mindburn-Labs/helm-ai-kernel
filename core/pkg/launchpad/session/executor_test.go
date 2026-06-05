package session

import (
	"archive/tar"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "helm-launchpad-session-test-*")
	if err == nil {
		_ = os.Setenv("HELM_DATA_DIR", dir)
	}
	code := m.Run()
	if err == nil {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

func TestExecutorRequiresRuntimeBeforeRunning(t *testing.T) {
	store := NewStore(t.TempDir())
	run, err := NewExecutor(store).ExecuteLaunch(allowPlan(), ExecuteOptions{
		Reason:         "test",
		RuntimeStarter: failingRuntimeStarter{},
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch: %v", err)
	}
	if run.State != StateRepairRequired {
		t.Fatalf("expected REPAIR_REQUIRED when runtime cannot start, got %s", run.State)
	}
	if run.RuntimeHandles.ContainerID != "" {
		t.Fatalf("runtime handle must not be set after failed runtime start: %#v", run.RuntimeHandles)
	}
}

func TestExecutorBlocksSideEffectsForNonAllowPlan(t *testing.T) {
	store := NewStore(t.TempDir())
	starter := &fakeStarter{}
	p := allowPlan()
	p.KernelVerdict = "ESCALATE"
	p.Status = "ESCALATED"
	p.ReasonCode = "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING"
	p.RequiredSecretRefs = []string{"OPENAI_API_KEY"}
	run, err := NewExecutor(store).ExecuteLaunch(p, ExecuteOptions{Reason: "test", RuntimeStarter: starter})
	if err != nil {
		t.Fatalf("ExecuteLaunch: %v", err)
	}
	if starter.called {
		t.Fatal("runtime starter must not be called for non-ALLOW plan")
	}
	if run.State != StateEscalated {
		t.Fatalf("expected ESCALATED, got %s", run.State)
	}
	if run.RuntimeHandles.ContainerID != "" {
		t.Fatalf("container must not start for non-ALLOW plan: %#v", run.RuntimeHandles)
	}
	if len(run.SecretGrantRefs) != 0 || len(run.StartReceiptRefs) != 0 {
		t.Fatalf("non-ALLOW plan must not issue runtime secret/start grants: %#v", run)
	}
}

func TestExecutorRecordsRuntimeHandleBeforeRunning(t *testing.T) {
	store := NewStore(t.TempDir())
	starter := &fakeStarter{}
	health := &fakeHealthcheck{}
	run, err := NewExecutor(store).ExecuteLaunch(allowPlan(), ExecuteOptions{Reason: "test", RuntimeStarter: starter, HealthcheckRunner: health})
	if err != nil {
		t.Fatalf("ExecuteLaunch: %v", err)
	}
	if !starter.called {
		t.Fatal("runtime starter was not called")
	}
	if !health.called {
		t.Fatal("healthcheck runner was not called")
	}
	if run.State != StateRunning {
		t.Fatalf("expected RUNNING, got %s", run.State)
	}
	if run.RuntimeHandles.ContainerID != "container-1" {
		t.Fatalf("runtime container handle missing: %#v", run.RuntimeHandles)
	}
	if len(run.HealthcheckRefs) == 0 || len(run.LaunchReceiptRefs) == 0 || len(run.SandboxGrantRefs) == 0 {
		t.Fatalf("RUNNING missing required refs: %#v", run)
	}
	if run.ArtifactDigest == "" || run.VerificationCommand == "" || run.TeardownCommand == "" {
		t.Fatalf("developer response fields missing: %#v", run)
	}
	if !strings.Contains(run.VerificationCommand, ".tar") {
		t.Fatalf("verification command must point to sealed archive: %s", run.VerificationCommand)
	}
	archivePath := strings.TrimPrefix(run.VerificationCommand, "helm-ai-kernel verify --bundle ")
	assertTarContains(t, archivePath, "07_ATTESTATIONS/evidence_pack.sig")
}

func TestExecutorEvidenceSealUsesLaunchpadStoreRoot(t *testing.T) {
	dataRoot := t.TempDir()
	storeRoot := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataRoot)

	run, err := (Executor{Store: NewStore(storeRoot)}).persist(LaunchRun{
		LaunchID:      "store-root-evidence",
		State:         StateValidated,
		KernelVerdict: "ALLOW",
	}, map[string][]byte{"runtime_environment.json": []byte("{}")})
	if err != nil {
		t.Fatalf("persist: %v", err)
	}

	var keyFile struct {
		KeyID string `json:"key_id"`
	}
	keyData, err := os.ReadFile(filepath.Join(storeRoot, "keys", "evidence-pack-dev.ed25519"))
	if err != nil {
		t.Fatalf("read store-root evidence key: %v", err)
	}
	if err := json.Unmarshal(keyData, &keyFile); err != nil {
		t.Fatalf("parse store-root evidence key: %v", err)
	}
	if keyFile.KeyID == "" {
		t.Fatal("store-root evidence key id missing")
	}

	var seal struct {
		Signer struct {
			KeyID string `json:"key_id"`
		} `json:"signer"`
	}
	sealData, err := os.ReadFile(filepath.Join(storeRoot, "evidencepacks", run.LaunchID, evidencepkg.EvidencePackSealPath))
	if err != nil {
		t.Fatalf("read evidence seal: %v", err)
	}
	if err := json.Unmarshal(sealData, &seal); err != nil {
		t.Fatalf("parse evidence seal: %v", err)
	}
	if seal.Signer.KeyID != keyFile.KeyID {
		t.Fatalf("evidence seal used %q, want store-root key %q", seal.Signer.KeyID, keyFile.KeyID)
	}
	if _, err := os.Stat(filepath.Join(dataRoot, "keys", "evidence-pack-dev.ed25519")); !os.IsNotExist(err) {
		t.Fatalf("expected HELM_DATA_DIR key to stay unused, stat err=%v", err)
	}
}

func TestExecutorBlocksRunningWhenHealthcheckFails(t *testing.T) {
	store := NewStore(t.TempDir())
	run, err := NewExecutor(store).ExecuteLaunch(allowPlan(), ExecuteOptions{
		Reason:            "test",
		RuntimeStarter:    &fakeStarter{},
		HealthcheckRunner: failingHealthcheck{},
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch: %v", err)
	}
	if run.State != StateRepairRequired {
		t.Fatalf("expected REPAIR_REQUIRED when healthcheck fails, got %s", run.State)
	}
}

func TestExecutorRecordsIsolationEvidenceOnRuntimeFailure(t *testing.T) {
	store := NewStore(t.TempDir())
	run, err := NewExecutor(store).ExecuteLaunch(allowPlan(), ExecuteOptions{
		Reason:         "test",
		RuntimeStarter: failingIsolationStarter{},
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch: %v", err)
	}
	if run.State != StateRepairRequired {
		t.Fatalf("expected REPAIR_REQUIRED when isolation is unsupported, got %s", run.State)
	}
	if len(run.EvidencePackRefs) == 0 {
		t.Fatalf("evidence pack missing: %#v", run)
	}

	var runtimeEnv map[string]any
	readJSON(t, filepath.Join(run.EvidencePackRefs[0], "04_EXPORTS/runtime_environment.json"), &runtimeEnv)
	if runtimeEnv["isolation_mode"] != "gvisor" || runtimeEnv["isolation_detection_status"] != "unsupported" {
		t.Fatalf("runtime environment missing isolation denial evidence: %#v", runtimeEnv)
	}
	if denied, _ := runtimeEnv["unsupported_mode_denial"].(bool); !denied {
		t.Fatalf("runtime environment missing unsupported-mode denial marker: %#v", runtimeEnv)
	}

	var failureReceipt struct {
		Subject map[string]any `json:"subject"`
	}
	readJSON(t, filepath.Join(run.EvidencePackRefs[0], "02_PROOFGRAPH/receipts/launchpad-runtime-failure.json"), &failureReceipt)
	if failureReceipt.Subject["isolation_unsupported_reason"] == "" {
		t.Fatalf("runtime failure receipt missing unsupported reason: %#v", failureReceipt.Subject)
	}
}

func assertTarContains(t *testing.T, archivePath, want string) {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	tr := tar.NewReader(file)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == want {
			return
		}
	}
	t.Fatalf("archive %s missing %s", archivePath, want)
}

func TestExecutorRequiresEgressReceiptForNetworkedLaunch(t *testing.T) {
	store := NewStore(t.TempDir())
	p := allowPlan()
	p.NetworkAllowlist = []string{"openrouter.ai:443"}
	run, err := NewExecutor(store).ExecuteLaunch(p, ExecuteOptions{
		Reason:            "test",
		RuntimeStarter:    &fakeStarter{},
		HealthcheckRunner: &fakeHealthcheck{},
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch: %v", err)
	}
	if run.State != StateRepairRequired {
		t.Fatalf("expected REPAIR_REQUIRED without egress receipt, got %s", run.State)
	}
	if len(run.EgressReceiptRefs) != 0 {
		t.Fatalf("egress refs should be empty: %#v", run.EgressReceiptRefs)
	}
}

func TestExecutorRunsNetworkedLaunchWithEgressReceipt(t *testing.T) {
	store := NewStore(t.TempDir())
	p := allowPlan()
	p.NetworkAllowlist = []string{"openrouter.ai:443"}
	run, err := NewExecutor(store).ExecuteLaunch(p, ExecuteOptions{
		Reason:            "test",
		RuntimeStarter:    &fakeNetworkStarter{},
		HealthcheckRunner: &fakeHealthcheck{},
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch: %v", err)
	}
	if run.State != StateRunning {
		t.Fatalf("expected RUNNING, got %s", run.State)
	}
	if len(run.EgressReceiptRefs) == 0 {
		t.Fatalf("egress receipt missing: %#v", run)
	}
}

type fakeStarter struct {
	called bool
}

type failingRuntimeStarter struct{}

func (failingRuntimeStarter) Start(plan.LaunchPlan, ExecuteOptions) (RuntimeStartResult, error) {
	return RuntimeStartResult{Runtime: "local-container"}, testError("runtime unavailable")
}

func (f *fakeStarter) Start(plan.LaunchPlan, ExecuteOptions) (RuntimeStartResult, error) {
	f.called = true
	return RuntimeStartResult{
		ContainerID:     "container-1",
		SandboxGrantRef: "sandbox-grant:runtime",
		Runtime:         "local-container",
	}, nil
}

type fakeHealthcheck struct {
	called bool
}

type fakeNetworkStarter struct{}

func (fakeNetworkStarter) Start(plan.LaunchPlan, ExecuteOptions) (RuntimeStartResult, error) {
	return RuntimeStartResult{
		ContainerID:      "container-1",
		SandboxGrantRef:  "sandbox-grant:runtime",
		EgressReceiptRef: "receipt:egress",
		Runtime:          "local-container",
	}, nil
}

type failingIsolationStarter struct{}

func (failingIsolationStarter) Start(plan.LaunchPlan, ExecuteOptions) (RuntimeStartResult, error) {
	return RuntimeStartResult{
		Runtime:                    "local-container",
		IsolationMode:              "gvisor",
		IsolationDetectionStatus:   "unsupported",
		IsolationUnsupportedReason: "gvisor requires Docker runtime \"runsc\"",
		RuntimeClass:               "runsc",
		DockerRuntimes:             []string{"runc"},
		PayloadInspection:          "opaque_connect",
		NetworkProof:               "destination_allowlist_only",
		TokenBrokerEnabled:         false,
	}, testError("gvisor requires Docker runtime \"runsc\"")
}

func (f *fakeHealthcheck) Run(plan.LaunchPlan, RuntimeStartResult, ExecuteOptions) (HealthcheckResult, error) {
	f.called = true
	return HealthcheckResult{Type: "command", Status: "passed", Metadata: map[string]any{"source": "test"}}, nil
}

type failingHealthcheck struct{}

func (failingHealthcheck) Run(plan.LaunchPlan, RuntimeStartResult, ExecuteOptions) (HealthcheckResult, error) {
	return HealthcheckResult{}, errHealthcheckFailed
}

var errHealthcheckFailed = testError("healthcheck failed")

type testError string

func (e testError) Error() string { return string(e) }

func readJSON(t *testing.T, path string, out any) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func allowPlan() plan.LaunchPlan {
	return plan.LaunchPlan{
		LaunchID:           "launch-allow",
		AppID:              "openclaw",
		AppVersion:         "v2026.5.12",
		SubstrateID:        "local-container",
		Principal:          "test.operator",
		ArtifactImage:      "registry.example/openclaw@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ArtifactDigest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Healthchecks:       []registry.HealthcheckSpec{{Type: "command", Command: "openclaw --version"}},
		PolicyHash:         "sha256:policy",
		SandboxProfileHash: "sha256:sandbox",
		MCPPolicy: registry.MCPPolicy{
			UnknownServerPolicy: "quarantine",
			UnknownToolPolicy:   "ESCALATE",
			RequireSchemaPin:    true,
		},
		Budgets:       registry.BudgetCeiling{},
		Nodes:         map[string]any{},
		TeardownPlan:  map[string]any{"required": true},
		KernelVerdict: "ALLOW",
		Status:        "VALIDATED",
		PlanHash:      "sha256:plan",
	}
}

func TestExecutorMultiCloudLaunchDryRun(t *testing.T) {
	store := NewStore(t.TempDir())
	t.Setenv("DIGITALOCEAN_TOKEN", "mock-do-token")
	t.Setenv("HCLOUD_TOKEN", "mock-hcloud-token")

	executor := NewExecutor(store)

	// Test DigitalOcean
	doPlan := allowPlan()
	doPlan.SubstrateID = "digitalocean"
	runDO, err := executor.ExecuteLaunch(doPlan, ExecuteOptions{
		Reason:        "test-do",
		RuntimeDryRun: true,
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch DO: %v", err)
	}
	if runDO.State != StateRunning {
		t.Fatalf("expected StateRunning for DO dry run, got %s", runDO.State)
	}
	if runDO.RuntimeHandles.CloudResourceIDs["provider"] != "digitalocean" {
		t.Fatalf("expected cloud resource provider to be digitalocean, got %v", runDO.RuntimeHandles.CloudResourceIDs)
	}

	// Test Hetzner
	hPlan := allowPlan()
	hPlan.SubstrateID = "hetzner"
	runH, err := executor.ExecuteLaunch(hPlan, ExecuteOptions{
		Reason:        "test-h",
		RuntimeDryRun: true,
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch Hetzner: %v", err)
	}
	if runH.State != StateRunning {
		t.Fatalf("expected StateRunning for Hetzner dry run, got %s", runH.State)
	}
	if runH.RuntimeHandles.CloudResourceIDs["provider"] != "hetzner" {
		t.Fatalf("expected cloud resource provider to be hetzner, got %v", runH.RuntimeHandles.CloudResourceIDs)
	}

	// Test delete DO
	deletedDO, err := executor.DeleteLaunch(runDO.LaunchID, true)
	if err != nil {
		t.Fatalf("DeleteLaunch DO: %v", err)
	}
	if deletedDO.State != StateDeleted {
		t.Fatalf("expected deleted DO StateDeleted, got %s", deletedDO.State)
	}

	// Test delete Hetzner
	deletedH, err := executor.DeleteLaunch(runH.LaunchID, true)
	if err != nil {
		t.Fatalf("DeleteLaunch Hetzner: %v", err)
	}
	if deletedH.State != StateDeleted {
		t.Fatalf("expected deleted Hetzner StateDeleted, got %s", deletedH.State)
	}

	// Test E2B
	e2bPlan := allowPlan()
	e2bPlan.LaunchID = "launch-allow-e2b"
	e2bPlan.SubstrateID = "e2b"
	runE2B, err := executor.ExecuteLaunch(e2bPlan, ExecuteOptions{
		Reason:        "test-e2b",
		RuntimeDryRun: true,
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch E2B: %v", err)
	}
	if runE2B.State != StateRunning {
		t.Fatalf("expected StateRunning for E2B dry run, got %s", runE2B.State)
	}
	if runE2B.RuntimeHandles.CloudResourceIDs["provider"] != "e2b" {
		t.Fatalf("expected cloud resource provider to be e2b, got %v", runE2B.RuntimeHandles.CloudResourceIDs)
	}

	// Test Daytona
	daytonaPlan := allowPlan()
	daytonaPlan.LaunchID = "launch-allow-daytona"
	daytonaPlan.SubstrateID = "daytona"
	runDaytona, err := executor.ExecuteLaunch(daytonaPlan, ExecuteOptions{
		Reason:        "test-daytona",
		RuntimeDryRun: true,
	})
	if err != nil {
		t.Fatalf("ExecuteLaunch Daytona: %v", err)
	}
	if runDaytona.State != StateRunning {
		t.Fatalf("expected StateRunning for Daytona dry run, got %s", runDaytona.State)
	}
	if runDaytona.RuntimeHandles.CloudResourceIDs["provider"] != "daytona" {
		t.Fatalf("expected cloud resource provider to be daytona, got %v", runDaytona.RuntimeHandles.CloudResourceIDs)
	}

	// Test delete E2B
	deletedE2B, err := executor.DeleteLaunch(runE2B.LaunchID, true)
	if err != nil {
		t.Fatalf("DeleteLaunch E2B: %v", err)
	}
	if deletedE2B.State != StateDeleted {
		t.Fatalf("expected deleted E2B StateDeleted, got %s", deletedE2B.State)
	}

	// Test delete Daytona
	deletedDaytona, err := executor.DeleteLaunch(runDaytona.LaunchID, true)
	if err != nil {
		t.Fatalf("DeleteLaunch Daytona: %v", err)
	}
	if deletedDaytona.State != StateDeleted {
		t.Fatalf("expected deleted Daytona StateDeleted, got %s", deletedDaytona.State)
	}
}
