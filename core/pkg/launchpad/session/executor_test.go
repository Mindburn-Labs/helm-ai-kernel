package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestExecutorRequiresRuntimeBeforeRunning(t *testing.T) {
	store := NewStore(t.TempDir())
	run, err := NewExecutor(store).ExecuteLaunch(allowPlan(), ExecuteOptions{Reason: "test"})
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
