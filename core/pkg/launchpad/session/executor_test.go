package session

import (
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
