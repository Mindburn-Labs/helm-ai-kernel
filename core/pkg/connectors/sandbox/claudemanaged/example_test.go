package claudemanaged

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

type exampleRunner struct{}

func (exampleRunner) Run(_ context.Context, _ ExecutionContext, req *actuators.ExecRequest) (*RunnerResult, error) {
	return &RunnerResult{
		ExitCode: 0,
		Stdout:   []byte("hello\n"),
		Duration: time.Millisecond,
	}, nil
}

func ExampleWorkerShim_HandleTool() {
	root, err := os.MkdirTemp("", "helm-claude-managed-example-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)

	cfg := DefaultConfig()
	cfg.WorkerID = "worker-prod-us-1"
	cfg.WorkerImageDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	cfg.SkillManifestHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	cfg.AgentID = "agent-1"
	cfg.AgentVersion = "v1"
	cfg.SessionID = "session-1"
	cfg.EnvironmentID = "env-1"
	cfg.WorkID = "work-1"
	cfg.WorkspaceRoot = filepath.Join(root, "workspace")
	cfg.OutputsRoot = filepath.Join(root, "outputs")
	cfg.EnvironmentKeyConfigured = true
	cfg.EnvironmentKeyFromSecretStore = true
	cfg.LogRetentionEnabled = true

	adapter := New(cfg, WithRunner(exampleRunner{}))
	handle, err := adapter.Create(context.Background(), &actuators.SandboxSpec{
		Runtime:   "claude-managed-worker",
		Resources: actuators.ResourceSpec{MemoryMB: 256, Timeout: 30 * time.Second},
		Egress:    actuators.EgressPolicy{Disabled: true},
	})
	if err != nil {
		panic(err)
	}

	shim := WorkerShim{Actuator: adapter}
	resp, err := shim.HandleTool(context.Background(), ToolRequest{
		RequestID: "tool-call-1",
		SandboxID: handle.ID,
		ToolName:  "bash",
		Class:     ToolBash,
		Command:   []string{"echo", "hello"},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.Allowed)
	fmt.Println(resp.StructuredContent["managed_agent_receipt_schema"])
	// Output:
	// true
	// managed_agent_execution_receipt.v1
}
