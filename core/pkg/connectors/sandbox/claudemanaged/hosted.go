package claudemanaged

import (
	"context"
	"errors"
	"fmt"
	"time"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

var _ connsandbox.Provider = (*Hosted)(nil)

// Hosted is the adapter as helm-gateway drives it. It never runs a command on
// the host of its own process: it refuses LocalCommandRunner, and executes
// through WorkerShim so the managed-agent receipt path runs for every command.
//
// Create makes bookkeeping directories under Config.WorkspaceRoot and
// Config.OutputsRoot on the host of this process (the adapter's workspace
// records); point both at a scratch volume.
type Hosted struct {
	*Adapter
	shim WorkerShim
}

// NewHosted builds a Hosted over runner, which must be a remote one.
func NewHosted(cfg Config, runner CommandRunner, signer ManagedAgentReceiptSigner, clock func() time.Time) (*Hosted, error) {
	switch runner.(type) {
	case nil:
		return nil, errors.New("claude managed agents: a hosted adapter needs a command runner")
	case LocalCommandRunner, *LocalCommandRunner:
		return nil, errors.New("claude managed agents: a hosted adapter never runs commands on its own host")
	}
	// The gateway has no effect that changes a sandbox's egress, and nothing
	// here enforces one: an egress change is refused, never just recorded.
	opts := []Option{WithRunner(runner), WithEgressController(refuseEgress{})}
	if signer != nil {
		opts = append(opts, WithReceiptSigner(signer))
	}
	if clock != nil {
		opts = append(opts, WithClock(clock))
	}
	a := New(cfg, opts...)
	return &Hosted{Adapter: a, shim: WorkerShim{Actuator: a, Clock: clock}}, nil
}

// refuseEgress is the hosted adapter's egress controller: it applies nothing.
type refuseEgress struct{}

func (refuseEgress) Allow(context.Context, string, []actuators.EgressRule) error {
	return actuators.ErrNotSupported
}

// Exec runs the command through the worker shim (tool class bash).
func (h *Hosted) Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	if req == nil {
		return nil, errors.New("claude managed agents: request is required")
	}
	if len(req.Env) > 0 || len(req.Stdin) > 0 {
		return nil, errors.New("claude managed agents: a hosted exec takes no environment or stdin")
	}
	start := h.Adapter.now()
	resp, err := h.shim.HandleTool(ctx, ToolRequest{SandboxID: id, ToolName: "bash", Class: ToolBash,
		Command: req.Command, WorkDir: req.WorkDir, TimeoutMS: req.Timeout.Milliseconds()})
	if err != nil {
		return nil, err
	}
	if !resp.Allowed {
		return nil, fmt.Errorf("claude managed agents: exec denied: %s", resp.ReasonCode)
	}
	code, ok := resp.StructuredContent["exit_code"].(int)
	if !ok {
		return nil, errors.New("claude managed agents: the shim answered without an exit code")
	}
	str := func(k string) string { s, _ := resp.StructuredContent[k].(string); return s }
	result := &actuators.ExecResult{ExitCode: code, Stdout: []byte(resp.Content)}
	result.Receipt = actuators.ReceiptFragment{
		Provider: ProviderID, ExecutedAt: start, Effect: actuators.EffectExecShell,
		RequestHash: str("receipt_fragment_ref"), StdoutHash: str("stdout_hash"), StderrHash: str("stderr_hash"),
	}
	return result, nil
}
