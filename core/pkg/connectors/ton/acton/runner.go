package acton

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

type SandboxCommandExecutor interface {
	Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error)
	Provider() string
}

type Runner struct {
	Executor  SandboxCommandExecutor
	SandboxID string
	Timeout   time.Duration
}

func (r Runner) Run(ctx context.Context, env *ActonCommandEnvelope, grant *contracts.SandboxGrant, expectedShapeHash string) (*ActonReceipt, error) {
	if r.Executor == nil {
		return nil, fmt.Errorf("acton runner: sandbox executor is required")
	}
	if r.SandboxID == "" {
		return nil, fmt.Errorf("acton runner: sandbox id is required")
	}
	if err := ValidateSandboxGrant(env, grant); err != nil {
		decision := deny(reasonFromError(err, ReasonSandboxGrantRequired), err.Error())
		return NewPreDispatchReceipt(env, decision)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req := &actuators.ExecRequest{
		Command: env.Argv,
		WorkDir: env.ProjectRoot,
		Timeout: timeout,
	}
	result, err := r.Executor.Exec(runCtx, r.SandboxID, req)
	if err != nil {
		receipt, receiptErr := ReceiptFromExec(env, &actuators.ExecResult{
			ExitCode: -1,
			Stderr:   []byte(err.Error()),
			Receipt:  actuators.ComputeReceiptFragment(req, nil, []byte(err.Error()), r.Executor.Provider(), time.Now().UTC(), nil, actuators.EffectExecShell),
		}, r.Executor.Provider(), DriftReceipt{})
		if receiptErr != nil {
			return nil, receiptErr
		}
		receipt.Status = "error"
		receipt.ToolError = err.Error()
		return receipt, nil
	}
	drift := DetectOutputDrift(env, result.Stdout, expectedShapeHash)
	receipt, err := ReceiptFromExec(env, result, r.Executor.Provider(), drift)
	if err != nil {
		return nil, err
	}
	if drift.ContractDrift {
		receipt.Verdict = contracts.VerdictDeny
		receipt.Status = "denied"
		receipt.ReasonCode = ReasonConnectorContractDrift
	}
	receipt.Environment.OS = runtime.GOOS
	receipt.Environment.Arch = runtime.GOARCH
	receipt.Environment.Runtime = grant.Runtime
	receipt.Environment.ImageDigest = grant.ImageDigest
	receipt.Environment.TemplateDigest = grant.TemplateDigest
	return receipt, nil
}
