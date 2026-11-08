package tonacton

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

// maxOutputBytes bounds what one run keeps of each output stream (09-04).
const maxOutputBytes = 256 * 1024

// processExecutor runs the operator-configured Acton binary for one call. It
// implements acton.SandboxCommandExecutor for the connector's runner and keeps
// what the adapter needs to tell "never started" from "ran".
type processExecutor struct {
	binary string
	dir    string
	env    []string
	// secret is redacted from both output streams before anything reads them.
	secret string

	started  bool
	startErr error
	stdout   []byte
}

func (p *processExecutor) Provider() string { return "helm-gateway-process" }

// Exec runs req.Command, whose first element is the connector's "acton", as the
// configured binary. The environment is exactly p.env: nothing is inherited.
func (p *processExecutor) Exec(ctx context.Context, _ string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	if len(req.Command) == 0 || req.Command[0] != "acton" {
		return nil, errors.New("the command is not an acton command")
	}
	cmd := exec.CommandContext(ctx, p.binary, req.Command[1:]...) // #nosec G204 -- operator-configured binary; argv is built from typed, schema-checked arguments
	cmd.Dir = p.dir
	cmd.Env = p.env
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	began := time.Now()
	if err := cmd.Start(); err != nil {
		p.startErr = err
		return nil, fmt.Errorf("start acton: %w", err)
	}
	p.started = true
	err := cmd.Wait()
	result := &actuators.ExecResult{Duration: time.Since(began)}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		result.TimedOut, result.ExitCode = true, -1
	case errors.As(err, &exit):
		result.ExitCode = exit.ExitCode()
	default:
		result.ExitCode = -1
		_, _ = stderr.Write([]byte(err.Error()))
	}
	result.Stdout, result.StdoutTruncated = p.redact(stdout.buf), stdout.truncated
	result.Stderr, result.StderrTruncated = p.redact(stderr.buf), stderr.truncated
	p.stdout = result.Stdout
	result.Receipt = actuators.ComputeReceiptFragment(req, result.Stdout, result.Stderr, p.Provider(), time.Now().UTC(), nil, actuators.EffectExecShell)
	return result, nil
}

func (p *processExecutor) redact(b []byte) []byte {
	if len(p.secret) == 0 {
		return b
	}
	return bytes.ReplaceAll(b, []byte(p.secret), []byte("[REDACTED]"))
}

// limitedBuffer keeps the first maxOutputBytes written and drops the rest.
type limitedBuffer struct {
	buf       []byte
	truncated bool
}

func (l *limitedBuffer) Write(b []byte) (int, error) {
	room := maxOutputBytes - len(l.buf)
	if room < len(b) {
		l.truncated = true
		b = b[:max(room, 0)]
	}
	l.buf = append(l.buf, b...)
	return len(b), nil
}

// textOf is stdout as bounded UTF-8 text for the typed result.
func textOf(b []byte) (string, bool) {
	truncated := false
	if len(b) > maxStdoutText {
		b, truncated = b[:maxStdoutText], true
	}
	return strings.ToValidUTF8(string(b), "�"), truncated
}
