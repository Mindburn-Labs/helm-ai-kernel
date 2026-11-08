package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

// ProviderID is the provider name of the Docker sandbox provider.
const ProviderID = "docker"

const (
	maxProviderOutput = 256 * 1024
	cliTimeout        = 2 * time.Minute
)

var (
	digestImage  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
	labelKey     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	labelValue   = regexp.MustCompile(`^[A-Za-z0-9._:/-]{0,256}$`)
	workDirValue = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,511}$`)
)

// Provider is the Docker sandbox for helm-gateway: a labelled, long-lived,
// hardened container per sandbox, driven through the docker CLI of a
// SandboxesRunner. The image must be pinned by digest and contain `sleep`: the
// container runs `sleep <timeout>` and ends when its timeout ends.
type Provider struct {
	runner *SandboxesRunner
}

var _ connsandbox.Provider = (*Provider)(nil)

// NewProvider builds a Docker provider.
func NewProvider(cfg SandboxesConfig) *Provider {
	return &Provider{runner: NewSandboxesRunner(cfg)}
}

// Provider implements actuators.SandboxActuator.
func (p *Provider) Provider() string { return ProviderID }

// limitedBuffer keeps at most max bytes and records that it dropped some.
type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (l *limitedBuffer) Write(b []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(b) <= room {
			l.buf.Write(b)
		} else {
			l.buf.Write(b[:room])
			l.truncated = true
		}
	} else if len(b) > 0 {
		l.truncated = true
	}
	return len(b), nil
}

// cli runs docker with args, returning bounded stdout and stderr.
func (p *Provider) cli(ctx context.Context, args ...string) (stdout, stderr *limitedBuffer, err error) {
	stdout, stderr = &limitedBuffer{max: maxProviderOutput}, &limitedBuffer{max: maxProviderOutput}
	cmd := p.runner.buildCommand(ctx, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	return stdout, stderr, err
}

func missing(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "no such container") || strings.Contains(s, "no such object")
}

// Preflight checks that the docker CLI answers.
func (p *Provider) Preflight(ctx context.Context) (*actuators.PreflightReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	check := actuators.PreflightCheck{Name: "docker_available", Required: true}
	if _, _, err := p.cli(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		check.Reason = "the docker daemon does not answer"
	} else {
		check.Passed, check.Reason = true, "the docker daemon answers"
	}
	return &actuators.PreflightReport{Provider: ProviderID, StrictPassed: check.Passed,
		Checks: []actuators.PreflightCheck{check}, CheckedAt: p.runner.clock()}, nil
}

// Create starts a hardened, labelled container from a digest-pinned image.
func (p *Provider) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	args, err := createArgs(spec)
	if err != nil {
		return nil, err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	name := "helm-sbx-" + hex.EncodeToString(rnd[:])
	full := append([]string{"run", "-d", "--name", name}, args...)
	ctx, cancel := context.WithTimeout(ctx, cliTimeout)
	defer cancel()
	if _, _, err := p.cli(ctx, full...); err != nil {
		// The daemon's message is not relayed: it can echo the command line.
		return nil, fmt.Errorf("docker: starting the sandbox failed: %w", errors.New(exitText(err)))
	}
	return &actuators.SandboxHandle{ID: name, Provider: ProviderID, Status: actuators.StatusRunning,
		CreatedAt: p.runner.clock(), Metadata: map[string]string{"image": spec.Runtime}}, nil
}

func exitText(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Sprintf("docker exited with status %d", ee.ExitCode())
	}
	return "the docker CLI could not run"
}

// createArgs is the `docker run` argument vector after the name: flags, image
// and command.
func createArgs(spec *actuators.SandboxSpec) ([]string, error) {
	switch {
	case spec == nil:
		return nil, errors.New("docker: a sandbox spec is required")
	case !digestImage.MatchString(spec.Runtime):
		return nil, errors.New("docker: the runtime must be an image pinned by digest (name@sha256:<64 hex>)")
	case len(spec.Env) > 0:
		return nil, errors.New("docker: environment variables are not accepted")
	case len(spec.Mounts) > 0:
		return nil, errors.New("docker: mounts are not accepted")
	case len(spec.Egress.DefaultAllowlist) > 0:
		return nil, errors.New("docker: an egress allowlist is not supported; egress is all or none")
	case spec.Resources.MemoryMB <= 0:
		return nil, errors.New("docker: a memory limit is required")
	case spec.Resources.Timeout < time.Second:
		return nil, errors.New("docker: a timeout of at least one second is required")
	}
	args := []string{
		"--read-only", "--tmpfs", "/tmp:rw,nosuid,size=64m",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--memory", fmt.Sprintf("%dm", spec.Resources.MemoryMB),
	}
	if spec.Resources.CPUMillis > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.2f", float64(spec.Resources.CPUMillis)/1000.0))
	}
	if spec.Resources.MaxProcesses > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", spec.Resources.MaxProcesses))
	}
	if spec.Egress.Disabled {
		args = append(args, "--network", "none")
	}
	keys := make([]string, 0, len(spec.Labels))
	for k := range spec.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !labelKey.MatchString(k) || !labelValue.MatchString(spec.Labels[k]) {
			return nil, errors.New("docker: a label is not label-safe")
		}
		args = append(args, "--label", k+"="+spec.Labels[k])
	}
	args = append(args, spec.Runtime, "sleep", fmt.Sprintf("%d", int64(spec.Resources.Timeout.Seconds())))
	return args, nil
}

type inspected struct {
	Name  string `json:"Name"`
	State struct {
		Status string `json:"Status"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func statusOf(s string) (actuators.SandboxStatus, error) {
	switch s {
	case "running", "restarting":
		return actuators.StatusRunning, nil
	case "created":
		return actuators.StatusCreating, nil
	case "paused":
		return actuators.StatusPaused, nil
	case "exited", "dead", "removing":
		return actuators.StatusTerminated, nil
	}
	return "", fmt.Errorf("docker: unknown container state %q", s)
}

// Lookup inspects one container.
func (p *Provider) Lookup(ctx context.Context, id string) (*connsandbox.Info, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	ctx, cancel := context.WithTimeout(ctx, cliTimeout)
	defer cancel()
	out, errOut, err := p.cli(ctx, "inspect", "--type", "container", "--format", "{{json .}}", id)
	if err != nil {
		if missing(errOut.buf.String()) {
			return nil, fmt.Errorf("%w: %s", actuators.ErrSandboxNotFound, id)
		}
		return nil, fmt.Errorf("docker: inspect failed: %s", exitText(err))
	}
	var in inspected
	if out.truncated || json.Unmarshal(out.buf.Bytes(), &in) != nil {
		return nil, errors.New("docker: inspect answered with something that is not a container")
	}
	status, err := statusOf(in.State.Status)
	if err != nil {
		return nil, err
	}
	return &connsandbox.Info{ID: id, Status: status, Labels: in.Config.Labels, Runtime: in.Config.Image}, nil
}

// Find lists the containers carrying every label.
func (p *Provider) Find(ctx context.Context, labels map[string]string) ([]connsandbox.Info, error) {
	if len(labels) == 0 {
		return nil, errors.New("docker: find needs at least one label")
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := []string{"ps", "-a", "--no-trunc"}
	for _, k := range keys {
		if !labelKey.MatchString(k) || !labelValue.MatchString(labels[k]) {
			return nil, errors.New("docker: a label is not label-safe")
		}
		args = append(args, "--filter", "label="+k+"="+labels[k])
	}
	args = append(args, "--format", "{{.Names}}")
	ctx, cancel := context.WithTimeout(ctx, cliTimeout)
	defer cancel()
	out, _, err := p.cli(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("docker: listing failed: %s", exitText(err))
	}
	var found []connsandbox.Info
	for _, name := range strings.Fields(out.buf.String()) {
		info, err := p.Lookup(ctx, name)
		if errors.Is(err, actuators.ErrSandboxNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		match := true
		for k, v := range labels {
			if got, ok := info.Labels[k]; !ok || got != v {
				match = false
			}
		}
		if !match {
			continue
		}
		if found = append(found, *info); len(found) > connsandbox.MaxFound {
			return nil, errors.New("docker: more sandboxes match than the gateway lists")
		}
	}
	return found, nil
}

// Exec runs argv inside the container with no shell and no environment.
func (p *Provider) Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	if req != nil && len(req.Env) > 0 {
		return nil, errors.New("docker: exec does not accept environment variables")
	}
	if req != nil && len(req.Stdin) > 0 {
		return nil, errors.New("docker: exec does not accept stdin")
	}
	prepared, err := actuators.PrepareExecRequest(req, nil)
	if err != nil {
		return nil, err
	}
	if prepared.WorkDir != "" && !workDirValue.MatchString(prepared.WorkDir) {
		return nil, errors.New("docker: the working directory is not an absolute plain path")
	}
	args := []string{"exec"}
	if prepared.WorkDir != "" {
		args = append(args, "-w", prepared.WorkDir)
	}
	args = append(args, id)
	args = append(args, prepared.Command...)
	runCtx, cancel := context.WithTimeout(ctx, prepared.Timeout)
	defer cancel()
	start := p.runner.clock()
	out, errOut, err := p.cli(runCtx, args...)
	duration := p.runner.clock().Sub(start)
	exitCode, timedOut := 0, false
	if err != nil {
		var ee *exec.ExitError
		switch {
		case runCtx.Err() == context.DeadlineExceeded:
			timedOut, exitCode = true, -1
		case errors.As(err, &ee):
			if missing(errOut.buf.String()) {
				return nil, fmt.Errorf("%w: %s", actuators.ErrSandboxNotFound, id)
			}
			if ee.ExitCode() == 125 || ee.ExitCode() < 0 {
				return nil, fmt.Errorf("docker: exec failed: %s", exitText(err))
			}
			exitCode = ee.ExitCode()
		default:
			return nil, fmt.Errorf("docker: exec failed: %s", exitText(err))
		}
	}
	res := actuators.BuildExecResult(prepared, out.buf.Bytes(), errOut.buf.Bytes(), exitCode, duration,
		exitCode == 137, timedOut, ProviderID, start, nil, actuators.EffectExecShell)
	res.StdoutTruncated = res.StdoutTruncated || out.truncated
	res.StderrTruncated = res.StderrTruncated || errOut.truncated
	return res, nil
}

// Terminate removes the container; a missing one is already terminated.
func (p *Provider) Terminate(ctx context.Context, id string) error {
	if !connsandbox.ValidID(id) {
		return connsandbox.ErrBadID
	}
	ctx, cancel := context.WithTimeout(ctx, cliTimeout)
	defer cancel()
	if _, errOut, err := p.cli(ctx, "rm", "-f", id); err != nil && !missing(errOut.buf.String()) {
		return fmt.Errorf("docker: removing the sandbox failed: %s", exitText(err))
	}
	return nil
}

func (p *Provider) Resume(context.Context, string) (*actuators.SandboxHandle, error) {
	return nil, actuators.ErrNotSupported
}
func (p *Provider) Pause(context.Context, string) error { return actuators.ErrNotSupported }
func (p *Provider) ReadFile(context.Context, string, string) ([]byte, error) {
	return nil, actuators.ErrNotSupported
}
func (p *Provider) WriteFile(context.Context, string, string, []byte) error {
	return actuators.ErrNotSupported
}
func (p *Provider) ListFiles(context.Context, string, string) ([]actuators.FileEntry, error) {
	return nil, actuators.ErrNotSupported
}
func (p *Provider) AllowEgress(context.Context, string, []actuators.EgressRule) error {
	return actuators.ErrNotSupported
}
func (p *Provider) Logs(context.Context, string, *actuators.LogOptions) ([]actuators.LogEntry, error) {
	return nil, actuators.ErrNotSupported
}
