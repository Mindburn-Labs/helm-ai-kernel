package claudemanaged

// quantum_posture: the worker call is a bearer-token request over TLS; nothing
// here signs or negotiates a key exchange, and no post-quantum claim is made.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

// maxRemoteStdin caps the stdin a RemoteRunner forwards.
const maxRemoteStdin = 64 << 10

// remoteLimit bounds a worker's answer.
const remoteLimit int64 = 4 << 20

type tokenKey struct{}

// ContextWithToken carries the bearer token one RemoteRunner call presents.
// The token is read from the context on each Run and kept nowhere.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}

// RemoteRunner runs commands on a customer-hosted worker instead of on the
// host of the process that holds the adapter. It speaks the HELM worker exec
// protocol v1:
//
//	POST <endpoint>/v1/exec
//	Authorization: Bearer <token>
//	{"sandbox_id": "...", "tenant": "...", "workdir": "...", "command": ["..."], "timeout_ms": 0,
//	 "spec": {"egress_disabled": true, "cpu_millis": 0, "memory_mb": 0, "disk_mb": 0, "max_processes": 0}}
//
// where workdir is relative to the sandbox's workspace on the worker ("" is
// the workspace itself) and never a path on the host of this process,

// and the worker answers 200 with
//
//	{"exit_code": 0, "stdout": "...", "stderr": "...", "duration_ms": 0,
//	 "oom_killed": false, "timed_out": false, "tenant": "...", "spec_applied": true}
//
// and the worker ends a sandbox with
//
//	POST <endpoint>/v1/terminate
//	{"sandbox_id": "...", "tenant": "..."}  ->  200 {"terminated": true, "tenant": "..."}
//
// tenant is the digest of the creating tenant. The worker binds a sandbox id
// to the tenant it first saw it with and refuses (4xx) a request for that
// sandbox from another tenant; it echoes the tenant, and the runner treats an
// answer that does not echo it as contract drift. spec is the sandbox's
// egress policy and resource limits: the worker applies them to the command or
// refuses (4xx), and says it applied them (spec_applied); an answer that does
// not is contract drift, since the gateway cannot see the worker apply them.
// The gateway chooses sandbox ids at random and never reuses one.
//
// No environment is sent. A 4xx is a definite refusal (the command did not
// run); anything else that is not a 200 is indefinite. Errors wrap a
// *connsandbox.CallError and never carry the token or a body.
type RemoteRunner struct {
	endpoint string
	client   *http.Client
}

// NewRemoteRunner validates the worker endpoint: https, or http on a loopback
// host (tests); no userinfo, query or fragment.
func NewRemoteRunner(endpoint string, client *http.Client) (*RemoteRunner, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("claude managed agents: the worker endpoint must be an absolute URL without credentials, query or fragment")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	default:
		return nil, errors.New("claude managed agents: the worker endpoint must use https (http only on a loopback host)")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &RemoteRunner{endpoint: strings.TrimRight(endpoint, "/"), client: client}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type remoteSpec struct {
	EgressDisabled bool  `json:"egress_disabled"`
	CPUMillis      int64 `json:"cpu_millis"`
	MemoryMB       int64 `json:"memory_mb"`
	DiskMB         int64 `json:"disk_mb"`
	MaxProcesses   int   `json:"max_processes"`
}

type remoteExecRequest struct {
	SandboxID string      `json:"sandbox_id"`
	Tenant    string      `json:"tenant,omitempty"`
	Spec      *remoteSpec `json:"spec,omitempty"`
	WorkDir   string      `json:"workdir,omitempty"`
	Command   []string    `json:"command"`
	Stdin     string      `json:"stdin,omitempty"`
	TimeoutMS int64       `json:"timeout_ms,omitempty"`
}

type remoteExecResponse struct {
	ExitCode    int    `json:"exit_code"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	DurationMS  int64  `json:"duration_ms"`
	OOMKilled   bool   `json:"oom_killed"`
	TimedOut    bool   `json:"timed_out"`
	Tenant      string `json:"tenant"`
	SpecApplied bool   `json:"spec_applied"`
}

type remoteTerminateRequest struct {
	SandboxID string `json:"sandbox_id"`
	Tenant    string `json:"tenant,omitempty"`
}

type remoteTerminateResponse struct {
	Terminated bool   `json:"terminated"`
	Tenant     string `json:"tenant"`
}

// workerWorkDir turns the adapter's host-side working directory into the path
// the worker understands: relative to the sandbox's workspace, with "" meaning
// the workspace itself. The host path is a bookkeeping directory of this
// process and means nothing to the worker.
func workerWorkDir(execCtx ExecutionContext, hostDir string) (string, error) {
	if hostDir == "" || execCtx.WorkspaceRoot == "" {
		return "", nil
	}
	rel, err := filepath.Rel(execCtx.WorkspaceRoot, hostDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", errors.New("claude managed agents: the working directory is outside the sandbox workspace")
	}
	if rel == "." {
		return "", nil
	}
	return filepath.ToSlash(rel), nil
}

// Run implements CommandRunner.
func (r *RemoteRunner) Run(ctx context.Context, execCtx ExecutionContext, req *actuators.ExecRequest) (*RunnerResult, error) {
	token, _ := ctx.Value(tokenKey{}).(string)
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("claude managed agents: no worker credential for this call")
	}
	if req == nil || len(req.Command) == 0 {
		return nil, errors.New("claude managed agents: command is required")
	}
	if len(req.Env) > 0 {
		return nil, errors.New("claude managed agents: the remote worker takes no environment")
	}
	if len(req.Stdin) > maxRemoteStdin {
		return nil, fmt.Errorf("claude managed agents: stdin exceeds %d bytes", maxRemoteStdin)
	}
	workdir, err := workerWorkDir(execCtx, req.WorkDir)
	if err != nil {
		return nil, err
	}
	body := remoteExecRequest{SandboxID: execCtx.SandboxID, Tenant: execCtx.Tenant, WorkDir: workdir, Command: req.Command,
		Stdin: string(req.Stdin), TimeoutMS: req.Timeout.Milliseconds()}
	if sp := execCtx.Spec; sp != nil {
		body.Spec = &remoteSpec{EgressDisabled: sp.Egress.Disabled, CPUMillis: sp.Resources.CPUMillis, MemoryMB: sp.Resources.MemoryMB,
			DiskMB: sp.Resources.DiskMB, MaxProcesses: sp.Resources.MaxProcesses}
	}
	var out remoteExecResponse
	err = connsandbox.DoJSON(ctx, connsandbox.Call{
		Client: r.client, Provider: ProviderID, Method: http.MethodPost, URL: r.endpoint + "/v1/exec",
		Auth: func(h *http.Request) { h.Header.Set("Authorization", "Bearer "+token) },
		Body: body, Out: &out, Limit: remoteLimit,
	})
	if err != nil {
		return nil, err
	}
	if out.Tenant != execCtx.Tenant {
		return nil, &connsandbox.CallError{Provider: ProviderID, Drift: true, Detail: "the worker's answer does not echo the sandbox's tenant"}
	}
	if body.Spec != nil && !out.SpecApplied {
		return nil, &connsandbox.CallError{Provider: ProviderID, Drift: true, Detail: "the worker's answer does not say it applied the sandbox's egress policy and limits"}
	}
	return &RunnerResult{ExitCode: out.ExitCode, Stdout: []byte(out.Stdout), Stderr: []byte(out.Stderr),
		Duration: time.Duration(out.DurationMS) * time.Millisecond, OOMKilled: out.OOMKilled, TimedOut: out.TimedOut}, nil
}

// Terminate implements Terminator: it asks the worker to end the sandbox. A
// worker that answers anything but a 200 that echoes the tenant and says it
// terminated has not ended it.
func (r *RemoteRunner) Terminate(ctx context.Context, execCtx ExecutionContext) error {
	token, _ := ctx.Value(tokenKey{}).(string)
	if strings.TrimSpace(token) == "" {
		return errors.New("claude managed agents: no worker credential for this call")
	}
	var out remoteTerminateResponse
	err := connsandbox.DoJSON(ctx, connsandbox.Call{
		Client: r.client, Provider: ProviderID, Method: http.MethodPost, URL: r.endpoint + "/v1/terminate",
		Auth: func(h *http.Request) { h.Header.Set("Authorization", "Bearer "+token) },
		Body: remoteTerminateRequest{SandboxID: execCtx.SandboxID, Tenant: execCtx.Tenant}, Out: &out, Limit: remoteLimit,
	})
	if err != nil {
		return err
	}
	if !out.Terminated || out.Tenant != execCtx.Tenant {
		return &connsandbox.CallError{Provider: ProviderID, Drift: true, Detail: "the worker's answer does not say it terminated the sandbox for this tenant"}
	}
	return nil
}
