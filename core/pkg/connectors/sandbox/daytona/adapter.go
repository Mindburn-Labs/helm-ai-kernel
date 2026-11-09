// Package daytona implements the SandboxActuator for Daytona sandboxes.
//
// Daytona provides stateless code execution and workspace-based shell execution.
// This adapter maps Daytona's API to the unified SandboxActuator interface.
// Pause/Resume returns ErrNotSupported since Daytona sandboxes are stateless.
//
// Ref: https://www.daytona.io/docs
package daytona

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

var _ connsandbox.Provider = (*Adapter)(nil)

// Config is the adapter configuration for Daytona.
type Config struct {
	// BaseURL is the Daytona API base URL.
	BaseURL string `json:"base_url"`

	// APIKey is the Daytona API key.
	APIKey string `json:"api_key"`

	// WorkspaceIsolation requires workspace-level isolation.
	WorkspaceIsolation bool `json:"workspace_isolation"`

	// DefaultLanguage is the default language for code execution.
	DefaultLanguage string `json:"default_language"`

	// AllowInsecureLoopback permits http:// loopback endpoints for local tests only.
	AllowInsecureLoopback bool `json:"allow_insecure_loopback,omitempty"`

	// RefuseUnappliedPolicy makes Create refuse (actuators.ErrNotSupported) a
	// spec that asks for a limit, an egress policy, an environment or a mount
	// this adapter's create call does not carry (CheckSpec), instead of
	// creating a sandbox that runs without them. helm-gateway sets it.
	RefuseUnappliedPolicy bool `json:"refuse_unapplied_policy,omitempty"`
}

// DefaultConfig returns a config with strict defaults.
func DefaultConfig() Config {
	return Config{
		WorkspaceIsolation: true,
		DefaultLanguage:    "bash",
	}
}

// Adapter implements actuators.SandboxActuator for Daytona.
type Adapter struct {
	cfg    Config
	client *http.Client
	clock  func() time.Time

	mu    sync.Mutex
	specs map[string]*actuators.SandboxSpec
}

// New creates a new Daytona adapter.
func New(cfg Config) *Adapter {
	return &Adapter{
		cfg: cfg,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		clock: time.Now,
		specs: make(map[string]*actuators.SandboxSpec),
	}
}

// WithClock overrides the clock.
func (a *Adapter) WithClock(clock func() time.Time) *Adapter {
	a.clock = clock
	return a
}

// WithHTTPClient overrides the HTTP client.
func (a *Adapter) WithHTTPClient(client *http.Client) *Adapter {
	a.client = client
	return a
}

func (a *Adapter) Provider() string { return "daytona" }

// ── Preflight ───────────────────────────────────────────────────

func (a *Adapter) Preflight(_ context.Context) (*actuators.PreflightReport, error) {
	checks := runPreflightChecks(a.cfg)
	strictPassed := true
	for _, c := range checks {
		if c.Required && !c.Passed {
			strictPassed = false
		}
	}
	return &actuators.PreflightReport{
		Provider:     "daytona",
		StrictPassed: strictPassed,
		Checks:       checks,
		CheckedAt:    a.clock(),
	}, nil
}

// ── Lifecycle ───────────────────────────────────────────────────

type daytonaCreateReq struct {
	Language string            `json:"language,omitempty"`
	Timeout  int               `json:"timeout,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type daytonaCreateResp struct {
	SandboxID string `json:"sandboxId"`
}

// CheckSpec refuses a spec this adapter would not apply: its create call
// carries the template or language, the timeout and the labels, and no
// resource limit, egress policy, environment or mount. The gateway checks it
// at admission and Create checks it again.
func CheckSpec(spec *actuators.SandboxSpec) error {
	return connsandbox.UnappliedPolicy(spec, true)
}

func (a *Adapter) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	if a.cfg.RefuseUnappliedPolicy {
		if err := CheckSpec(spec); err != nil {
			return nil, fmt.Errorf("%s: create refused: %w", "daytona", err)
		}
	}
	report, err := a.Preflight(ctx)
	if err != nil {
		return nil, err
	}
	if !report.StrictPassed {
		return nil, actuators.ErrPreflightFailed
	}

	lang := a.cfg.DefaultLanguage
	if spec.Runtime != "" && spec.Runtime != "default" {
		lang = spec.Runtime
	}

	var resp daytonaCreateResp
	if err := a.doJSON(ctx, "POST", "/sandbox", daytonaCreateReq{
		Language: lang,
		Timeout:  int(spec.Resources.Timeout.Seconds()),
		Labels:   spec.Labels,
	}, &resp); err != nil {
		return nil, fmt.Errorf("daytona: create failed: %w", err)
	}
	if !connsandbox.ValidID(resp.SandboxID) {
		return nil, fmt.Errorf("daytona: create failed: %w", &connsandbox.CallError{Provider: "daytona", Drift: true,
			Detail: "the create answer carries no usable sandbox id"})
	}

	a.mu.Lock()
	a.specs[resp.SandboxID] = spec
	a.mu.Unlock()
	return &actuators.SandboxHandle{
		ID:        resp.SandboxID,
		Provider:  "daytona",
		Status:    actuators.StatusRunning,
		CreatedAt: a.clock(),
		Metadata: map[string]string{
			"language": lang,
		},
	}, nil
}

func (a *Adapter) Resume(_ context.Context, _ string) (*actuators.SandboxHandle, error) {
	return nil, actuators.ErrNotSupported // Daytona sandboxes are stateless.
}

func (a *Adapter) Pause(_ context.Context, _ string) error {
	return actuators.ErrNotSupported // Daytona sandboxes are stateless.
}

func (a *Adapter) Terminate(ctx context.Context, id string) error {
	if !connsandbox.ValidID(id) {
		return connsandbox.ErrBadID
	}
	return a.doJSON(ctx, "DELETE", fmt.Sprintf("/sandbox/%s", id), nil, nil)
}

// ── Execution ───────────────────────────────────────────────────

type daytonaExecReq struct {
	Command string            `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
	WorkDir string            `json:"cwd,omitempty"`
	Timeout int               `json:"timeout,omitempty"`
}

type daytonaExecResp struct {
	Output     string `json:"output"`
	Errors     string `json:"errors"`
	ExitCode   int    `json:"exitCode"`
	TimedOut   bool   `json:"timedOut"`
	DurationMs int64  `json:"durationMs"`
}

func (a *Adapter) Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	a.mu.Lock()
	spec := a.specs[id]
	a.mu.Unlock()
	req, err := actuators.PrepareExecRequest(req, spec)
	if err != nil {
		return nil, err
	}

	// The API takes one command string: quote each argument so the original
	// argument vector runs unchanged.
	cmd := connsandbox.ShellJoin(req.Command)

	apiReq := daytonaExecReq{
		Command: cmd,
		Env:     req.Env,
		WorkDir: req.WorkDir,
	}
	if req.Timeout > 0 {
		apiReq.Timeout = int(req.Timeout.Seconds())
	}

	var resp daytonaExecResp
	if err := a.doJSON(ctx, "POST", fmt.Sprintf("/sandbox/%s/process/execute", id), apiReq, &resp); err != nil {
		return nil, fmt.Errorf("daytona: exec failed: %w", err)
	}

	stdout := []byte(resp.Output)
	stderr := []byte(resp.Errors)
	now := a.clock()
	return actuators.BuildExecResult(req, stdout, stderr, resp.ExitCode, time.Duration(resp.DurationMs)*time.Millisecond, false, resp.TimedOut, "daytona", now, spec, actuators.EffectExecShell), nil
}

// ── Filesystem ──────────────────────────────────────────────────

func (a *Adapter) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var data []byte
	if err := connsandbox.DoJSON(ctx, connsandbox.Call{
		Client: a.client, Provider: "daytona", Method: "GET",
		URL:    fmt.Sprintf("%s/sandbox/%s/filesystem?path=%s", a.cfg.BaseURL, id, url.QueryEscape(path)),
		Auth:   a.setAuth,
		RawOut: &data,
	}); err != nil {
		return nil, fmt.Errorf("daytona: read file: %w", err)
	}
	return data, nil
}

func (a *Adapter) WriteFile(ctx context.Context, id string, path string, data []byte) error {
	if !connsandbox.ValidID(id) {
		return connsandbox.ErrBadID
	}
	if data == nil {
		data = []byte{}
	}
	if err := connsandbox.DoJSON(ctx, connsandbox.Call{
		Client: a.client, Provider: "daytona", Method: "PUT",
		URL:     fmt.Sprintf("%s/sandbox/%s/filesystem?path=%s", a.cfg.BaseURL, id, url.QueryEscape(path)),
		Auth:    a.setAuth,
		RawBody: data,
	}); err != nil {
		return fmt.Errorf("daytona: write file: %w", err)
	}
	return nil
}

func (a *Adapter) ListFiles(ctx context.Context, id string, dir string) ([]actuators.FileEntry, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	type listResp struct {
		Entries []struct {
			Name  string `json:"name"`
			Path  string `json:"path"`
			IsDir bool   `json:"isDir"`
			Size  int64  `json:"size"`
		} `json:"entries"`
	}

	var resp listResp
	if err := a.doJSON(ctx, "GET", fmt.Sprintf("/sandbox/%s/filesystem/list?dir=%s", id, url.QueryEscape(dir)), nil, &resp); err != nil {
		return nil, err
	}

	entries := make([]actuators.FileEntry, len(resp.Entries))
	for i, e := range resp.Entries {
		entries[i] = actuators.FileEntry{
			Name:  e.Name,
			Path:  e.Path,
			IsDir: e.IsDir,
			Size:  e.Size,
		}
	}
	return entries, nil
}

// ── Network ─────────────────────────────────────────────────────

func (a *Adapter) AllowEgress(_ context.Context, _ string, _ []actuators.EgressRule) error {
	return actuators.ErrNotSupported // Daytona handles this at config level.
}

// ── Observability ───────────────────────────────────────────────

func (a *Adapter) Logs(ctx context.Context, id string, opts *actuators.LogOptions) ([]actuators.LogEntry, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	path := fmt.Sprintf("/sandbox/%s/logs", id)
	if opts != nil && opts.Tail > 0 {
		path = fmt.Sprintf("%s?limit=%d", path, opts.Tail)
	}

	type logResp struct {
		Logs []struct {
			Timestamp string `json:"timestamp"`
			Line      string `json:"line"`
		} `json:"logs"`
	}

	var resp logResp
	if err := a.doJSON(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}

	entries := make([]actuators.LogEntry, len(resp.Logs))
	for i, l := range resp.Logs {
		ts, _ := time.Parse(time.RFC3339Nano, l.Timestamp)
		entries[i] = actuators.LogEntry{
			Timestamp: ts,
			Stream:    "stdout",
			Line:      l.Line,
		}
	}
	return entries, nil
}

// ── Inventory ───────────────────────────────────────────────────

// The inventory wire shapes below follow this adapter's REST style and are
// unproven against a live Daytona account: GET /sandbox/{id} answers
// {"sandboxId","state","labels","language"}; GET /sandbox?labels=<JSON object>
// answers a JSON array of the same objects. Find never trusts the server's
// filter.

type daytonaSandbox struct {
	SandboxID string            `json:"sandboxId"`
	State     string            `json:"state"`
	Labels    map[string]string `json:"labels"`
	Language  string            `json:"language"`
}

func daytonaStatus(state string) (actuators.SandboxStatus, bool) {
	switch state {
	case "started", "running":
		return actuators.StatusRunning, true
	case "stopped", "paused":
		return actuators.StatusPaused, true
	case "creating", "starting":
		return actuators.StatusCreating, true
	case "destroyed", "terminated", "deleted":
		return actuators.StatusTerminated, true
	case "error", "failed":
		return actuators.StatusError, true
	}
	return "", false
}

func (s daytonaSandbox) info() (*connsandbox.Info, error) {
	status, ok := daytonaStatus(s.State)
	if !ok || !connsandbox.ValidID(s.SandboxID) {
		return nil, &connsandbox.CallError{Provider: "daytona", Drift: true, Detail: "a sandbox answer has no usable id or state"}
	}
	return &connsandbox.Info{ID: s.SandboxID, Status: status, Labels: s.Labels, Runtime: s.Language}, nil
}

// Lookup implements connsandbox.Inventory.
func (a *Adapter) Lookup(ctx context.Context, id string) (*connsandbox.Info, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var out daytonaSandbox
	if err := a.doJSON(ctx, "GET", "/sandbox/"+id, nil, &out); err != nil {
		if ce := connsandbox.AsCallError(err); ce != nil && ce.Status == http.StatusNotFound {
			return nil, fmt.Errorf("%w: %w", actuators.ErrSandboxNotFound, err)
		}
		return nil, fmt.Errorf("daytona: lookup failed: %w", err)
	}
	info, err := out.info()
	if err != nil {
		return nil, fmt.Errorf("daytona: lookup failed: %w", err)
	}
	if info.ID != id {
		return nil, fmt.Errorf("daytona: lookup failed: %w", &connsandbox.CallError{Provider: "daytona", Drift: true, Detail: "the answer names another sandbox"})
	}
	return info, nil
}

// Find implements connsandbox.Inventory.
func (a *Adapter) Find(ctx context.Context, labels map[string]string) ([]connsandbox.Info, error) {
	if len(labels) == 0 {
		return nil, fmt.Errorf("daytona: find needs at least one label")
	}
	filter, err := json.Marshal(labels)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := a.doJSON(ctx, "GET", "/sandbox?labels="+url.QueryEscape(string(filter)), nil, &raw); err != nil {
		return nil, fmt.Errorf("daytona: find failed: %w", err)
	}
	// A list is a JSON array. null, an object or anything else is not an empty
	// list: reading it as one would say a sandbox that exists is absent.
	var list []daytonaSandbox
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '[' || json.Unmarshal(t, &list) != nil {
		return nil, fmt.Errorf("daytona: find failed: %w", &connsandbox.CallError{Provider: "daytona", Drift: true, Detail: "the list answer is not a JSON array"})
	}
	var found []connsandbox.Info
	for _, s := range list {
		if !labelsMatch(s.Labels, labels) {
			continue
		}
		info, err := s.info()
		if err != nil {
			return nil, fmt.Errorf("daytona: find failed: %w", err)
		}
		found = append(found, *info)
		if len(found) > connsandbox.MaxFound {
			return nil, fmt.Errorf("daytona: find matched more than %d sandboxes", connsandbox.MaxFound)
		}
	}
	return found, nil
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if got, ok := have[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// ── HTTP helpers ────────────────────────────────────────────────

func (a *Adapter) doJSON(ctx context.Context, method, path string, reqBody interface{}, respBody interface{}) error {
	return connsandbox.DoJSON(ctx, connsandbox.Call{
		Client: a.client, Provider: "daytona", Method: method, URL: a.cfg.BaseURL + path,
		Auth: a.setAuth, Body: reqBody, Out: respBody,
	})
}

func (a *Adapter) setAuth(req *http.Request) {
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
}
