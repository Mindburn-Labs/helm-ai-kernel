// Package e2b implements the SandboxActuator for E2B sandboxes.
//
// E2B provides stateful sandboxes with persistence (pause/resume preserving
// filesystem and memory). This adapter maps E2B's REST API patterns to the
// unified SandboxActuator interface.
//
// Ref: https://e2b.dev/docs
package e2b

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

var _ connsandbox.Provider = (*Adapter)(nil)

// Config is the adapter configuration for E2B.
type Config struct {
	// APIURL is the E2B API base URL.
	APIURL string `json:"api_url"`

	// APIKey is the E2B API key.
	APIKey string `json:"api_key"`

	// TemplateID is the default sandbox template.
	TemplateID string `json:"template_id"`

	// DefaultTimeout is the default sandbox timeout.
	DefaultTimeout time.Duration `json:"default_timeout"`

	// AllowInsecureLoopback permits http:// loopback endpoints for local tests only.
	AllowInsecureLoopback bool `json:"allow_insecure_loopback,omitempty"`

	// RefuseUnappliedPolicy makes Create refuse (actuators.ErrNotSupported) a
	// spec that asks for a limit, an egress policy, an environment or a mount
	// this adapter's create call does not carry (CheckSpec), instead of
	// creating a sandbox that runs without them. helm-gateway sets it.
	RefuseUnappliedPolicy bool `json:"refuse_unapplied_policy,omitempty"`
}

// DefaultConfig returns a config with defaults.
func DefaultConfig() Config {
	return Config{
		APIURL:         "https://api.e2b.dev",
		DefaultTimeout: 5 * time.Minute,
	}
}

// Adapter implements actuators.SandboxActuator for E2B.
type Adapter struct {
	cfg    Config
	client *http.Client
	clock  func() time.Time

	mu    sync.Mutex
	specs map[string]*actuators.SandboxSpec
}

// New creates a new E2B adapter.
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

// WithClock overrides the clock for testing.
func (a *Adapter) WithClock(clock func() time.Time) *Adapter {
	a.clock = clock
	return a
}

// WithHTTPClient overrides the HTTP client for testing.
func (a *Adapter) WithHTTPClient(client *http.Client) *Adapter {
	a.client = client
	return a
}

func (a *Adapter) Provider() string { return "e2b" }

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
		Provider:     "e2b",
		StrictPassed: strictPassed,
		Checks:       checks,
		CheckedAt:    a.clock(),
	}, nil
}

// ── Lifecycle ───────────────────────────────────────────────────

type e2bCreateReq struct {
	TemplateID string            `json:"templateID"`
	Timeout    int               `json:"timeout,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type e2bCreateResp struct {
	SandboxID string `json:"sandboxID"`
	ClientID  string `json:"clientID,omitempty"`
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
			return nil, fmt.Errorf("%s: create refused: %w", "e2b", err)
		}
	}
	report, err := a.Preflight(ctx)
	if err != nil {
		return nil, err
	}
	if !report.StrictPassed {
		return nil, actuators.ErrPreflightFailed
	}

	templateID := a.cfg.TemplateID
	if spec.Runtime != "" && spec.Runtime != "default" {
		templateID = spec.Runtime
	}

	timeout := int(spec.Resources.Timeout.Seconds())
	if timeout == 0 {
		timeout = int(a.cfg.DefaultTimeout.Seconds())
	}

	var resp e2bCreateResp
	if err := a.doJSON(ctx, "POST", "/sandboxes", e2bCreateReq{
		TemplateID: templateID,
		Timeout:    timeout,
		Metadata:   spec.Labels,
	}, &resp); err != nil {
		return nil, fmt.Errorf("e2b: create failed: %w", err)
	}
	if !connsandbox.ValidID(resp.SandboxID) {
		return nil, fmt.Errorf("e2b: create failed: %w", &connsandbox.CallError{Provider: "e2b", Drift: true,
			Detail: "the create answer carries no usable sandbox id"})
	}

	a.remember(resp.SandboxID, spec)
	return &actuators.SandboxHandle{
		ID:        resp.SandboxID,
		Provider:  "e2b",
		Status:    actuators.StatusRunning,
		CreatedAt: a.clock(),
		Metadata: map[string]string{
			"template_id": templateID,
			"client_id":   resp.ClientID,
		},
	}, nil
}

func (a *Adapter) remember(id string, spec *actuators.SandboxSpec) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.specs[id] = spec
}

func (a *Adapter) specOf(id string) *actuators.SandboxSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.specs[id]
}

func (a *Adapter) Resume(ctx context.Context, id string) (*actuators.SandboxHandle, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var resp e2bCreateResp
	if err := a.doJSON(ctx, "POST", fmt.Sprintf("/sandboxes/%s/resume", id), nil, &resp); err != nil {
		return nil, fmt.Errorf("e2b: resume failed: %w", err)
	}
	return &actuators.SandboxHandle{
		ID:       resp.SandboxID,
		Provider: "e2b",
		Status:   actuators.StatusRunning,
	}, nil
}

func (a *Adapter) Pause(ctx context.Context, id string) error {
	if !connsandbox.ValidID(id) {
		return connsandbox.ErrBadID
	}
	return a.doJSON(ctx, "POST", fmt.Sprintf("/sandboxes/%s/pause", id), nil, nil)
}

func (a *Adapter) Terminate(ctx context.Context, id string) error {
	if !connsandbox.ValidID(id) {
		return connsandbox.ErrBadID
	}
	return a.doJSON(ctx, "DELETE", fmt.Sprintf("/sandboxes/%s", id), nil, nil)
}

// ── Execution ───────────────────────────────────────────────────

type e2bExecReq struct {
	Cmd     string            `json:"cmd"`
	Env     map[string]string `json:"envVars,omitempty"`
	WorkDir string            `json:"cwd,omitempty"`
	Timeout int               `json:"timeout,omitempty"`
}

type e2bExecResp struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exitCode"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"durationMs"`
}

func (a *Adapter) Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	spec := a.specOf(id)
	req, err := actuators.PrepareExecRequest(req, spec)
	if err != nil {
		return nil, err
	}

	// E2B takes a string command, not an array: quote each argument so the
	// original argument vector runs unchanged.
	cmd := connsandbox.ShellJoin(req.Command)

	apiReq := e2bExecReq{
		Cmd:     cmd,
		Env:     req.Env,
		WorkDir: req.WorkDir,
	}
	if req.Timeout > 0 {
		apiReq.Timeout = int(req.Timeout.Seconds())
	}

	var resp e2bExecResp
	if err := a.doJSON(ctx, "POST", fmt.Sprintf("/sandboxes/%s/process", id), apiReq, &resp); err != nil {
		return nil, fmt.Errorf("e2b: exec failed: %w", err)
	}

	stdout := []byte(resp.Stdout)
	stderr := []byte(resp.Stderr)
	now := a.clock()

	timedOut := resp.Error == "timeout"
	return actuators.BuildExecResult(req, stdout, stderr, resp.ExitCode, time.Duration(resp.DurationMs)*time.Millisecond, false, timedOut, "e2b", now, spec, actuators.EffectExecShell), nil
}

// ── Filesystem ──────────────────────────────────────────────────

func (a *Adapter) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var data []byte
	if err := connsandbox.DoJSON(ctx, connsandbox.Call{
		Client: a.client, Provider: "e2b", Method: "GET",
		URL:    fmt.Sprintf("%s/sandboxes/%s/filesystem?path=%s", a.cfg.APIURL, id, url.QueryEscape(path)),
		Auth:   a.setAuth,
		RawOut: &data,
	}); err != nil {
		return nil, fmt.Errorf("e2b: read file: %w", err)
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
		Client: a.client, Provider: "e2b", Method: "PUT",
		URL:     fmt.Sprintf("%s/sandboxes/%s/filesystem?path=%s", a.cfg.APIURL, id, url.QueryEscape(path)),
		Auth:    a.setAuth,
		RawBody: data,
	}); err != nil {
		return fmt.Errorf("e2b: write file: %w", err)
	}
	return nil
}

type e2bFileListResp struct {
	Entries []e2bFileEntry `json:"entries"`
}

type e2bFileEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
}

func (a *Adapter) ListFiles(ctx context.Context, id string, dir string) ([]actuators.FileEntry, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var resp e2bFileListResp
	if err := a.doJSON(ctx, "GET", fmt.Sprintf("/sandboxes/%s/filesystem/list?dir=%s", id, url.QueryEscape(dir)), nil, &resp); err != nil {
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
	// E2B handles egress at the template/config level, not per-sandbox runtime.
	return actuators.ErrNotSupported
}

// ── Observability ───────────────────────────────────────────────

func (a *Adapter) Logs(ctx context.Context, id string, opts *actuators.LogOptions) ([]actuators.LogEntry, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	path := fmt.Sprintf("/sandboxes/%s/logs", id)
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
// unproven against a live E2B account: GET /sandboxes/{id} answers
// {"sandboxID","templateID","state","metadata"}; GET /sandboxes?metadata=k%3Dv%26k2%3Dv2
// answers a JSON array of the same objects. Find never trusts the server's
// filter.

type e2bSandbox struct {
	SandboxID  string            `json:"sandboxID"`
	TemplateID string            `json:"templateID"`
	State      string            `json:"state"`
	Metadata   map[string]string `json:"metadata"`
}

func e2bStatus(state string) (actuators.SandboxStatus, bool) {
	switch state {
	case "running":
		return actuators.StatusRunning, true
	case "paused":
		return actuators.StatusPaused, true
	case "creating", "starting":
		return actuators.StatusCreating, true
	case "terminated", "killed":
		return actuators.StatusTerminated, true
	case "error", "failed":
		return actuators.StatusError, true
	}
	return "", false
}

func (s e2bSandbox) info() (*connsandbox.Info, error) {
	status, ok := e2bStatus(s.State)
	if !ok || !connsandbox.ValidID(s.SandboxID) {
		return nil, &connsandbox.CallError{Provider: "e2b", Drift: true, Detail: "a sandbox answer has no usable id or state"}
	}
	return &connsandbox.Info{ID: s.SandboxID, Status: status, Labels: s.Metadata, Runtime: s.TemplateID}, nil
}

// Lookup implements connsandbox.Inventory.
func (a *Adapter) Lookup(ctx context.Context, id string) (*connsandbox.Info, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var out e2bSandbox
	if err := a.doJSON(ctx, "GET", "/sandboxes/"+id, nil, &out); err != nil {
		if ce := connsandbox.AsCallError(err); ce != nil && ce.Status == http.StatusNotFound {
			return nil, fmt.Errorf("%w: %w", actuators.ErrSandboxNotFound, err)
		}
		return nil, fmt.Errorf("e2b: lookup failed: %w", err)
	}
	info, err := out.info()
	if err != nil {
		return nil, fmt.Errorf("e2b: lookup failed: %w", err)
	}
	if info.ID != id {
		return nil, fmt.Errorf("e2b: lookup failed: %w", &connsandbox.CallError{Provider: "e2b", Drift: true, Detail: "the answer names another sandbox"})
	}
	return info, nil
}

// Find implements connsandbox.Inventory.
func (a *Adapter) Find(ctx context.Context, labels map[string]string) ([]connsandbox.Info, error) {
	if len(labels) == 0 {
		return nil, fmt.Errorf("e2b: find needs at least one label")
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, len(keys))
	for i, k := range keys {
		pairs[i] = url.QueryEscape(k) + "=" + url.QueryEscape(labels[k])
	}
	var raw json.RawMessage
	if err := a.doJSON(ctx, "GET", "/sandboxes?metadata="+url.QueryEscape(strings.Join(pairs, "&")), nil, &raw); err != nil {
		return nil, fmt.Errorf("e2b: find failed: %w", err)
	}
	// A list is a JSON array. null, an object or anything else is not an empty
	// list: reading it as one would say a sandbox that exists is absent.
	var list []e2bSandbox
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '[' || json.Unmarshal(t, &list) != nil {
		return nil, fmt.Errorf("e2b: find failed: %w", &connsandbox.CallError{Provider: "e2b", Drift: true, Detail: "the list answer is not a JSON array"})
	}
	var found []connsandbox.Info
	for _, s := range list {
		if !labelsMatch(s.Metadata, labels) {
			continue
		}
		info, err := s.info()
		if err != nil {
			return nil, fmt.Errorf("e2b: find failed: %w", err)
		}
		found = append(found, *info)
		if len(found) > connsandbox.MaxFound {
			return nil, fmt.Errorf("e2b: find matched more than %d sandboxes", connsandbox.MaxFound)
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
		Client: a.client, Provider: "e2b", Method: method, URL: a.cfg.APIURL + path,
		Auth: a.setAuth, Body: reqBody, Out: respBody,
	})
}

func (a *Adapter) setAuth(req *http.Request) {
	if a.cfg.APIKey != "" {
		req.Header.Set("X-E2B-API-Key", a.cfg.APIKey)
	}
}
