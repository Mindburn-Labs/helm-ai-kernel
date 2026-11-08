// Package opensandbox implements the SandboxActuator for Alibaba OpenSandbox.
//
// OpenSandbox provides containerized execution with optional auth and egress controls.
// This adapter enforces strict preflight: API key must be set, egress sidecar must
// be in strict mode, and TLS must be enabled — HELM refuses to run otherwise.
//
// Ref: https://github.com/alibaba/OpenSandbox
package opensandbox

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	connsandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

var _ connsandbox.Provider = (*Adapter)(nil)

// Config is the adapter configuration for OpenSandbox.
type Config struct {
	// BaseURL is the OpenSandbox server URL (e.g. "https://sandbox.example.com").
	BaseURL string `json:"base_url"`

	// APIKey is the server API key. HELM requires this even though OpenSandbox
	// treats it as optional.
	APIKey string `json:"api_key"`

	// TLSRequired enforces HTTPS. Defaults to true.
	TLSRequired bool `json:"tls_required"`

	// EgressStrictMode requires the egress sidecar to be in strict enforcement mode.
	EgressStrictMode bool `json:"egress_strict_mode"`
}

// DefaultConfig returns a config with strict defaults.
func DefaultConfig() Config {
	return Config{
		TLSRequired:      true,
		EgressStrictMode: true,
	}
}

// Adapter implements actuators.SandboxActuator for OpenSandbox.
type Adapter struct {
	cfg    Config
	client *http.Client
	clock  func() time.Time

	mu    sync.Mutex
	specs map[string]*actuators.SandboxSpec
}

// New creates a new OpenSandbox adapter with the given config.
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

func (a *Adapter) Provider() string { return "opensandbox" }

// ── Preflight ───────────────────────────────────────────────────

func (a *Adapter) Preflight(_ context.Context) (*actuators.PreflightReport, error) {
	report := &actuators.PreflightReport{
		Provider:  "opensandbox",
		CheckedAt: a.clock(),
	}

	checks := runPreflightChecks(a.cfg)
	report.Checks = checks

	strictPassed := true
	for _, c := range checks {
		if c.Required && !c.Passed {
			strictPassed = false
		}
	}
	report.StrictPassed = strictPassed

	return report, nil
}

// ── Lifecycle ───────────────────────────────────────────────────

// createRequest is the request body for OpenSandbox /api/sandbox.
type createRequest struct {
	Image     string            `json:"image"`
	Command   []string          `json:"command,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Resources resourceRequest   `json:"resources,omitempty"`
	Network   networkRequest    `json:"network,omitempty"`
}

type resourceRequest struct {
	CPUMillis    int64 `json:"cpu_millis,omitempty"`
	MemoryMB     int64 `json:"memory_mb,omitempty"`
	DiskMB       int64 `json:"disk_mb,omitempty"`
	MaxProcesses int   `json:"max_processes,omitempty"`
	TimeoutSec   int   `json:"timeout_sec,omitempty"`
}

type networkRequest struct {
	Disabled  bool     `json:"disabled"`
	Allowlist []string `json:"egress_allowlist,omitempty"`
}

type createResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (a *Adapter) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	// Enforce preflight.
	report, err := a.Preflight(ctx)
	if err != nil {
		return nil, fmt.Errorf("opensandbox: preflight error: %w", err)
	}
	if !report.StrictPassed {
		return nil, actuators.ErrPreflightFailed
	}

	body := createRequest{
		Image:    spec.Runtime,
		Env:      spec.Env,
		Metadata: spec.Labels,
		Resources: resourceRequest{
			CPUMillis:    spec.Resources.CPUMillis,
			MemoryMB:     spec.Resources.MemoryMB,
			DiskMB:       spec.Resources.DiskMB,
			MaxProcesses: spec.Resources.MaxProcesses,
			TimeoutSec:   int(spec.Resources.Timeout.Seconds()),
		},
		Network: networkRequest{
			Disabled: spec.Egress.Disabled,
		},
	}

	for _, rule := range spec.Egress.DefaultAllowlist {
		entry := rule.Host
		if rule.Port > 0 {
			entry = fmt.Sprintf("%s:%d", rule.Host, rule.Port)
		}
		body.Network.Allowlist = append(body.Network.Allowlist, entry)
	}

	var resp createResponse
	if err := a.doJSON(ctx, "POST", "/api/sandbox", body, &resp); err != nil {
		return nil, fmt.Errorf("opensandbox: create failed: %w", err)
	}
	if !connsandbox.ValidID(resp.ID) {
		return nil, fmt.Errorf("opensandbox: create failed: %w", &connsandbox.CallError{Provider: "opensandbox", Drift: true,
			Detail: "the create answer carries no usable sandbox id"})
	}

	a.mu.Lock()
	a.specs[resp.ID] = spec
	a.mu.Unlock()
	return &actuators.SandboxHandle{
		ID:        resp.ID,
		Provider:  "opensandbox",
		Status:    actuators.StatusRunning,
		CreatedAt: a.clock(),
		Metadata:  map[string]string{"image": spec.Runtime},
	}, nil
}

func (a *Adapter) Resume(ctx context.Context, id string) (*actuators.SandboxHandle, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var resp createResponse
	if err := a.doJSON(ctx, "POST", fmt.Sprintf("/api/sandbox/%s/resume", id), nil, &resp); err != nil {
		return nil, fmt.Errorf("opensandbox: resume failed: %w", err)
	}
	return &actuators.SandboxHandle{
		ID:       resp.ID,
		Provider: "opensandbox",
		Status:   actuators.StatusRunning,
	}, nil
}

func (a *Adapter) Pause(ctx context.Context, id string) error {
	if !connsandbox.ValidID(id) {
		return connsandbox.ErrBadID
	}
	return a.doJSON(ctx, "POST", fmt.Sprintf("/api/sandbox/%s/pause", id), nil, nil)
}

func (a *Adapter) Terminate(ctx context.Context, id string) error {
	if !connsandbox.ValidID(id) {
		return connsandbox.ErrBadID
	}
	return a.doJSON(ctx, "DELETE", fmt.Sprintf("/api/sandbox/%s", id), nil, nil)
}

// ── Execution ───────────────────────────────────────────────────

type execRequest struct {
	Command []string          `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
	Stdin   string            `json:"stdin,omitempty"`
	WorkDir string            `json:"workdir,omitempty"`
	Timeout int               `json:"timeout_sec,omitempty"`
}

type execResponse struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"duration_ms"`
	OOMKilled  bool   `json:"oom_killed"`
	TimedOut   bool   `json:"timed_out"`
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

	apiReq := execRequest{
		Command: req.Command,
		Env:     req.Env,
		WorkDir: req.WorkDir,
	}
	if req.Timeout > 0 {
		apiReq.Timeout = int(req.Timeout.Seconds())
	}
	if len(req.Stdin) > 0 {
		apiReq.Stdin = string(req.Stdin)
	}

	var resp execResponse
	if err := a.doJSON(ctx, "POST", fmt.Sprintf("/api/sandbox/%s/exec", id), apiReq, &resp); err != nil {
		return nil, fmt.Errorf("opensandbox: exec failed: %w", err)
	}

	stdout := []byte(resp.Stdout)
	stderr := []byte(resp.Stderr)
	now := a.clock()
	return actuators.BuildExecResult(req, stdout, stderr, resp.ExitCode, time.Duration(resp.DurationMs)*time.Millisecond, resp.OOMKilled, resp.TimedOut, "opensandbox", now, spec, actuators.EffectExecShell), nil
}

// ── Filesystem ──────────────────────────────────────────────────

func (a *Adapter) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var data []byte
	if err := connsandbox.DoJSON(ctx, connsandbox.Call{
		Client: a.client, Provider: "opensandbox", Method: "GET",
		URL:    fmt.Sprintf("%s/api/sandbox/%s/files?path=%s", a.cfg.BaseURL, id, url.QueryEscape(path)),
		Auth:   a.setAuth,
		RawOut: &data,
	}); err != nil {
		return nil, fmt.Errorf("opensandbox: read file: %w", err)
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
		Client: a.client, Provider: "opensandbox", Method: "PUT",
		URL:     fmt.Sprintf("%s/api/sandbox/%s/files?path=%s", a.cfg.BaseURL, id, url.QueryEscape(path)),
		Auth:    a.setAuth,
		RawBody: data,
	}); err != nil {
		return fmt.Errorf("opensandbox: write file: %w", err)
	}
	return nil
}

type fileListResponse struct {
	Entries []fileEntryResponse `json:"entries"`
}

type fileEntryResponse struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

func (a *Adapter) ListFiles(ctx context.Context, id string, dir string) ([]actuators.FileEntry, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var resp fileListResponse
	if err := a.doJSON(ctx, "GET", fmt.Sprintf("/api/sandbox/%s/files/list?dir=%s", id, url.QueryEscape(dir)), nil, &resp); err != nil {
		return nil, err
	}

	entries := make([]actuators.FileEntry, len(resp.Entries))
	for i, e := range resp.Entries {
		modTime, _ := time.Parse(time.RFC3339, e.ModTime)
		entries[i] = actuators.FileEntry{
			Name:    e.Name,
			Path:    e.Path,
			IsDir:   e.IsDir,
			Size:    e.Size,
			ModTime: modTime,
		}
	}
	return entries, nil
}

// ── Network ─────────────────────────────────────────────────────

func (a *Adapter) AllowEgress(ctx context.Context, id string, rules []actuators.EgressRule) error {
	if !connsandbox.ValidID(id) {
		return connsandbox.ErrBadID
	}
	apiRules := make([]string, len(rules))
	for i, r := range rules {
		if r.Port > 0 {
			apiRules[i] = fmt.Sprintf("%s:%d", r.Host, r.Port)
		} else {
			apiRules[i] = r.Host
		}
	}

	body := map[string]interface{}{
		"egress_allowlist": apiRules,
	}
	return a.doJSON(ctx, "PUT", fmt.Sprintf("/api/sandbox/%s/network", id), body, nil)
}

// ── Observability ───────────────────────────────────────────────

type logsResponse struct {
	Logs []logEntryResponse `json:"logs"`
}

type logEntryResponse struct {
	Timestamp string `json:"timestamp"`
	Stream    string `json:"stream"`
	Line      string `json:"line"`
}

func (a *Adapter) Logs(ctx context.Context, id string, opts *actuators.LogOptions) ([]actuators.LogEntry, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	path := fmt.Sprintf("/api/sandbox/%s/logs", id)
	if opts != nil && opts.Tail > 0 {
		path = fmt.Sprintf("%s?tail=%d", path, opts.Tail)
	}

	var resp logsResponse
	if err := a.doJSON(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}

	entries := make([]actuators.LogEntry, len(resp.Logs))
	for i, l := range resp.Logs {
		ts, _ := time.Parse(time.RFC3339Nano, l.Timestamp)
		entries[i] = actuators.LogEntry{
			Timestamp: ts,
			Stream:    l.Stream,
			Line:      l.Line,
		}
	}
	return entries, nil
}

// ── Inventory ───────────────────────────────────────────────────

// The inventory wire shapes below follow this adapter's REST style and are
// unproven against a live OpenSandbox server: GET /api/sandbox/{id} answers
// {"id","status","metadata","image"}; GET /api/sandbox?label=k%3Dv (repeated per
// label) answers {"items":[...]} of the same objects. Find never trusts the
// server's filter.

type osSandbox struct {
	ID       string            `json:"id"`
	Status   string            `json:"status"`
	Metadata map[string]string `json:"metadata"`
	Image    string            `json:"image"`
}

func osStatus(status string) (actuators.SandboxStatus, bool) {
	switch status {
	case "running":
		return actuators.StatusRunning, true
	case "paused":
		return actuators.StatusPaused, true
	case "creating", "pending":
		return actuators.StatusCreating, true
	case "terminated", "deleted":
		return actuators.StatusTerminated, true
	case "error", "failed":
		return actuators.StatusError, true
	}
	return "", false
}

func (s osSandbox) info() (*connsandbox.Info, error) {
	status, ok := osStatus(s.Status)
	if !ok || !connsandbox.ValidID(s.ID) {
		return nil, &connsandbox.CallError{Provider: "opensandbox", Drift: true, Detail: "a sandbox answer has no usable id or status"}
	}
	return &connsandbox.Info{ID: s.ID, Status: status, Labels: s.Metadata, Runtime: s.Image}, nil
}

// Lookup implements connsandbox.Inventory.
func (a *Adapter) Lookup(ctx context.Context, id string) (*connsandbox.Info, error) {
	if !connsandbox.ValidID(id) {
		return nil, connsandbox.ErrBadID
	}
	var out osSandbox
	if err := a.doJSON(ctx, "GET", "/api/sandbox/"+id, nil, &out); err != nil {
		if ce := connsandbox.AsCallError(err); ce != nil && ce.Status == http.StatusNotFound {
			return nil, fmt.Errorf("%w: %w", actuators.ErrSandboxNotFound, err)
		}
		return nil, fmt.Errorf("opensandbox: lookup failed: %w", err)
	}
	info, err := out.info()
	if err != nil {
		return nil, fmt.Errorf("opensandbox: lookup failed: %w", err)
	}
	if info.ID != id {
		return nil, fmt.Errorf("opensandbox: lookup failed: %w", &connsandbox.CallError{Provider: "opensandbox", Drift: true, Detail: "the answer names another sandbox"})
	}
	return info, nil
}

// Find implements connsandbox.Inventory.
func (a *Adapter) Find(ctx context.Context, labels map[string]string) ([]connsandbox.Info, error) {
	if len(labels) == 0 {
		return nil, fmt.Errorf("opensandbox: find needs at least one label")
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	q := url.Values{}
	for _, k := range keys {
		q.Add("label", k+"="+labels[k])
	}
	var list struct {
		Items *[]osSandbox `json:"items"`
	}
	if err := a.doJSON(ctx, "GET", "/api/sandbox?"+q.Encode(), nil, &list); err != nil {
		return nil, fmt.Errorf("opensandbox: find failed: %w", err)
	}
	// {} and {"items":null} are not an empty list: reading them as one would
	// say a sandbox that exists is absent.
	if list.Items == nil {
		return nil, fmt.Errorf("opensandbox: find failed: %w", &connsandbox.CallError{Provider: "opensandbox", Drift: true, Detail: "the list answer carries no items array"})
	}
	var found []connsandbox.Info
	for _, s := range *list.Items {
		if !labelsMatch(s.Metadata, labels) {
			continue
		}
		info, err := s.info()
		if err != nil {
			return nil, fmt.Errorf("opensandbox: find failed: %w", err)
		}
		found = append(found, *info)
		if len(found) > connsandbox.MaxFound {
			return nil, fmt.Errorf("opensandbox: find matched more than %d sandboxes", connsandbox.MaxFound)
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
		Client: a.client, Provider: "opensandbox", Method: method, URL: a.cfg.BaseURL + path,
		Auth: a.setAuth, Body: reqBody, Out: respBody,
	})
}

func (a *Adapter) setAuth(req *http.Request) {
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
}
