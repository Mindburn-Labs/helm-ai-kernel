// Package opensandbox implements the SandboxActuator for Alibaba OpenSandbox.
//
// OpenSandbox provides containerized execution with optional auth and egress controls.
// This adapter enforces strict preflight: API key must be set, egress sidecar must
// be in strict mode, and TLS must be enabled — HELM refuses to run otherwise.
//
// Ref: https://github.com/alibaba/OpenSandbox
package opensandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

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
	specs  map[string]*actuators.SandboxSpec
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
		Image: spec.Runtime,
		Env:   spec.Env,
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

	a.specs[resp.ID] = spec
	return &actuators.SandboxHandle{
		ID:        resp.ID,
		Provider:  "opensandbox",
		Status:    actuators.StatusRunning,
		CreatedAt: a.clock(),
		Metadata:  map[string]string{"image": spec.Runtime},
	}, nil
}

func (a *Adapter) Resume(ctx context.Context, id string) (*actuators.SandboxHandle, error) {
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
	return a.doJSON(ctx, "POST", fmt.Sprintf("/api/sandbox/%s/pause", id), nil, nil)
}

func (a *Adapter) Terminate(ctx context.Context, id string) error {
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

	return &actuators.ExecResult{
		ExitCode:  resp.ExitCode,
		Stdout:    stdout,
		Stderr:    stderr,
		Duration:  time.Duration(resp.DurationMs) * time.Millisecond,
		OOMKilled: resp.OOMKilled,
		TimedOut:  resp.TimedOut,
		Receipt:   actuators.ComputeReceiptFragment(req, stdout, stderr, "opensandbox", now, a.specs[id], actuators.EffectExecShell),
	}, nil
}

// ── Filesystem ──────────────────────────────────────────────────

func (a *Adapter) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/sandbox/%s/files?path=%s", a.cfg.BaseURL, id, path)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	a.setAuth(httpReq)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("opensandbox: read file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opensandbox: read file: status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (a *Adapter) WriteFile(ctx context.Context, id string, path string, data []byte) error {
	url := fmt.Sprintf("%s/api/sandbox/%s/files?path=%s", a.cfg.BaseURL, id, path)
	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	a.setAuth(httpReq)
	httpReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("opensandbox: write file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("opensandbox: write file: status %d", resp.StatusCode)
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
	var resp fileListResponse
	if err := a.doJSON(ctx, "GET", fmt.Sprintf("/api/sandbox/%s/files/list?dir=%s", id, dir), nil, &resp); err != nil {
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

// ── HTTP helpers ────────────────────────────────────────────────

func (a *Adapter) doJSON(ctx context.Context, method, path string, reqBody interface{}, respBody interface{}) error {
	url := a.cfg.BaseURL + path

	var body io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("opensandbox: marshal request: %w", err)
		}
		body = bytes.NewReader(data)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	a.setAuth(httpReq)
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("opensandbox: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respData, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("opensandbox: %s %s: status %d: %s", method, path, resp.StatusCode, string(respData))
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("opensandbox: decode response: %w", err)
		}
	}
	return nil
}

func (a *Adapter) setAuth(req *http.Request) {
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
}
