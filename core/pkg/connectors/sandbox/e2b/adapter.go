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
	"io"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

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
	specs  map[string]*actuators.SandboxSpec
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
	TemplateID string `json:"templateID"`
	Timeout    int    `json:"timeout,omitempty"`
}

type e2bCreateResp struct {
	SandboxID string `json:"sandboxID"`
	ClientID  string `json:"clientID,omitempty"`
}

func (a *Adapter) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
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
	}, &resp); err != nil {
		return nil, fmt.Errorf("e2b: create failed: %w", err)
	}

	a.specs[resp.SandboxID] = spec
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

func (a *Adapter) Resume(ctx context.Context, id string) (*actuators.SandboxHandle, error) {
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
	return a.doJSON(ctx, "POST", fmt.Sprintf("/sandboxes/%s/pause", id), nil, nil)
}

func (a *Adapter) Terminate(ctx context.Context, id string) error {
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
	// E2B takes a string command, not an array.
	cmd := ""
	for i, c := range req.Command {
		if i > 0 {
			cmd += " "
		}
		cmd += c
	}

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

	return &actuators.ExecResult{
		ExitCode: resp.ExitCode,
		Stdout:   stdout,
		Stderr:   stderr,
		Duration: time.Duration(resp.DurationMs) * time.Millisecond,
		TimedOut: timedOut,
		Receipt:  actuators.ComputeReceiptFragment(req, stdout, stderr, "e2b", now, a.specs[id], actuators.EffectExecShell),
	}, nil
}

// ── Filesystem ──────────────────────────────────────────────────

func (a *Adapter) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	url := fmt.Sprintf("%s/sandboxes/%s/filesystem?path=%s", a.cfg.APIURL, id, path)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	a.setAuth(httpReq)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("e2b: read file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("e2b: read file: status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (a *Adapter) WriteFile(ctx context.Context, id string, path string, data []byte) error {
	url := fmt.Sprintf("%s/sandboxes/%s/filesystem?path=%s", a.cfg.APIURL, id, path)
	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	a.setAuth(httpReq)
	httpReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("e2b: write file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("e2b: write file: status %d", resp.StatusCode)
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
	var resp e2bFileListResp
	if err := a.doJSON(ctx, "GET", fmt.Sprintf("/sandboxes/%s/filesystem/list?dir=%s", id, dir), nil, &resp); err != nil {
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

// ── HTTP helpers ────────────────────────────────────────────────

func (a *Adapter) doJSON(ctx context.Context, method, path string, reqBody interface{}, respBody interface{}) error {
	url := a.cfg.APIURL + path

	var body io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return err
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
		return fmt.Errorf("e2b: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respData, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("e2b: %s %s: status %d: %s", method, path, resp.StatusCode, string(respData))
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("e2b: decode response: %w", err)
		}
	}
	return nil
}

func (a *Adapter) setAuth(req *http.Request) {
	if a.cfg.APIKey != "" {
		req.Header.Set("X-E2B-API-Key", a.cfg.APIKey)
	}
}
