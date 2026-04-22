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
	"io"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

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
	specs  map[string]*actuators.SandboxSpec
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
	Language string `json:"language,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
}

type daytonaCreateResp struct {
	SandboxID string `json:"sandboxId"`
}

func (a *Adapter) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
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
	}, &resp); err != nil {
		return nil, fmt.Errorf("daytona: create failed: %w", err)
	}

	a.specs[resp.SandboxID] = spec
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
	cmd := ""
	for i, c := range req.Command {
		if i > 0 {
			cmd += " "
		}
		cmd += c
	}

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

	return &actuators.ExecResult{
		ExitCode: resp.ExitCode,
		Stdout:   stdout,
		Stderr:   stderr,
		Duration: time.Duration(resp.DurationMs) * time.Millisecond,
		TimedOut: resp.TimedOut,
		Receipt:  actuators.ComputeReceiptFragment(req, stdout, stderr, "daytona", now, a.specs[id], actuators.EffectExecShell),
	}, nil
}

// ── Filesystem ──────────────────────────────────────────────────

func (a *Adapter) ReadFile(ctx context.Context, id string, path string) ([]byte, error) {
	url := fmt.Sprintf("%s/sandbox/%s/filesystem?path=%s", a.cfg.BaseURL, id, path)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	a.setAuth(httpReq)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("daytona: read file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daytona: read file: status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (a *Adapter) WriteFile(ctx context.Context, id string, path string, data []byte) error {
	url := fmt.Sprintf("%s/sandbox/%s/filesystem?path=%s", a.cfg.BaseURL, id, path)
	httpReq, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	a.setAuth(httpReq)
	httpReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("daytona: write file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("daytona: write file: status %d", resp.StatusCode)
	}
	return nil
}

func (a *Adapter) ListFiles(ctx context.Context, id string, dir string) ([]actuators.FileEntry, error) {
	type listResp struct {
		Entries []struct {
			Name  string `json:"name"`
			Path  string `json:"path"`
			IsDir bool   `json:"isDir"`
			Size  int64  `json:"size"`
		} `json:"entries"`
	}

	var resp listResp
	if err := a.doJSON(ctx, "GET", fmt.Sprintf("/sandbox/%s/filesystem/list?dir=%s", id, dir), nil, &resp); err != nil {
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

// ── HTTP helpers ────────────────────────────────────────────────

func (a *Adapter) doJSON(ctx context.Context, method, path string, reqBody interface{}, respBody interface{}) error {
	url := a.cfg.BaseURL + path

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
		return fmt.Errorf("daytona: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respData, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("daytona: %s %s: status %d: %s", method, path, resp.StatusCode, string(respData))
	}

	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("daytona: decode response: %w", err)
		}
	}
	return nil
}

func (a *Adapter) setAuth(req *http.Request) {
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}
}
