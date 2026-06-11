// Package claudemanaged implements a HELM SandboxActuator for Claude Managed
// Agents self-hosted workers.
//
// The adapter governs the customer-controlled execution context where tools
// run. It does not call Anthropic's orchestration control plane.
package claudemanaged

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

const (
	ProviderID          = "claude-managed-agents"
	DefaultWorkspace    = "/workspace"
	DefaultOutputsRoot  = "/mnt/session/outputs"
	defaultPolicyEpoch  = "claude-managed-agents.self-hosted.v1"
	metadataImageDigest = "worker_image_digest"
)

// Config is the security-relevant configuration for a self-hosted Claude
// Managed Agents worker.
type Config struct {
	WorkerID                      string           `json:"worker_id"`
	WorkerImageDigest             string           `json:"worker_image_digest"`
	SkillManifestHash             string           `json:"skill_manifest_hash"`
	AgentID                       string           `json:"agent_id,omitempty"`
	AgentVersion                  string           `json:"agent_version,omitempty"`
	SessionID                     string           `json:"session_id,omitempty"`
	EnvironmentID                 string           `json:"environment_id,omitempty"`
	WorkID                        string           `json:"work_id,omitempty"`
	WorkspaceRoot                 string           `json:"workspace_root"`
	OutputsRoot                   string           `json:"outputs_root"`
	EnvironmentKeyConfigured      bool             `json:"environment_key_configured"`
	EnvironmentKeyFromSecretStore bool             `json:"environment_key_from_secret_store"`
	OrganizationAPIKeyPresent     bool             `json:"organization_api_key_present"`
	EgressEnforced                bool             `json:"egress_enforced"`
	LogRetentionEnabled           bool             `json:"log_retention_enabled"`
	TLSRequired                   bool             `json:"tls_required"`
	RemoteEndpoint                string           `json:"remote_endpoint,omitempty"`
	SkillsPinned                  bool             `json:"skills_pinned"`
	AllowRawMCPTunnelTargets      bool             `json:"allow_raw_mcp_tunnel_targets"`
	MCPGatewayURL                 string           `json:"mcp_gateway_url,omitempty"`
	Tunnel                        MCPTunnelProfile `json:"tunnel,omitempty"`
}

// MCPTunnelProfile captures the evidence HELM requires when an Anthropic MCP
// tunnel is part of the execution path.
type MCPTunnelProfile struct {
	Enabled                 bool     `json:"enabled"`
	RouteThroughHELMGateway bool     `json:"route_through_helm_gateway"`
	TunnelDomainHash        string   `json:"tunnel_domain_hash,omitempty"`
	UpstreamMCPServerID     string   `json:"upstream_mcp_server_id,omitempty"`
	OAuthResource           string   `json:"oauth_resource,omitempty"`
	RequiredScopes          []string `json:"required_scopes,omitempty"`
	ProtocolVersion         string   `json:"protocol_version,omitempty"`
	CACertRefHash           string   `json:"ca_cert_ref_hash,omitempty"`
	AllowedUpstreamHostHash string   `json:"allowed_upstream_host_hash,omitempty"`
}

// DefaultConfig returns strict defaults for a self-hosted worker.
func DefaultConfig() Config {
	return Config{
		WorkspaceRoot:  DefaultWorkspace,
		OutputsRoot:    DefaultOutputsRoot,
		TLSRequired:    true,
		SkillsPinned:   true,
		EgressEnforced: true,
		MCPGatewayURL:  "http://127.0.0.1:3000/mcp",
	}
}

// RunnerResult is the provider-neutral result returned by a tool runner.
type RunnerResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Duration  time.Duration
	OOMKilled bool
	TimedOut  bool
}

// ExecutionContext describes the already-governed local execution context.
type ExecutionContext struct {
	SandboxID     string
	WorkspaceRoot string
	OutputsRoot   string
	Spec          *actuators.SandboxSpec
	Metadata      map[string]string
}

// CommandRunner executes a command inside a self-hosted worker context.
type CommandRunner interface {
	Run(ctx context.Context, execCtx ExecutionContext, req *actuators.ExecRequest) (*RunnerResult, error)
}

// EgressController applies an already-authorized egress allowlist change.
type EgressController interface {
	Allow(ctx context.Context, sandboxID string, rules []actuators.EgressRule) error
}

// ManagedAgentReceiptSigner signs managed-agent execution receipts. Production
// deployments should provide a KMS/HSM-backed implementation.
type ManagedAgentReceiptSigner interface {
	Sign(data []byte) (string, error)
	SignerKeyID() string
}

// Option configures an Adapter.
type Option func(*Adapter)

// WithRunner overrides command execution, primarily for tests and worker shims.
func WithRunner(r CommandRunner) Option {
	return func(a *Adapter) {
		if r != nil {
			a.runner = r
		}
	}
}

// WithEgressController wires a provider-specific egress enforcement hook.
func WithEgressController(c EgressController) Option {
	return func(a *Adapter) {
		a.egress = c
	}
}

// WithClock overrides the adapter clock.
func WithClock(clock func() time.Time) Option {
	return func(a *Adapter) {
		if clock != nil {
			a.clock = clock
		}
	}
}

// WithReceiptSigner overrides managed-agent receipt signing.
func WithReceiptSigner(signer ManagedAgentReceiptSigner) Option {
	return func(a *Adapter) {
		if signer != nil {
			a.receiptSigner = signer
		}
	}
}

// Adapter implements actuators.SandboxActuator for Claude Managed Agents
// self-hosted worker execution.
type Adapter struct {
	cfg           Config
	runner        CommandRunner
	egress        EgressController
	clock         func() time.Time
	receiptSigner ManagedAgentReceiptSigner

	mu        sync.Mutex
	nextID    int
	sandboxes map[string]*sandboxState
}

type sandboxState struct {
	handle      *actuators.SandboxHandle
	spec        *actuators.SandboxSpec
	workspace   string
	outputs     string
	metadata    map[string]string
	logs        []actuators.LogEntry
	egressRules []actuators.EgressRule
}

// New creates an adapter for the customer-controlled self-hosted worker.
func New(cfg Config, opts ...Option) *Adapter {
	if cfg.WorkspaceRoot == "" {
		cfg.WorkspaceRoot = DefaultWorkspace
	}
	if cfg.OutputsRoot == "" {
		cfg.OutputsRoot = DefaultOutputsRoot
	}
	a := &Adapter{
		cfg:       cfg,
		runner:    LocalCommandRunner{},
		clock:     time.Now,
		sandboxes: make(map[string]*sandboxState),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Adapter) Provider() string { return ProviderID }

func (a *Adapter) Preflight(_ context.Context) (*actuators.PreflightReport, error) {
	checks := runPreflightChecks(a.cfg, a.receiptSigner)
	strictPassed := true
	for _, check := range checks {
		if check.Required && !check.Passed {
			strictPassed = false
		}
	}
	return &actuators.PreflightReport{
		Provider:     ProviderID,
		StrictPassed: strictPassed,
		Checks:       checks,
		CheckedAt:    a.now(),
	}, nil
}

func (a *Adapter) Create(ctx context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	report, err := a.Preflight(ctx)
	if err != nil {
		return nil, fmt.Errorf("claude managed agents: preflight error: %w", err)
	}
	if !report.StrictPassed {
		return nil, actuators.ErrPreflightFailed
	}
	if spec == nil {
		return nil, fmt.Errorf("claude managed agents: sandbox spec is required")
	}
	if err := validateSandboxSpec(spec); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(a.cfg.WorkspaceRoot, 0o755); err != nil {
		return nil, fmt.Errorf("claude managed agents: create workspace root: %w", err)
	}
	if err := os.MkdirAll(a.cfg.OutputsRoot, 0o755); err != nil {
		return nil, fmt.Errorf("claude managed agents: create outputs root: %w", err)
	}

	a.mu.Lock()
	a.nextID++
	id := a.sandboxID()
	a.mu.Unlock()

	workspace := filepath.Join(a.cfg.WorkspaceRoot, id, "workspace")
	outputs := filepath.Join(a.cfg.OutputsRoot, id)
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return nil, fmt.Errorf("claude managed agents: create sandbox workspace: %w", err)
	}
	if err := os.MkdirAll(outputs, 0o700); err != nil {
		return nil, fmt.Errorf("claude managed agents: create sandbox outputs: %w", err)
	}

	specCopy := *spec
	if specCopy.WorkDir == "" {
		specCopy.WorkDir = DefaultWorkspace
	}
	metadata := a.metadataFor(&specCopy, workspace, outputs)
	handle := &actuators.SandboxHandle{
		ID:        id,
		Provider:  ProviderID,
		Status:    actuators.StatusRunning,
		CreatedAt: a.now(),
		Metadata:  metadata,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.sandboxes[id]; exists {
		return nil, fmt.Errorf("claude managed agents: sandbox id %q already exists", id)
	}
	a.sandboxes[id] = &sandboxState{
		handle:    handle,
		spec:      &specCopy,
		workspace: workspace,
		outputs:   outputs,
		metadata:  metadata,
		logs:      make([]actuators.LogEntry, 0),
	}
	return handle, nil
}

func (a *Adapter) Resume(_ context.Context, _ string) (*actuators.SandboxHandle, error) {
	return nil, actuators.ErrNotSupported
}

func (a *Adapter) Pause(_ context.Context, _ string) error {
	return actuators.ErrNotSupported
}

func (a *Adapter) Terminate(_ context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	state, ok := a.sandboxes[id]
	if !ok {
		return actuators.ErrSandboxNotFound
	}
	state.handle.Status = actuators.StatusTerminated
	return nil
}

func (a *Adapter) Exec(ctx context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	state, err := a.runningState(id)
	if err != nil {
		return nil, err
	}
	if req == nil || len(req.Command) == 0 {
		return nil, fmt.Errorf("claude managed agents: command is required")
	}

	runnerReq := *req
	if runnerReq.WorkDir == "" {
		runnerReq.WorkDir = state.workspace
	} else {
		hostWorkDir, err := a.resolvePath(state, runnerReq.WorkDir, false)
		if err != nil {
			return nil, err
		}
		runnerReq.WorkDir = hostWorkDir
	}

	start := a.now()
	run, err := a.runner.Run(ctx, a.executionContext(state), &runnerReq)
	if err != nil {
		return nil, err
	}
	if run == nil {
		return nil, fmt.Errorf("claude managed agents: runner returned nil result")
	}

	result := &actuators.ExecResult{
		ExitCode:  run.ExitCode,
		Stdout:    run.Stdout,
		Stderr:    run.Stderr,
		Duration:  run.Duration,
		OOMKilled: run.OOMKilled,
		TimedOut:  run.TimedOut,
		Receipt:   actuators.ComputeReceiptFragment(req, run.Stdout, run.Stderr, ProviderID, start, state.spec, actuators.EffectExecShell),
	}
	a.appendLogs(id, start, run.Stdout, run.Stderr)
	return result, nil
}

func (a *Adapter) ReadFile(_ context.Context, id string, path string) ([]byte, error) {
	state, err := a.runningState(id)
	if err != nil {
		return nil, err
	}
	hostPath, err := a.resolvePath(state, path, false)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(hostPath)
}

func (a *Adapter) WriteFile(_ context.Context, id string, path string, data []byte) error {
	state, err := a.runningState(id)
	if err != nil {
		return err
	}
	hostPath, err := a.resolvePath(state, path, true)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(hostPath, data, 0o644)
}

func (a *Adapter) ListFiles(_ context.Context, id string, dir string) ([]actuators.FileEntry, error) {
	state, err := a.runningState(id)
	if err != nil {
		return nil, err
	}
	hostDir, err := a.resolvePath(state, dir, false)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(hostDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]actuators.FileEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, actuators.FileEntry{
			Name:    entry.Name(),
			Path:    filepath.Join(dir, entry.Name()),
			IsDir:   entry.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (a *Adapter) AllowEgress(ctx context.Context, id string, rules []actuators.EgressRule) error {
	state, err := a.runningState(id)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return nil
	}
	if state.spec.Egress.Disabled && len(state.spec.Egress.DefaultAllowlist) == 0 {
		return actuators.ErrNotSupported
	}
	for _, rule := range rules {
		if !egressRuleAllowed(rule, state.spec.Egress.DefaultAllowlist) {
			return fmt.Errorf("claude managed agents: egress rule %s denied outside sandbox grant", egressRuleKey(rule))
		}
	}
	if a.egress != nil {
		if err := a.egress.Allow(ctx, id, rules); err != nil {
			return err
		}
	}
	a.mu.Lock()
	state.egressRules = append([]actuators.EgressRule(nil), rules...)
	a.mu.Unlock()
	return nil
}

func (a *Adapter) Logs(_ context.Context, id string, opts *actuators.LogOptions) ([]actuators.LogEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	state, ok := a.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}
	logs := append([]actuators.LogEntry(nil), state.logs...)
	if opts != nil && opts.Tail > 0 && len(logs) > opts.Tail {
		logs = logs[len(logs)-opts.Tail:]
	}
	return logs, nil
}

func (a *Adapter) runningState(id string) (*sandboxState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	state, ok := a.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}
	if state.handle.Status == actuators.StatusTerminated {
		return nil, actuators.ErrSandboxTerminated
	}
	if state.handle.Status != actuators.StatusRunning {
		return nil, fmt.Errorf("claude managed agents: sandbox %q is not running", id)
	}
	return state, nil
}

func (a *Adapter) executionContext(state *sandboxState) ExecutionContext {
	return ExecutionContext{
		SandboxID:     state.handle.ID,
		WorkspaceRoot: state.workspace,
		OutputsRoot:   state.outputs,
		Spec:          state.spec,
		Metadata:      copyStringMap(state.metadata),
	}
}

func (a *Adapter) sandboxID() string {
	if a.cfg.WorkID != "" {
		return fmt.Sprintf("claude-work-%s-%d", a.cfg.WorkID, a.nextID)
	}
	if a.cfg.SessionID != "" {
		return fmt.Sprintf("claude-session-%s-%d", a.cfg.SessionID, a.nextID)
	}
	return fmt.Sprintf("claude-managed-%d", a.nextID)
}

func (a *Adapter) metadataFor(spec *actuators.SandboxSpec, workspace, outputs string) map[string]string {
	return map[string]string{
		"worker_id":           a.cfg.WorkerID,
		metadataImageDigest:   a.cfg.WorkerImageDigest,
		"skill_manifest_hash": a.cfg.SkillManifestHash,
		"agent_id":            a.cfg.AgentID,
		"agent_version":       a.cfg.AgentVersion,
		"session_id":          a.cfg.SessionID,
		"environment_id":      a.cfg.EnvironmentID,
		"work_id":             a.cfg.WorkID,
		"sandbox_spec_hash":   actuators.ComputeSandboxSpecHash(spec),
		"sandbox_grant_hash":  a.sandboxGrantHash(spec, workspace, outputs),
		"policy_epoch":        defaultPolicyEpoch,
	}
}

func (a *Adapter) sandboxGrantHash(spec *actuators.SandboxSpec, workspace, outputs string) string {
	return hashAny(struct {
		WorkerID          string `json:"worker_id"`
		WorkerImageDigest string `json:"worker_image_digest"`
		SkillManifestHash string `json:"skill_manifest_hash"`
		SandboxSpecHash   string `json:"sandbox_spec_hash"`
		WorkspaceRoot     string `json:"workspace_root"`
		OutputsRoot       string `json:"outputs_root"`
	}{
		WorkerID:          a.cfg.WorkerID,
		WorkerImageDigest: a.cfg.WorkerImageDigest,
		SkillManifestHash: a.cfg.SkillManifestHash,
		SandboxSpecHash:   actuators.ComputeSandboxSpecHash(spec),
		WorkspaceRoot:     workspace,
		OutputsRoot:       outputs,
	})
}

func (a *Adapter) appendLogs(id string, ts time.Time, stdout, stderr []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()

	state, ok := a.sandboxes[id]
	if !ok {
		return
	}
	if len(stdout) > 0 {
		state.logs = append(state.logs, actuators.LogEntry{Timestamp: ts, Stream: "stdout", Line: string(stdout)})
	}
	if len(stderr) > 0 {
		state.logs = append(state.logs, actuators.LogEntry{Timestamp: ts, Stream: "stderr", Line: string(stderr)})
	}
}

func (a *Adapter) resolvePath(state *sandboxState, sandboxPath string, forWrite bool) (string, error) {
	clean := cleanSandboxPath(sandboxPath)
	if clean == "" {
		return "", fmt.Errorf("claude managed agents: path is required")
	}
	if forWrite && !pathWritable(state.spec, clean) {
		return "", fmt.Errorf("claude managed agents: write denied outside declared writable preopens: %s", clean)
	}
	if !forWrite && !pathReadable(state.spec, clean) {
		return "", fmt.Errorf("claude managed agents: read denied outside declared preopens: %s", clean)
	}

	switch {
	case clean == "/workspace" || strings.HasPrefix(clean, "/workspace/"):
		return safeJoin(state.workspace, strings.TrimPrefix(clean, "/workspace"), forWrite)
	case clean == "/mnt/session/outputs" || strings.HasPrefix(clean, "/mnt/session/outputs/"):
		return safeJoin(state.outputs, strings.TrimPrefix(clean, "/mnt/session/outputs"), forWrite)
	case clean == "/tmp" || strings.HasPrefix(clean, "/tmp/"):
		return safeJoin(filepath.Join(state.workspace, "tmp"), strings.TrimPrefix(clean, "/tmp"), forWrite)
	default:
		return "", fmt.Errorf("claude managed agents: path %s is outside worker sandbox roots", clean)
	}
}

func cleanSandboxPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/workspace/" + path
	}
	return filepath.Clean(path)
}

func safeJoin(root, rel string, forWrite bool) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(rootAbs, 0o755); err != nil {
		return "", err
	}
	candidate := filepath.Join(rootAbs, rel)
	checkPath := candidate
	if forWrite {
		if err := os.MkdirAll(filepath.Dir(candidate), 0o755); err != nil {
			return "", err
		}
		checkPath = filepath.Dir(candidate)
	}

	rootEval, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		rootEval = rootAbs
	}
	checkEval, err := filepath.EvalSymlinks(checkPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		missingRel, relErr := filepath.Rel(rootAbs, checkPath)
		if relErr != nil {
			return "", relErr
		}
		checkEval = filepath.Join(rootEval, missingRel)
	}
	if !withinRoot(rootEval, checkEval) {
		return "", fmt.Errorf("claude managed agents: path escapes sandbox root")
	}
	if !forWrite {
		finalEval, err := filepath.EvalSymlinks(candidate)
		if err == nil && !withinRoot(rootEval, finalEval) {
			return "", fmt.Errorf("claude managed agents: path escapes sandbox root")
		}
	}
	return candidate, nil
}

func withinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func validateSandboxSpec(spec *actuators.SandboxSpec) error {
	if !spec.Egress.Disabled && len(spec.Egress.DefaultAllowlist) == 0 {
		return fmt.Errorf("claude managed agents: unrestricted egress denied; default allowlist is required when egress is enabled")
	}
	for _, rule := range spec.Egress.DefaultAllowlist {
		if egressRuleUnrestricted(rule) {
			return fmt.Errorf("claude managed agents: unrestricted egress rule %s denied", egressRuleKey(rule))
		}
	}
	for _, mount := range spec.Mounts {
		target := cleanSandboxPath(mount.Target)
		if target == "/" || target == "." {
			return fmt.Errorf("claude managed agents: broad filesystem mount target %q denied", mount.Target)
		}
		source := filepath.Clean(mount.Source)
		if source == "/" {
			return fmt.Errorf("claude managed agents: broad filesystem mount source %q denied", mount.Source)
		}
	}
	for name := range spec.Env {
		if credentialEnvName(name) {
			return fmt.Errorf("claude managed agents: secret-bearing env var %q must not be injected into worker tools", name)
		}
	}
	return nil
}

func pathReadable(spec *actuators.SandboxSpec, path string) bool {
	if len(spec.Mounts) == 0 {
		return true
	}
	for _, mount := range spec.Mounts {
		if pathWithinSandboxTarget(path, mount.Target) {
			return true
		}
	}
	return path == "/tmp" || strings.HasPrefix(path, "/tmp/")
}

func pathWritable(spec *actuators.SandboxSpec, path string) bool {
	if len(spec.Mounts) == 0 {
		return true
	}
	for _, mount := range spec.Mounts {
		if !mount.ReadOnly && pathWithinSandboxTarget(path, mount.Target) {
			return true
		}
	}
	return path == "/tmp" || strings.HasPrefix(path, "/tmp/")
}

func pathWithinSandboxTarget(path, target string) bool {
	target = cleanSandboxPath(target)
	return path == target || strings.HasPrefix(path, target+"/")
}

func egressRuleAllowed(rule actuators.EgressRule, allowed []actuators.EgressRule) bool {
	for _, candidate := range allowed {
		if egressRuleKey(rule) == egressRuleKey(candidate) {
			return true
		}
	}
	return false
}

func egressRuleUnrestricted(rule actuators.EgressRule) bool {
	host := strings.TrimSpace(strings.ToLower(rule.Host))
	return host == "" || host == "*" || host == "0.0.0.0/0" || host == "::/0" || host == "0/0"
}

func egressRuleKey(rule actuators.EgressRule) string {
	proto := rule.Protocol
	if proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%s/%s/%d", proto, rule.Host, rule.Port)
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (a *Adapter) now() time.Time {
	if a.clock == nil {
		return time.Now()
	}
	return a.clock()
}

// LocalCommandRunner executes commands directly in the worker context.
type LocalCommandRunner struct{}

func (LocalCommandRunner) Run(ctx context.Context, execCtx ExecutionContext, req *actuators.ExecRequest) (*RunnerResult, error) {
	if req == nil || len(req.Command) == 0 {
		return nil, fmt.Errorf("command is required")
	}
	env, err := commandEnvironment(execCtx, req)
	if err != nil {
		return nil, err
	}
	runCtx := ctx
	cancel := func() {}
	if req.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, req.Timeout)
	}
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(runCtx, req.Command[0], req.Command[1:]...)
	cmd.Dir = req.WorkDir
	cmd.Env = env
	if len(req.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(req.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()

	result := &RunnerResult{
		ExitCode: exitCode(err),
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: time.Since(start),
		TimedOut: runCtx.Err() == context.DeadlineExceeded,
	}
	if err != nil && !result.TimedOut && result.ExitCode == 0 {
		return nil, err
	}
	if result.TimedOut && result.ExitCode == 0 {
		result.ExitCode = -1
	}
	return result, nil
}

func commandEnvironment(execCtx ExecutionContext, req *actuators.ExecRequest) ([]string, error) {
	workspace := execCtx.WorkspaceRoot
	if workspace == "" && req != nil {
		workspace = req.WorkDir
	}
	if workspace == "" {
		workspace = os.TempDir()
	}
	tmpDir := filepath.Join(workspace, "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return nil, fmt.Errorf("create sandbox tmp dir: %w", err)
	}
	env := []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + workspace,
		"TMPDIR=" + tmpDir,
	}
	if req == nil || len(req.Env) == 0 {
		return env, nil
	}
	keys := make([]string, 0, len(req.Env))
	for key := range req.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if invalidEnvName(key) {
			return nil, fmt.Errorf("invalid env var name %q", key)
		}
		if credentialEnvName(key) {
			return nil, fmt.Errorf("secret-bearing env var %q must not be passed to worker tools", key)
		}
		env = append(env, key+"="+req.Env[key])
	}
	return env, nil
}

func invalidEnvName(name string) bool {
	return name == "" || strings.ContainsAny(name, "=\x00")
}

func credentialEnvName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	for _, marker := range []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "COOKIE", "SESSION", "PRIVATE"} {
		if upper == marker ||
			strings.HasPrefix(upper, marker+"_") ||
			strings.HasSuffix(upper, "_"+marker) ||
			strings.Contains(upper, "_"+marker+"_") {
			return true
		}
	}
	return false
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
