package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
	dockersandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox/docker"
)

type LocalContainerRuntime struct {
	NetworkDefault     string
	FilesystemMode     string
	IsolationMode      string
	CommandTimeout     time.Duration
	DockerBin          string
	DockerInfoProvider DockerInfoProvider
}

type ContainerRequest struct {
	Plan             plan.LaunchPlan
	ImageDigest      string
	WorkspaceMount   string
	Secrets          map[string]string
	DryRun           bool
	Command          []string
	Args             []string
	NetworkAllowlist []string
	EgressProxy      EgressProxy
	IsolationMode    string
	TokenBroker      bool
	AutoCleanup      bool
	Privileged       bool
	RecursiveLaunch  bool
	// AdditionalMounts attaches host paths to the container in addition to
	// the canonical /workspace mount. Populated from
	// `filesystem_policy.mounts` in the AppSpec (e.g. `app_state:rw[:target]`).
	// Each entry is bind-mounted at the requested target inside the container.
	AdditionalMounts []LaunchpadMount

	// Detached marks daemon-style runs (docker run -d). When set, runtime
	// returns as soon as the container is up and the healthcheck passes
	// (or times out into REPAIR_REQUIRED), instead of blocking until the
	// container exits.
	Detached         bool
	ReadinessTimeout time.Duration
}

// LaunchpadMount is a host-to-container bind mount derived from an AppSpec
// `filesystem_policy.mounts` entry. The launchpad runner creates Source on
// the host (typically under `<launchpad_home>/state/<launch_id>/<name>/`)
// and bind-mounts it at Target inside the workload.
type LaunchpadMount struct {
	Name     string
	Source   string
	Target   string
	ReadOnly bool
}

type ContainerHandle struct {
	ContainerID       string            `json:"container_id"`
	SandboxGrantRef   string            `json:"sandbox_grant_ref"`
	EgressReceiptRef  string            `json:"egress_receipt_ref,omitempty"`
	EgressReceiptPath string            `json:"egress_receipt_path,omitempty"`
	EgressNetworkName string            `json:"egress_network_name,omitempty"`
	EgressProxyID     string            `json:"egress_proxy_id,omitempty"`
	EgressProxyName   string            `json:"egress_proxy_name,omitempty"`
	EgressProxyImage  string            `json:"egress_proxy_image,omitempty"`
	Isolation         IsolationEvidence `json:"isolation"`
	ProjectedSecrets  map[string]string `json:"projected_secrets"`
}

func NewLocalContainerRuntime() LocalContainerRuntime {
	return LocalContainerRuntime{NetworkDefault: "deny", FilesystemMode: "deny_by_default"}
}

func (r LocalContainerRuntime) Preflight(req ContainerRequest) (ContainerHandle, error) {
	if r.NetworkDefault != "deny" {
		return ContainerHandle{}, errors.New("local-container network default must be deny")
	}
	if r.FilesystemMode != "deny_by_default" {
		return ContainerHandle{}, errors.New("local-container filesystem must be deny_by_default")
	}
	if req.WorkspaceMount == "" {
		return ContainerHandle{}, errors.New("workspace mount is required")
	}
	if err := validateWorkspaceMount(req.WorkspaceMount); err != nil {
		return ContainerHandle{}, err
	}
	if req.ImageDigest == "" {
		return ContainerHandle{}, errors.New("image digest is required")
	}
	if req.Privileged {
		return ContainerHandle{}, errors.New("local-container privileged mode is denied")
	}
	if req.RecursiveLaunch || launchRecurses(req.Plan) {
		return ContainerHandle{}, errors.New("local-container recursive launch is denied")
	}
	if err := ValidateModelProviderAllowlist(req.NetworkAllowlist); err != nil {
		return ContainerHandle{}, err
	}
	if containsPrivilegeEscalation(req.Command) || containsPrivilegeEscalation(req.Args) {
		return ContainerHandle{}, errors.New("local-container privilege escalation flag is denied")
	}
	isolation, err := r.resolveIsolation(req)
	if err != nil {
		return ContainerHandle{Isolation: isolation}, err
	}
	isolation.TokenBrokerEnabled = req.TokenBroker
	return ContainerHandle{
		ContainerID:      "dryrun-" + req.Plan.LaunchID,
		SandboxGrantRef:  "sandbox-grant:" + req.Plan.SandboxProfileHash,
		Isolation:        isolation,
		ProjectedSecrets: ProjectSecrets(req.Secrets),
	}, nil
}

func (r LocalContainerRuntime) Start(req ContainerRequest) (ContainerHandle, error) {
	handle, err := r.Preflight(req)
	if err != nil {
		return handle, err
	}
	if req.DryRun {
		return handle, nil
	}
	proxyHandle := EgressProxyHandle{}
	if len(req.NetworkAllowlist) > 0 {
		if req.EgressProxy == nil {
			return handle, fmt.Errorf("local-container model provider egress requires launch-scoped egress proxy receipt")
		}
		proxyHandle, err = req.EgressProxy.Start(EgressProxyRequest{
			LaunchID:           req.Plan.LaunchID,
			Allowlist:          req.NetworkAllowlist,
			PayloadInspection:  handle.Isolation.PayloadInspection,
			NetworkProof:       handle.Isolation.NetworkProof,
			TokenBrokerEnabled: req.TokenBroker,
		})
		if err != nil {
			return handle, err
		}
		if proxyHandle.ProxyURL == "" || proxyHandle.ReceiptRef == "" {
			return handle, fmt.Errorf("local-container egress proxy did not return proxy URL and receipt ref")
		}
		handle.EgressReceiptRef = proxyHandle.ReceiptRef
		handle.EgressReceiptPath = proxyHandle.ReceiptPath
		handle.EgressNetworkName = proxyHandle.NetworkName
		handle.EgressProxyID = proxyHandle.ProxyContainerID
		handle.EgressProxyName = proxyHandle.ProxyContainerName
		handle.EgressProxyImage = proxyHandle.ProxyImage
	}
	command, args := containerCommand(req.Command, req.Args)
	env := map[string]string{}
	for key, value := range req.Secrets {
		env[key] = value
	}
	if proxyHandle.ProxyURL != "" {
		if proxyHandle.NetworkName != "" {
			env["HELM_EGRESS_TRANSPARENT"] = "1"
		} else {
			env["HTTPS_PROXY"] = proxyHandle.ProxyURL
			env["HTTP_PROXY"] = proxyHandle.ProxyURL
			env["NO_PROXY"] = "127.0.0.1,localhost"
		}
	}
	network := sandbox.NetworkPolicy{Disabled: true, EgressAllowlist: req.NetworkAllowlist}
	if proxyHandle.NetworkName != "" {
		network.Disabled = false
		network.NetworkName = proxyHandle.NetworkName
	}
	mounts := []sandbox.Mount{{
		Source:   req.WorkspaceMount,
		Target:   "/workspace",
		ReadOnly: false,
	}}
	for _, am := range req.AdditionalMounts {
		mounts = append(mounts, sandbox.Mount{
			Source:   am.Source,
			Target:   am.Target,
			ReadOnly: am.ReadOnly,
		})
		if req.Plan.StateDirEnv != "" && am.Name != "" && !strings.EqualFold(am.Name, "workspace") && env[req.Plan.StateDirEnv] == "" {
			env[req.Plan.StateDirEnv] = am.Target
		}
	}
	spec := &sandbox.SandboxSpec{
		Image:   req.ImageDigest,
		Command: command,
		Args:    args,
		Env:     env,
		Labels: map[string]string{
			"launchpad-launch-id": req.Plan.LaunchID,
			"launchpad-app-id":    req.Plan.AppID,
		},
		Mounts: mounts,
		Limits: sandbox.ResourceLimits{
			CPUMillis:    500,
			MemoryMB:     512,
			DiskMB:       1024,
			Timeout:      r.commandTimeout(req),
			MaxProcesses: 64,
		},
		Network:      network,
		WorkDir:      "/workspace",
		RuntimeClass: handle.Isolation.RuntimeClass,
		Detached:     req.Detached,
	}
	result, receipt, err := dockersandbox.NewDockerRunner().Run(spec)
	if err != nil {
		cleanupEgressProxy(proxyHandle)
		return handle, err
	}
	if !result.Success() {
		cleanupEgressProxy(proxyHandle)
		detail := redactedCommandOutput(result.Stdout, result.Stderr, req.Secrets)
		if detail != "" {
			return handle, fmt.Errorf("local-container command failed: exit=%d timed_out=%t oom=%t output=%q", result.ExitCode, result.TimedOut, result.OOMKilled, detail)
		}
		return handle, fmt.Errorf("local-container command failed: exit=%d timed_out=%t oom=%t", result.ExitCode, result.TimedOut, result.OOMKilled)
	}
	if req.AutoCleanup {
		cleanupEgressProxy(proxyHandle)
	}
	handle.ContainerID = receipt.ExecutionID
	// Daemon-style readiness: container started (docker run -d returned),
	// now poll the AppSpec healthcheck commands via `docker exec` until
	// one passes or ReadinessTimeout elapses. Failure here means the
	// daemon never came up healthy; kill the container and surface the
	// last error to the caller (translates to REPAIR_REQUIRED).
	if req.Detached {
		if err := waitForReadiness(receipt.ExecutionID, req.Plan.Healthchecks, req.ReadinessTimeout, req.Secrets); err != nil {
			_ = exec.Command("docker", "rm", "-f", receipt.ExecutionID).Run()
			cleanupEgressProxy(proxyHandle)
			return handle, fmt.Errorf("local-container daemon never became ready: %w", err)
		}
	}
	handle.Isolation.TokenBrokerEnabled = req.TokenBroker || proxyHandle.TokenBrokerEnabled
	return handle, nil
}

// projectAppStateMounts materializes the non-workspace mounts declared in
// AppSpec.FilesystemPolicy.Mounts (e.g. "app_state:rw") into actual host
// directories under ~/.helm/launchpad/state/<launch_id>/<name>/ and a
// container target at /var/lib/<app_id>/<name>. If StateDirEnv is set on
// the plan, an env var pointing at the first such mount is exported into
// the container, so apps (hermes, openclaw) can discover their state
// directory without baking the path into their YAML command.
func projectAppStateMounts(p plan.LaunchPlan) ([]sandbox.Mount, map[string]string, error) {
	if len(p.FilesystemMounts) == 0 {
		return nil, nil, nil
	}
	root, err := appStateRoot(p.LaunchID)
	if err != nil {
		return nil, nil, err
	}
	var mounts []sandbox.Mount
	var firstTarget string
	for _, raw := range p.FilesystemMounts {
		name, mode := parseFilesystemMount(raw)
		if name == "" || strings.EqualFold(name, "workspace") {
			continue
		}
		hostDir := filepath.Join(root, name)
		if err := os.MkdirAll(hostDir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create state dir for %s: %w", name, err)
		}
		// Workaround for container-side UID mismatch: kernel runs as the
		// host user (often UID 501 on macOS), apps inside the container
		// run as their own UID (hermes=999, openclaw=nonroot). Loosen
		// dir perms so the in-container user can write. Outer parent
		// (~/.helm/launchpad/) stays 0700, so this is not externally
		// reachable.
		_ = os.Chmod(hostDir, 0o777)
		target := filepath.Join("/var/lib", p.AppID, name)
		mounts = append(mounts, sandbox.Mount{
			Source:   hostDir,
			Target:   target,
			ReadOnly: !strings.EqualFold(mode, "rw"),
		})
		if firstTarget == "" {
			firstTarget = target
		}
	}
	env := map[string]string{}
	if firstTarget != "" && p.StateDirEnv != "" {
		env[p.StateDirEnv] = firstTarget
	}
	return mounts, env, nil
}

// parseFilesystemMount splits entries like "app_state:rw" into name + mode.
func parseFilesystemMount(raw string) (string, string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ""
	}
	parts := strings.SplitN(trimmed, ":", 2)
	name := strings.TrimSpace(parts[0])
	mode := "ro"
	if len(parts) == 2 {
		mode = strings.TrimSpace(parts[1])
	}
	return name, mode
}

// appStateRoot resolves ~/.helm/launchpad/state/<launch_id>/.
func appStateRoot(launchID string) (string, error) {
	if launchID == "" {
		return "", errors.New("launch id required for app state root")
	}
	if override := strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_HOME")); override != "" {
		return filepath.Join(override, "state", launchID), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".helm", "launchpad", "state", launchID), nil
}

// waitForReadiness polls the AppSpec healthcheck commands inside a detached
// container via `docker exec`, retrying with a fixed 6-second interval until
// one passes or timeout elapses. Returns nil on the first successful check.
func waitForReadiness(containerID string, checks []registry.HealthcheckSpec, timeout time.Duration, secrets map[string]string) error {
	if timeout <= 0 {
		timeout = 8 * time.Minute
	}
	if len(checks) == 0 {
		// No healthcheck declared: best-effort, just verify the container
		// is still up after a short grace period.
		time.Sleep(5 * time.Second)
		if !containerRunning(containerID) {
			return errors.New("container exited before grace period")
		}
		return nil
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if !containerRunning(containerID) {
			return errors.New("container exited during readiness wait")
		}
		for _, hc := range checks {
			cmd := strings.TrimSpace(hc.Command)
			if cmd == "" {
				continue
			}
			out, err := exec.Command("docker", "exec", containerID, "sh", "-lc", cmd).CombinedOutput()
			if err == nil {
				return nil
			}
			lastErr = fmt.Errorf("healthcheck %q failed: %v (%s)", cmd, err, strings.TrimSpace(redactedCommandOutput(out, nil, secrets)))
		}
		time.Sleep(6 * time.Second)
	}
	if lastErr == nil {
		lastErr = errors.New("readiness timeout with no successful healthcheck")
	}
	return lastErr
}

func containerRunning(containerID string) bool {
	out, err := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", containerID).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

const defaultLocalContainerCommandTimeout = 600 * time.Second

// commandTimeout resolves the per-launch container timeout. Precedence:
// explicit AppSpec runtime.timeout (req.Plan.RuntimeTimeout) → struct field
// CommandTimeout (set programmatically, e.g. by a custom substrate adapter
// or a test) → operator env HELM_LAUNCHPAD_LOCAL_CONTAINER_TIMEOUT → default
// 120s. Yaml wins because the AppSpec author knows the app's warm-up profile;
// env stays as a deployment-wide escape hatch when no spec/field is set.
func (r LocalContainerRuntime) commandTimeout(req ContainerRequest) time.Duration {
	if raw := strings.TrimSpace(req.Plan.RuntimeTimeout); raw != "" {
		if timeout, err := time.ParseDuration(raw); err == nil && timeout > 0 {
			return timeout
		}
	}
	if r.CommandTimeout > 0 {
		return r.CommandTimeout
	}
	if raw := strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_LOCAL_CONTAINER_TIMEOUT")); raw != "" {
		if timeout, err := time.ParseDuration(raw); err == nil && timeout > 0 {
			return timeout
		}
	}
	return defaultLocalContainerCommandTimeout
}

func (r LocalContainerRuntime) resolveIsolation(req ContainerRequest) (IsolationEvidence, error) {
	mode := r.IsolationMode
	if req.IsolationMode != "" {
		mode = req.IsolationMode
	}
	dockerBin := strings.TrimSpace(r.DockerBin)
	if dockerBin == "" {
		dockerBin = "docker"
	}
	return ResolveIsolationProfile(mode, dockerBin, r.DockerInfoProvider)
}

func containerCommand(command, args []string) ([]string, []string) {
	if len(command) > 0 {
		return append([]string{}, command...), append([]string{}, args...)
	}
	if len(args) > 0 {
		return []string{"/bin/sh"}, append([]string{}, args...)
	}
	return []string{"/bin/sh"}, []string{"-lc", "true"}
}

func redactedCommandOutput(stdout, stderr []byte, secrets map[string]string) string {
	combined := strings.TrimSpace(string(append(append([]byte{}, stdout...), stderr...)))
	if combined == "" {
		return ""
	}
	for _, value := range secrets {
		if value != "" {
			combined = strings.ReplaceAll(combined, value, "[REDACTED]")
		}
	}
	const maxDetail = 2048
	if len(combined) > maxDetail {
		combined = "...[truncated]\n" + combined[len(combined)-maxDetail:]
	}
	return combined
}

func cleanupEgressProxy(proxyHandle EgressProxyHandle) {
	if proxyHandle.Stop != nil {
		_ = proxyHandle.Stop()
	}
}

func validateWorkspaceMount(mount string) error {
	clean := filepath.Clean(mount)
	if clean != mount {
		return errors.New("workspace mount must be canonical")
	}
	if !filepath.IsAbs(clean) {
		return errors.New("workspace mount must be absolute")
	}
	if clean == string(filepath.Separator) {
		return errors.New("workspace mount cannot be host root")
	}
	if runtime.GOOS != "windows" {
		for _, protected := range []string{"/bin", "/boot", "/dev", "/etc", "/proc", "/root", "/sbin", "/sys", "/usr"} {
			if clean == protected || strings.HasPrefix(clean, protected+"/") {
				return errors.New("workspace mount escapes allowed host workspace")
			}
		}
		for _, socket := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
			if clean == socket {
				return errors.New("workspace mount cannot bind host container socket")
			}
		}
	}
	return nil
}

func launchRecurses(p plan.LaunchPlan) bool {
	if p.Nodes == nil {
		return false
	}
	value, ok := p.Nodes["recursive_launch"]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true")
	default:
		return false
	}
}

func containsPrivilegeEscalation(values []string) bool {
	for _, value := range values {
		switch {
		case value == "--privileged":
			return true
		case strings.HasPrefix(value, "--cap-add"):
			return true
		case strings.HasPrefix(value, "--security-opt"):
			return true
		case strings.Contains(value, "/var/run/docker.sock"):
			return true
		case strings.Contains(value, "/run/docker.sock"):
			return true
		}
	}
	return false
}
