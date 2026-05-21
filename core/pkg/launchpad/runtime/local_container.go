package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
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
}

type ContainerHandle struct {
	ContainerID       string            `json:"container_id"`
	SandboxGrantRef   string            `json:"sandbox_grant_ref"`
	EgressReceiptRef  string            `json:"egress_receipt_ref,omitempty"`
	EgressNetworkName string            `json:"egress_network_name,omitempty"`
	EgressProxyID     string            `json:"egress_proxy_id,omitempty"`
	EgressProxyName   string            `json:"egress_proxy_name,omitempty"`
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
	if err := ValidateOpenRouterAllowlist(req.NetworkAllowlist); err != nil {
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
			return handle, fmt.Errorf("local-container OpenRouter egress requires launch-scoped egress proxy receipt")
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
	}
	command, args := containerCommand(req.Command, req.Args)
	env := map[string]string{}
	for key, value := range req.Secrets {
		env[key] = value
	}
	if proxyHandle.ProxyURL != "" {
		env["HTTPS_PROXY"] = proxyHandle.ProxyURL
		env["HTTP_PROXY"] = proxyHandle.ProxyURL
		env["NO_PROXY"] = "127.0.0.1,localhost"
	}
	network := sandbox.NetworkPolicy{Disabled: true, EgressAllowlist: req.NetworkAllowlist}
	if proxyHandle.NetworkName != "" {
		network.Disabled = false
		network.NetworkName = proxyHandle.NetworkName
	}
	spec := &sandbox.SandboxSpec{
		Image:   req.ImageDigest,
		Command: command,
		Args:    args,
		Env:     env,
		Mounts: []sandbox.Mount{{
			Source:   req.WorkspaceMount,
			Target:   "/workspace",
			ReadOnly: false,
		}},
		Limits: sandbox.ResourceLimits{
			CPUMillis:    500,
			MemoryMB:     512,
			DiskMB:       1024,
			Timeout:      r.commandTimeout(),
			MaxProcesses: 64,
		},
		Network:      network,
		WorkDir:      "/workspace",
		RuntimeClass: handle.Isolation.RuntimeClass,
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
	handle.EgressReceiptRef = proxyHandle.ReceiptRef
	handle.EgressNetworkName = proxyHandle.NetworkName
	handle.EgressProxyID = proxyHandle.ProxyContainerID
	handle.EgressProxyName = proxyHandle.ProxyContainerName
	handle.Isolation.TokenBrokerEnabled = req.TokenBroker || proxyHandle.TokenBrokerEnabled
	return handle, nil
}

const defaultLocalContainerCommandTimeout = 120 * time.Second

func (r LocalContainerRuntime) commandTimeout() time.Duration {
	if r.CommandTimeout > 0 {
		return r.CommandTimeout
	}
	raw := strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_LOCAL_CONTAINER_TIMEOUT"))
	if raw == "" {
		return defaultLocalContainerCommandTimeout
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout <= 0 {
		return defaultLocalContainerCommandTimeout
	}
	return timeout
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
