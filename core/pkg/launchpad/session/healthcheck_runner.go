package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	lpruntime "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/runtime"
)

type HealthcheckResult struct {
	Type     string         `json:"type"`
	Status   string         `json:"status"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type HealthcheckRunner interface {
	Run(plan.LaunchPlan, RuntimeStartResult, ExecuteOptions) (HealthcheckResult, error)
}

type DefaultHealthcheckRunner struct{}

func (DefaultHealthcheckRunner) Run(compiled plan.LaunchPlan, runtime RuntimeStartResult, opts ExecuteOptions) (HealthcheckResult, error) {
	if runtime.ContainerID == "" || runtime.SandboxGrantRef == "" {
		return HealthcheckResult{}, errors.New("healthcheck requires runtime container and sandbox grant refs")
	}
	if len(compiled.Healthchecks) == 0 {
		return HealthcheckResult{}, errors.New("healthcheck spec is required before RUNNING")
	}
	check := compiled.Healthchecks[0]

	switch check.Type {
	case "command":
		if check.Command == "" {
			return HealthcheckResult{}, errors.New("command healthcheck requires command")
		}
		if isCloudRuntime(runtime.Runtime) && !opts.RuntimeDryRun {
			return HealthcheckResult{}, errors.New("cloud command healthcheck requires remote command runner or http readiness probe before RUNNING")
		}
		return runCommandHealthcheck(compiled, runtime, opts, check.Command)
	case "http":
		return runHTTPHealthcheck(compiled, runtime, opts, check.URL)
	default:
		return HealthcheckResult{}, fmt.Errorf("unsupported healthcheck type %q", check.Type)
	}
}

func runHTTPHealthcheck(compiled plan.LaunchPlan, runtime RuntimeStartResult, opts ExecuteOptions, rawURL string) (HealthcheckResult, error) {
	probeURL, err := validateHealthcheckURL(rawURL)
	if err != nil {
		return HealthcheckResult{}, err
	}
	// Host-side probes must obey the same egress policy the sandboxed
	// command path enforces: loopback (the launched container's published
	// ports) is always reachable; anything else must be in the plan's
	// network allowlist. Deny-by-default, even on dry runs — a dry run must
	// not validate a plan that enforcement would reject.
	if err := enforceHealthcheckEgress(probeURL, compiled.NetworkAllowlist); err != nil {
		return HealthcheckResult{}, err
	}
	if opts.RuntimeDryRun {
		return HealthcheckResult{
			Type:   "http",
			Status: "dry-run-passed",
			Metadata: map[string]any{
				"runtime": runtime.Runtime,
				"url":     probeURL,
			},
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return HealthcheckResult{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return HealthcheckResult{}, fmt.Errorf("http healthcheck failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		return HealthcheckResult{}, fmt.Errorf("http healthcheck returned status %d", resp.StatusCode)
	}
	return HealthcheckResult{
		Type:   "http",
		Status: "passed",
		Metadata: map[string]any{
			"runtime":     runtime.Runtime,
			"url":         probeURL,
			"status_code": resp.StatusCode,
		},
	}, nil
}

func runCommandHealthcheck(compiled plan.LaunchPlan, runtime RuntimeStartResult, opts ExecuteOptions, command string) (HealthcheckResult, error) {
	if opts.RuntimeDryRun {
		return HealthcheckResult{
			Type:   "command",
			Status: "dry-run-passed",
			Metadata: map[string]any{
				"command": command,
				"runtime": runtime.Runtime,
			},
		}, nil
	}
	imageRef := compiled.ArtifactImage
	if imageRef == "" {
		return HealthcheckResult{}, errors.New("artifact image is required for command healthcheck")
	}
	if compiled.ArtifactDigest != "" && !containsImageDigest(imageRef) {
		imageRef = imageRef + "@" + compiled.ArtifactDigest
	}
	workspace := opts.WorkspaceMount
	if workspace == "" {
		wd, err := os.Getwd()
		if err != nil {
			return HealthcheckResult{}, err
		}
		workspace = wd
	}
	egressProxy, err := egressProxyFromEnv(compiled.SubstrateID, compiled.NetworkAllowlist)
	if err != nil {
		return HealthcheckResult{}, err
	}
	handle, err := lpruntime.NewLocalContainerRuntime().Start(lpruntime.ContainerRequest{
		Plan:             compiled,
		ImageDigest:      imageRef,
		WorkspaceMount:   workspace,
		Secrets:          runtimeSecrets(compiled, opts),
		DryRun:           false,
		Command:          []string{"/bin/sh"},
		Args:             []string{"-lc", command},
		NetworkAllowlist: compiled.NetworkAllowlist,
		EgressProxy:      egressProxy,
		AutoCleanup:      true,
	})
	if err != nil {
		return HealthcheckResult{}, err
	}
	return HealthcheckResult{
		Type:   "command",
		Status: "passed",
		Metadata: map[string]any{
			"command":               command,
			"runtime":               runtime.Runtime,
			"healthcheck_exec_id":   handle.ContainerID,
			"healthcheck_grant_ref": handle.SandboxGrantRef,
		},
	}, nil
}

// enforceHealthcheckEgress applies the plan's egress policy to host-side HTTP
// probes. Loopback hosts are always allowed; every other origin must match an
// entry in the plan's NetworkAllowlist (scheme://host[:port], matched with and
// without the port). Fail-closed: an empty allowlist denies all non-loopback
// probes.
func enforceHealthcheckEgress(probeURL string, allowlist []string) error {
	parsed, err := url.Parse(probeURL)
	if err != nil {
		return fmt.Errorf("invalid http healthcheck url %q", probeURL)
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	// Allowlist entries appear both as origins (https://host[:port]) and as
	// bare host[:port] pairs; match the probe against every equivalent form.
	probeForms := []string{
		parsed.Scheme + "://" + parsed.Host,
		parsed.Scheme + "://" + host,
		parsed.Host,
		host,
	}
	for _, allowed := range allowlist {
		candidate := strings.TrimRight(strings.TrimSpace(allowed), "/")
		if candidate == "" {
			continue
		}
		for _, form := range probeForms {
			if strings.EqualFold(candidate, form) {
				return nil
			}
		}
	}
	return fmt.Errorf("http healthcheck url %q is outside the plan network allowlist; host egress is deny-by-default", probeURL)
}

func validateHealthcheckURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", errors.New("http healthcheck requires url")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid http healthcheck url %q", rawURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported healthcheck url scheme %q", parsed.Scheme)
	}
	return parsed.String(), nil
}

func isCloudRuntime(runtime string) bool {
	switch strings.ToLower(strings.TrimSpace(runtime)) {
	case "digitalocean", "hetzner", "e2b", "daytona":
		return true
	default:
		return false
	}
}

func containsImageDigest(image string) bool {
	return strings.Contains(image, "@sha256:")
}
