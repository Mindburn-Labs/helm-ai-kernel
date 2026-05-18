package session

import (
	"errors"
	"fmt"
	"os"
	"strings"

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
	if check.Type != "command" || check.Command == "" {
		return HealthcheckResult{}, fmt.Errorf("unsupported healthcheck type %q", check.Type)
	}
	if opts.RuntimeDryRun {
		return HealthcheckResult{
			Type:   "command",
			Status: "dry-run-passed",
			Metadata: map[string]any{
				"command": check.Command,
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
	handle, err := lpruntime.NewLocalContainerRuntime().Start(lpruntime.ContainerRequest{
		Plan:             compiled,
		ImageDigest:      imageRef,
		WorkspaceMount:   workspace,
		Secrets:          runtimeSecrets(compiled, opts),
		DryRun:           false,
		Command:          []string{"/bin/sh"},
		Args:             []string{"-lc", check.Command},
		NetworkAllowlist: compiled.NetworkAllowlist,
		EgressProxy:      egressProxyFromEnv(compiled.NetworkAllowlist),
		AutoCleanup:      true,
	})
	if err != nil {
		return HealthcheckResult{}, err
	}
	return HealthcheckResult{
		Type:   "command",
		Status: "passed",
		Metadata: map[string]any{
			"command":               check.Command,
			"runtime":               runtime.Runtime,
			"healthcheck_exec_id":   handle.ContainerID,
			"healthcheck_grant_ref": handle.SandboxGrantRef,
		},
	}, nil
}

func containsImageDigest(image string) bool {
	return strings.Contains(image, "@sha256:")
}
