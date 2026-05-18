package session

import (
	"errors"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	lpruntime "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/runtime"
)

type DefaultRuntimeStarter struct{}

func (DefaultRuntimeStarter) Start(compiled plan.LaunchPlan, opts ExecuteOptions) (RuntimeStartResult, error) {
	if compiled.SubstrateID != "local-container" {
		return RuntimeStartResult{}, errors.New("default runtime starter only supports local-container")
	}
	imageRef := compiled.ArtifactImage
	if imageRef == "" {
		return RuntimeStartResult{}, errors.New("artifact image is required for local-container runtime")
	}
	if compiled.ArtifactDigest == "" {
		return RuntimeStartResult{}, errors.New("artifact digest is required for local-container runtime")
	}
	if !strings.Contains(imageRef, "@sha256:") {
		imageRef = strings.TrimSuffix(imageRef, ":latest") + "@" + compiled.ArtifactDigest
	}
	workspace := opts.WorkspaceMount
	if workspace == "" {
		wd, err := os.Getwd()
		if err != nil {
			return RuntimeStartResult{}, err
		}
		workspace = wd
	}
	secrets := map[string]string{}
	for _, envName := range compiled.ModelGatewayEnv {
		if value := opts.RuntimeSecretEnv[envName]; value != "" {
			secrets[envName] = value
			continue
		}
		if value, ok := os.LookupEnv(envName); ok && value != "" {
			secrets[envName] = value
		}
	}
	var egressProxy lpruntime.EgressProxy
	if proxyURL := os.Getenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL"); proxyURL != "" {
		egressProxy = lpruntime.StaticEgressProxy{
			ProxyURL:   proxyURL,
			ReceiptRef: os.Getenv("HELM_LAUNCHPAD_EGRESS_PROXY_RECEIPT_REF"),
		}
	}
	handle, err := lpruntime.NewLocalContainerRuntime().Start(lpruntime.ContainerRequest{
		Plan:             compiled,
		ImageDigest:      imageRef,
		WorkspaceMount:   workspace,
		Secrets:          secrets,
		DryRun:           opts.RuntimeDryRun,
		Command:          compiled.RuntimeCommand,
		NetworkAllowlist: compiled.NetworkAllowlist,
		EgressProxy:      egressProxy,
	})
	if err != nil {
		return RuntimeStartResult{}, err
	}
	return RuntimeStartResult{
		ContainerID:      handle.ContainerID,
		SandboxGrantRef:  handle.SandboxGrantRef,
		EgressReceiptRef: handle.EgressReceiptRef,
		Runtime:          "local-container",
	}, nil
}
