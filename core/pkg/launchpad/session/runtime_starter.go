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
	secrets := runtimeSecrets(compiled, opts)
	egressProxy := egressProxyFromEnv(compiled.NetworkAllowlist)
	runtime := lpruntime.NewLocalContainerRuntime()
	runtime.IsolationMode = isolationModeFromEnv()
	handle, err := runtime.Start(lpruntime.ContainerRequest{
		Plan:             compiled,
		ImageDigest:      imageRef,
		WorkspaceMount:   workspace,
		Secrets:          secrets,
		DryRun:           opts.RuntimeDryRun,
		Command:          compiled.RuntimeCommand,
		NetworkAllowlist: compiled.NetworkAllowlist,
		EgressProxy:      egressProxy,
		TokenBroker:      compiled.ModelGatewayMode == "token_broker",
	})
	if err != nil {
		result := runtimeStartResultFromHandle(handle)
		if result.IsolationMode == "" {
			if evidence, ok := lpruntime.IsolationEvidenceFromError(err); ok {
				result = runtimeStartResultFromIsolation(evidence)
			}
		}
		return result, err
	}
	return runtimeStartResultFromHandle(handle), nil
}

func runtimeStartResultFromHandle(handle lpruntime.ContainerHandle) RuntimeStartResult {
	result := runtimeStartResultFromIsolation(handle.Isolation)
	result.ContainerID = handle.ContainerID
	result.SandboxGrantRef = handle.SandboxGrantRef
	result.EgressReceiptRef = handle.EgressReceiptRef
	result.EgressNetworkName = handle.EgressNetworkName
	result.EgressProxyID = handle.EgressProxyID
	result.EgressProxyName = handle.EgressProxyName
	return result
}

func runtimeStartResultFromIsolation(isolation lpruntime.IsolationEvidence) RuntimeStartResult {
	return RuntimeStartResult{
		Runtime:                    "local-container",
		IsolationMode:              isolation.Mode,
		IsolationHardened:          isolation.Hardened,
		IsolationDetectionStatus:   isolation.DetectionStatus,
		IsolationUnsupportedReason: isolation.UnsupportedReason,
		RuntimeClass:               isolation.RuntimeClass,
		DockerRootless:             isolation.DockerRootless,
		DockerUserns:               isolation.DockerUserns,
		DockerECI:                  isolation.DockerECI,
		DedicatedVM:                isolation.DedicatedVM,
		DockerRuntimes:             append([]string{}, isolation.DockerRuntimes...),
		DefaultRuntime:             isolation.DefaultRuntime,
		HostileAgentGrade:          isolation.HostileAgentGrade,
		PayloadInspection:          isolation.PayloadInspection,
		NetworkProof:               isolation.NetworkProof,
		TokenBrokerEnabled:         isolation.TokenBrokerEnabled,
	}
}

func egressProxyFromEnv(allowlist []string) lpruntime.EgressProxy {
	var egressProxy lpruntime.EgressProxy
	if proxyURL := os.Getenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL"); proxyURL != "" {
		egressProxy = lpruntime.StaticEgressProxy{
			ProxyURL:   proxyURL,
			ReceiptRef: os.Getenv("HELM_LAUNCHPAD_EGRESS_PROXY_RECEIPT_REF"),
		}
	} else if proxyImage := os.Getenv("HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE"); proxyImage != "" {
		egressProxy = lpruntime.DockerSidecarEgressProxy{
			Image:      proxyImage,
			ReceiptDir: os.Getenv("HELM_LAUNCHPAD_EGRESS_RECEIPT_DIR"),
		}
	} else if len(allowlist) > 0 {
		proxy := lpruntime.NewLaunchOwnedEgressProxy()
		if receiptDir := os.Getenv("HELM_LAUNCHPAD_EGRESS_RECEIPT_DIR"); receiptDir != "" {
			proxy.ReceiptDir = receiptDir
		}
		egressProxy = proxy
	}
	return egressProxy
}

func runtimeSecrets(compiled plan.LaunchPlan, opts ExecuteOptions) map[string]string {
	secrets := map[string]string{}
	if compiled.ModelGatewayMode == "token_broker" {
		if value := opts.RuntimeSecretEnv["HELM_MODEL_GATEWAY_TOKEN"]; value != "" {
			secrets["HELM_MODEL_GATEWAY_TOKEN"] = value
		} else if value, ok := os.LookupEnv("HELM_MODEL_GATEWAY_TOKEN"); ok && value != "" {
			secrets["HELM_MODEL_GATEWAY_TOKEN"] = value
		}
		if value := opts.RuntimeSecretEnv["HELM_MODEL_GATEWAY_URL"]; value != "" {
			secrets["HELM_MODEL_GATEWAY_URL"] = value
		} else if value, ok := os.LookupEnv("HELM_MODEL_GATEWAY_URL"); ok && value != "" {
			secrets["HELM_MODEL_GATEWAY_URL"] = value
		}
		return secrets
	}
	for _, envName := range compiled.ModelGatewayEnv {
		if value := opts.RuntimeSecretEnv[envName]; value != "" {
			secrets[envName] = value
			continue
		}
		if value, ok := os.LookupEnv(envName); ok && value != "" {
			secrets[envName] = value
		}
	}
	return secrets
}

func isolationModeFromEnv() string {
	return lpruntime.ResolveIsolationMode(os.Getenv("HELM_LAUNCHPAD_ISOLATION_MODE"))
}
