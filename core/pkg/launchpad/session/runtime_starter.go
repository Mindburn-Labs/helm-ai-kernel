package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/daytona"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/e2b"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	lpprovision "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/provision"
	lpruntime "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/runtime"
)

type DefaultRuntimeStarter struct{}

func (DefaultRuntimeStarter) Start(compiled plan.LaunchPlan, opts ExecuteOptions) (RuntimeStartResult, error) {
	if compiled.SubstrateID == "digitalocean" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		token := firstEnv("DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_TOKEN")
		if token == "" {
			return RuntimeStartResult{}, fmt.Errorf("digitalocean token required")
		}
		name := cloudResourceName(compiled)
		provisioner := lpprovision.DigitalOceanProvisioner{
			AllowLiveWrites: !opts.RuntimeDryRun,
			DryRun:          opts.RuntimeDryRun,
			Token:           token,
			Endpoint:        os.Getenv("HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT"),
		}
		result, err := provisioner.Create(ctx, lpprovision.DigitalOceanProvisionRequest{
			LaunchID:     compiled.LaunchID,
			PlanHash:     compiled.PlanHash,
			Name:         name,
			Region:       firstEnvValue("HELM_LAUNCHPAD_DO_REGION", "nyc3"),
			Size:         firstEnvValue("HELM_LAUNCHPAD_DO_SIZE", "s-1vcpu-1gb"),
			Image:        firstEnvValue("HELM_LAUNCHPAD_DO_IMAGE", "ubuntu-24-04-x64"),
			Tags:         cloudTags(compiled, "no-approval"),
			FirewallName: name + "-firewall",
		})
		if err != nil {
			return RuntimeStartResult{}, err
		}
		sandboxGrant := "receipt:digitalocean:" + compiled.LaunchID + ":sandbox"
		if len(result.ReceiptRefs) > 0 {
			sandboxGrant = result.ReceiptRefs[0]
		}
		egressRef := "receipt:digitalocean:" + compiled.LaunchID + ":egress"
		if len(result.ReceiptRefs) > 1 {
			egressRef = result.ReceiptRefs[1]
		} else if len(result.ReceiptRefs) > 0 {
			egressRef = result.ReceiptRefs[0]
		}
		containerID := strconv.FormatInt(result.DropletID, 10)
		if containerID == "0" {
			containerID = "dry-run-droplet"
		}
		resRefs := make(map[string]string)
		for k, v := range result.ResourceRefs {
			resRefs[k] = v
		}
		resRefs["provider"] = "digitalocean"

		return RuntimeStartResult{
			Runtime:            "digitalocean",
			ContainerID:        containerID,
			SandboxGrantRef:    sandboxGrant,
			EgressReceiptRef:   egressRef,
			CloudResourceIDs:   resRefs,
			IsolationMode:      "dedicated-vm",
			IsolationHardened:  true,
			RuntimeClass:       "provider-vm",
			DedicatedVM:        true,
			TokenBrokerEnabled: false,
		}, nil
	}

	if compiled.SubstrateID == "hetzner" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		token := firstEnv("HCLOUD_TOKEN", "HELM_LAUNCHPAD_HETZNER_TOKEN")
		if token == "" {
			return RuntimeStartResult{}, fmt.Errorf("hetzner token required")
		}
		name := cloudResourceName(compiled)
		provisioner := lpprovision.HetznerProvisioner{
			AllowLiveWrites: !opts.RuntimeDryRun,
			DryRun:          opts.RuntimeDryRun,
			Token:           token,
			Endpoint:        os.Getenv("HELM_LAUNCHPAD_HETZNER_ENDPOINT"),
		}
		result, err := provisioner.Create(ctx, lpprovision.HetznerProvisionRequest{
			LaunchID:     compiled.LaunchID,
			PlanHash:     compiled.PlanHash,
			Name:         name,
			Location:     firstEnvValue("HELM_LAUNCHPAD_HETZNER_LOCATION", "nbg1"),
			ServerType:   firstEnvValue("HELM_LAUNCHPAD_HETZNER_SERVER_TYPE", "cx22"),
			Image:        firstEnvValue("HELM_LAUNCHPAD_HETZNER_IMAGE", "ubuntu-24.04"),
			Labels:       cloudLabels(compiled, "no-approval", 0.0),
			FirewallName: name + "-firewall",
		})
		if err != nil {
			return RuntimeStartResult{}, err
		}
		sandboxGrant := "receipt:hetzner:" + compiled.LaunchID + ":sandbox"
		if len(result.ReceiptRefs) > 0 {
			sandboxGrant = result.ReceiptRefs[0]
		}
		egressRef := "receipt:hetzner:" + compiled.LaunchID + ":egress"
		if len(result.ReceiptRefs) > 1 {
			egressRef = result.ReceiptRefs[1]
		} else if len(result.ReceiptRefs) > 0 {
			egressRef = result.ReceiptRefs[0]
		}
		containerID := strconv.FormatInt(result.ServerID, 10)
		if containerID == "0" {
			containerID = "dry-run-server"
		}
		resRefs := make(map[string]string)
		for k, v := range result.ResourceRefs {
			resRefs[k] = v
		}
		resRefs["provider"] = "hetzner"

		return RuntimeStartResult{
			Runtime:            "hetzner",
			ContainerID:        containerID,
			SandboxGrantRef:    sandboxGrant,
			EgressReceiptRef:   egressRef,
			CloudResourceIDs:   resRefs,
			IsolationMode:      "dedicated-vm",
			IsolationHardened:  true,
			RuntimeClass:       "provider-vm",
			DedicatedVM:        true,
			TokenBrokerEnabled: false,
		}, nil
	}

	if compiled.SubstrateID == "e2b" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		apiKey := firstEnv("E2B_API_KEY", "HELM_LAUNCHPAD_E2B_API_KEY")
		if apiKey == "" && !opts.RuntimeDryRun {
			return RuntimeStartResult{}, fmt.Errorf("e2b api key required")
		}
		apiURL := firstEnvValue("HELM_LAUNCHPAD_E2B_API_URL", "https://api.e2b.dev")

		resRefs := map[string]string{
			"provider": "e2b",
		}

		if opts.RuntimeDryRun {
			return RuntimeStartResult{
				Runtime:            "e2b",
				ContainerID:        "dry-run-e2b-sandbox",
				SandboxGrantRef:    "receipt:e2b:" + compiled.LaunchID + ":sandbox-dry-run",
				EgressReceiptRef:   "receipt:e2b:" + compiled.LaunchID + ":egress-dry-run",
				CloudResourceIDs:   resRefs,
				IsolationMode:      "dedicated-vm",
				IsolationHardened:  true,
				RuntimeClass:       "hosted-sandbox",
				DedicatedVM:        true,
				TokenBrokerEnabled: false,
			}, nil
		}

		cfg := e2b.DefaultConfig()
		cfg.APIKey = apiKey
		cfg.APIURL = apiURL
		if compiled.ArtifactImage != "" {
			cfg.TemplateID = compiled.ArtifactImage
		}
		adapter := e2b.New(cfg)

		spec := &actuators.SandboxSpec{
			Runtime: "default",
		}

		handle, err := adapter.Create(ctx, spec)
		if err != nil {
			return RuntimeStartResult{}, err
		}

		resRefs["sandbox_id"] = handle.ID
		return RuntimeStartResult{
			Runtime:            "e2b",
			ContainerID:        handle.ID,
			SandboxGrantRef:    "receipt:e2b:" + compiled.LaunchID + ":sandbox",
			EgressReceiptRef:   "receipt:e2b:" + compiled.LaunchID + ":egress",
			CloudResourceIDs:   resRefs,
			IsolationMode:      "dedicated-vm",
			IsolationHardened:  true,
			RuntimeClass:       "hosted-sandbox",
			DedicatedVM:        true,
			TokenBrokerEnabled: false,
		}, nil
	}

	if compiled.SubstrateID == "daytona" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		apiKey := firstEnv("DAYTONA_API_KEY", "HELM_LAUNCHPAD_DAYTONA_API_KEY")
		if apiKey == "" && !opts.RuntimeDryRun {
			return RuntimeStartResult{}, fmt.Errorf("daytona api key required")
		}
		baseURL := firstEnvValue("HELM_LAUNCHPAD_DAYTONA_BASE_URL", "https://api.daytona.io")

		resRefs := map[string]string{
			"provider": "daytona",
		}

		if opts.RuntimeDryRun {
			return RuntimeStartResult{
				Runtime:            "daytona",
				ContainerID:        "dry-run-daytona-sandbox",
				SandboxGrantRef:    "receipt:daytona:" + compiled.LaunchID + ":sandbox-dry-run",
				EgressReceiptRef:   "receipt:daytona:" + compiled.LaunchID + ":egress-dry-run",
				CloudResourceIDs:   resRefs,
				IsolationMode:      "dedicated-vm",
				IsolationHardened:  true,
				RuntimeClass:       "hosted-sandbox",
				DedicatedVM:        true,
				TokenBrokerEnabled: false,
			}, nil
		}

		cfg := daytona.DefaultConfig()
		cfg.APIKey = apiKey
		cfg.BaseURL = baseURL
		if compiled.ArtifactImage != "" {
			cfg.DefaultLanguage = compiled.ArtifactImage
		}
		adapter := daytona.New(cfg)

		spec := &actuators.SandboxSpec{
			Runtime: "default",
		}

		handle, err := adapter.Create(ctx, spec)
		if err != nil {
			return RuntimeStartResult{}, err
		}

		resRefs["sandbox_id"] = handle.ID
		return RuntimeStartResult{
			Runtime:            "daytona",
			ContainerID:        handle.ID,
			SandboxGrantRef:    "receipt:daytona:" + compiled.LaunchID + ":sandbox",
			EgressReceiptRef:   "receipt:daytona:" + compiled.LaunchID + ":egress",
			CloudResourceIDs:   resRefs,
			IsolationMode:      "dedicated-vm",
			IsolationHardened:  true,
			RuntimeClass:       "hosted-sandbox",
			DedicatedVM:        true,
			TokenBrokerEnabled: false,
		}, nil
	}

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
	egressProxy, err := egressProxyFromEnv(compiled.SubstrateID, compiled.NetworkAllowlist)
	if err != nil && !opts.RuntimeDryRun {
		return RuntimeStartResult{}, err
	}
	runtime := lpruntime.NewLocalContainerRuntime()
	runtime.IsolationMode = isolationModeFromEnv()
	readiness, _ := time.ParseDuration(compiled.RuntimeReadinessTimeout)
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
		Detached:         compiled.RuntimeDetached,
		ReadinessTimeout: readiness,
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

// substratesWithNetworkNamespace lists substrates whose workloads run in an
// isolated network namespace where host-loopback proxies are unreachable.
// For these, the LaunchOwnedEgressProxy default (listening on 127.0.0.1)
// cannot serve the workload and silently produces curl exit 7 / HTTP 000
// from inside the container — which then masquerades as an OpenRouter key
// failure. Refuse the combination at start time with a clear remediation.
var substratesWithNetworkNamespace = map[string]bool{
	"local-container": true,
}

func egressProxyFromEnv(substrateID string, allowlist []string) (lpruntime.EgressProxy, error) {
	if proxyURL := os.Getenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL"); proxyURL != "" {
		return lpruntime.StaticEgressProxy{
			ProxyURL:   proxyURL,
			ReceiptRef: os.Getenv("HELM_LAUNCHPAD_EGRESS_PROXY_RECEIPT_REF"),
		}, nil
	}
	if proxyImage := os.Getenv("HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE"); proxyImage != "" {
		return lpruntime.DockerSidecarEgressProxy{
			Image:      proxyImage,
			ReceiptDir: os.Getenv("HELM_LAUNCHPAD_EGRESS_RECEIPT_DIR"),
		}, nil
	}
	if len(allowlist) == 0 {
		return nil, nil
	}
	if substratesWithNetworkNamespace[substrateID] {
		return nil, fmt.Errorf(
			"egress proxy required for %q substrate with non-empty network allowlist: "+
				"set HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE=<sha256-pinned image> to run a docker sidecar proxy, "+
				"or HELM_LAUNCHPAD_EGRESS_PROXY_URL=<http://host:port> for an external proxy. "+
				"The default loopback-listening proxy is unreachable from the container network namespace",
			substrateID,
		)
	}
	proxy := lpruntime.NewLaunchOwnedEgressProxy()
	if receiptDir := os.Getenv("HELM_LAUNCHPAD_EGRESS_RECEIPT_DIR"); receiptDir != "" {
		proxy.ReceiptDir = receiptDir
	}
	return proxy, nil
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

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func firstEnvValue(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func cloudResourceName(compiled plan.LaunchPlan) string {
	id := strings.ToLower(strings.ReplaceAll(compiled.LaunchID, "_", "-"))
	if len(id) > 36 {
		id = id[:36]
	}
	return "helm-launchpad-" + id
}

func cloudTags(compiled plan.LaunchPlan, approvalID string) []string {
	return []string{
		"helm-launchpad-app-" + compiled.AppID,
		"helm-launchpad-substrate-" + compiled.SubstrateID,
		"helm-launchpad-approval-" + sanitizeCloudTag(approvalID),
	}
}

func cloudLabels(compiled plan.LaunchPlan, approvalID string, costCeiling float64) []string {
	return []string{
		"helm-launchpad-app=" + sanitizeCloudTag(compiled.AppID),
		"helm-launchpad-substrate=" + sanitizeCloudTag(compiled.SubstrateID),
		"helm-launchpad-approval=" + sanitizeCloudTag(approvalID),
		"helm-launchpad-cost-ceiling-usd=" + sanitizeCloudTag(fmt.Sprintf("%.2f", costCeiling)),
	}
}

func sanitizeCloudTag(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(" ", "-", "/", "-", ":", "-", "@", "-", ".", "-")
	value = replacer.Replace(value)
	if value == "" {
		return "unset"
	}
	if len(value) > 48 {
		return value[:48]
	}
	return value
}
