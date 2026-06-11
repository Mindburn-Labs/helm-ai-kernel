package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/daytona"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/e2b"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/modelproviders"
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
		cfg.AllowInsecureLoopback = allowInsecureLoopbackSandboxAPI()
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
		cfg.AllowInsecureLoopback = allowInsecureLoopbackSandboxAPI()
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
	additionalMounts, err := materializeFilesystemMounts(compiled, opts)
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
		AdditionalMounts: additionalMounts,
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
	result.EgressReceiptPath = handle.EgressReceiptPath
	result.EgressNetworkName = handle.EgressNetworkName
	result.EgressProxyID = handle.EgressProxyID
	result.EgressProxyName = handle.EgressProxyName
	result.EgressProxyImage = handle.EgressProxyImage
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

// launchpadStateRoot resolves the host directory under which per-launch
// state mounts (`<root>/state/<launch_id>/<name>/`) are materialized.
// Mirrors the resolution rule in services.go::launchpadStoreRoot so a
// session package consumer does not have to depend on the cmd/ wiring.
func launchpadStateRoot() string {
	if v := strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_HOME")); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".helm", "launchpad")
}

// parsedMount represents an AppSpec `filesystem_policy.mounts` entry in the
// supported `<name>[:<mode>[:<target>]]` syntax. `mode` defaults to "rw" and
// `target` defaults to `/var/lib/<app_id>/<name>` when the AppSpec leaves it
// implicit.
type parsedMount struct {
	Name     string
	ReadOnly bool
	Target   string
}

var launchpadPathComponentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func parseFilesystemMount(raw, appID string) (parsedMount, error) {
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return parsedMount{}, fmt.Errorf("invalid filesystem mount %q: empty name", raw)
	}
	m := parsedMount{Name: strings.TrimSpace(parts[0])}
	if err := validateLaunchpadPathComponent("filesystem mount name", m.Name); err != nil {
		return parsedMount{}, fmt.Errorf("invalid filesystem mount %q: %w", raw, err)
	}
	mode := "rw"
	if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
		mode = strings.TrimSpace(parts[1])
	}
	switch mode {
	case "rw":
		m.ReadOnly = false
	case "ro":
		m.ReadOnly = true
	default:
		return parsedMount{}, fmt.Errorf("invalid filesystem mount %q: mode must be rw or ro", raw)
	}
	if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
		target := strings.TrimSpace(parts[2])
		if !filepath.IsAbs(target) || strings.Contains(target, "..") {
			return parsedMount{}, fmt.Errorf("invalid filesystem mount %q: target must be absolute and not contain '..'", raw)
		}
		m.Target = target
	} else {
		m.Target = "/var/lib/" + appID + "/" + m.Name
	}
	return m, nil
}

// materializeFilesystemMounts walks compiled.FilesystemMounts and, for every
// non-workspace entry, creates the host state directory and prepares a
// runtime LaunchpadMount that the local-container runner will bind into the
// workload. The workspace mount is excluded because it is handled separately
// via ContainerRequest.WorkspaceMount.
func materializeFilesystemMounts(compiled plan.LaunchPlan, opts ExecuteOptions) ([]lpruntime.LaunchpadMount, error) {
	if len(compiled.FilesystemMounts) == 0 {
		return nil, nil
	}
	stateRoot := launchpadStateRoot()
	if !opts.RuntimeDryRun {
		if err := validateLaunchpadPathComponent("launch id", compiled.LaunchID); err != nil {
			return nil, err
		}
	}
	var mounts []lpruntime.LaunchpadMount
	for _, raw := range compiled.FilesystemMounts {
		m, err := parseFilesystemMount(raw, compiled.AppID)
		if err != nil {
			return nil, err
		}
		if m.Name == "workspace" {
			continue
		}
		if opts.RuntimeDryRun {
			mounts = append(mounts, lpruntime.LaunchpadMount{
				Name:     m.Name,
				Source:   "",
				Target:   m.Target,
				ReadOnly: m.ReadOnly,
			})
			continue
		}
		if stateRoot == "" {
			return nil, fmt.Errorf("cannot materialize filesystem mount %q: HELM_LAUNCHPAD_HOME unset and user home directory not resolvable", m.Name)
		}
		launchStateRoot := filepath.Join(stateRoot, "state", compiled.LaunchID)
		hostDir := filepath.Join(launchStateRoot, m.Name)
		if !pathInsideRoot(launchStateRoot, hostDir) {
			return nil, fmt.Errorf("filesystem mount %q escapes launch state directory", m.Name)
		}
		if err := os.MkdirAll(hostDir, 0o700); err != nil {
			return nil, fmt.Errorf("create host state dir %s: %w", hostDir, err)
		}
		// Launch-scoped state directories are mounted into containers whose
		// app user often differs from the host operator UID. Keep the outer
		// Launchpad root private, but make this specific bind target writable
		// so apps can initialize their state without a host chown step.
		_ = os.Chmod(hostDir, 0o777)
		mounts = append(mounts, lpruntime.LaunchpadMount{
			Name:     m.Name,
			Source:   hostDir,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
		})
	}
	return mounts, nil
}

func validateLaunchpadPathComponent(label, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if value == "." || value == ".." || filepath.IsAbs(value) || strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("%s must be a single safe path component", label)
	}
	if filepath.Clean(value) != value {
		return fmt.Errorf("%s must be clean", label)
	}
	if !launchpadPathComponentRE.MatchString(value) {
		return fmt.Errorf("%s must match %s", label, launchpadPathComponentRE.String())
	}
	return nil
}

func pathInsideRoot(root, path string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
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
	selectedEnv := ""
	for _, envName := range compiled.ModelGatewayEnv {
		if value := opts.RuntimeSecretEnv[envName]; value != "" {
			secrets[envName] = value
			if selectedEnv == "" {
				selectedEnv = envName
			}
			continue
		}
		if value, ok := os.LookupEnv(envName); ok && value != "" {
			secrets[envName] = value
			if selectedEnv == "" {
				selectedEnv = envName
			}
		}
	}
	projectModelProviderRuntimeMetadata(secrets, selectedEnv)
	return secrets
}

func projectModelProviderRuntimeMetadata(env map[string]string, selectedEnv string) {
	if selectedEnv == "" {
		return
	}
	catalog, err := modelproviders.DefaultCatalog()
	if err != nil {
		return
	}
	provider, ok := catalog.ProviderForEnv(selectedEnv)
	if !ok {
		return
	}
	lookup := func(name string) (string, bool) {
		if value := env[name]; value != "" {
			return value, true
		}
		return os.LookupEnv(name)
	}
	baseURL := provider.PreferredBaseURLFromEnv(lookup)
	setIfEmpty(env, "HELM_MODEL_GATEWAY_PROVIDER", provider.ID)
	setIfEmpty(env, "HELM_LAUNCHPAD_MODEL_PROVIDER", provider.ID)
	setIfEmpty(env, "HELM_MODEL_GATEWAY_ENV", selectedEnv)
	if baseURL != "" {
		setIfEmpty(env, "HELM_MODEL_GATEWAY_BASE_URL", baseURL)
	}
	if len(provider.Protocols) > 0 {
		setIfEmpty(env, "HELM_MODEL_GATEWAY_PROTOCOLS", strings.Join(provider.Protocols, ","))
	}
	if baseURL != "" && provider.HasProtocol("openai-compatible") {
		setIfEmpty(env, "OPENAI_BASE_URL", baseURL)
		setIfEmpty(env, "OPENAI_API_BASE", baseURL)
	}
	if baseURL != "" && (provider.HasProtocol("anthropic-compatible") || provider.HasProtocol("anthropic-messages")) {
		setIfEmpty(env, "ANTHROPIC_BASE_URL", baseURL)
	}
}

func setIfEmpty(env map[string]string, key, value string) {
	if value == "" || env[key] != "" {
		return
	}
	env[key] = value
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

func allowInsecureLoopbackSandboxAPI() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_ALLOW_INSECURE_LOOPBACK_API"))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
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
