package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/modelproviders"
	"gopkg.in/yaml.v3"
)

var allowedEvidenceRequirements = map[string]struct{}{
	"cpi_output":                    {},
	"contract_preflight":            {},
	"kernel_verdict":                {},
	"sandbox_grant":                 {},
	"launch_receipt":                {},
	"install_receipt":               {},
	"egress_proxy_receipt":          {},
	"healthcheck_receipt":           {},
	"teardown_receipt":              {},
	"evidence_pack":                 {},
	"offline_verify":                {},
	"evidence_graph":                {},
	"mcp_quarantine":                {},
	"mcp_manifest":                  {},
	"model_gateway_broker":          {},
	"artifact_digest":               {},
	"cosign_signature":              {},
	"syft_sbom":                     {},
	"grype_vulnerability_scan":      {},
	"trivy_vulnerability_scan":      {},
	"slsa_provenance":               {},
	"rebuild_attestation":           {},
	"workstation_artifact_manifest": {},
	"agent_run_receipt":             {},
}

var ossSupportedInstallStrategies = map[string]struct{}{
	"signed_oci":              {},
	"signed_tarball":          {},
	"signed_release_artifact": {},
}

var sha256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (c *Catalog) Validate() error {
	if len(c.Apps) == 0 {
		return fmt.Errorf("no launchpad apps registered")
	}
	if len(c.Substrates) == 0 {
		return fmt.Errorf("no launchpad substrates registered")
	}
	appIDs := map[string]struct{}{}
	manifestByID := map[string]MCPServerManifest{}
	for _, manifest := range c.MCPManifests {
		if manifest.ID == "" {
			return fmt.Errorf("MCP manifest id is required")
		}
		if _, ok := manifestByID[manifest.ID]; ok {
			return fmt.Errorf("duplicate MCP manifest id %q", manifest.ID)
		}
		manifestByID[manifest.ID] = manifest
	}
	for _, app := range c.Apps {
		if app.ID == "" {
			return fmt.Errorf("app id is required")
		}
		if _, ok := appIDs[app.ID]; ok {
			return fmt.Errorf("duplicate app id %q", app.ID)
		}
		appIDs[app.ID] = struct{}{}
		if !validAvailability(app.Availability) {
			return fmt.Errorf("app %s has unknown availability %q", app.ID, app.Availability)
		}
		if err := validateSupportLevel(app); err != nil {
			return err
		}
		if app.Availability == AvailabilityExternalProprietaryAdapter && app.Install.Strategy != "byo_tool" {
			return fmt.Errorf("external app %s must use byo_tool install strategy", app.ID)
		}
		if app.NetworkPolicy.Default != "deny" {
			return fmt.Errorf("app %s network default must be deny", app.ID)
		}
		if app.MCPPolicy.UnknownServerPolicy != "quarantine" || app.MCPPolicy.RequireSchemaPin == false {
			return fmt.Errorf("app %s MCP policy must quarantine unknown servers and require schema pins", app.ID)
		}
		if err := validateEvidenceRequirements(app.ID, app.EvidenceRequirements); err != nil {
			return err
		}
		if err := validateModelGateway(app); err != nil {
			return err
		}
		if err := validateAppMCPManifestRefs(app, manifestByID); err != nil {
			return err
		}
		if app.FilesystemPolicy.PolicyRef == "" {
			return fmt.Errorf("app %s policy_ref is required", app.ID)
		}
		if err := c.validatePolicyPack(app.ID, app.FilesystemPolicy.PolicyRef); err != nil {
			return err
		}
		if app.Availability == AvailabilityOSSSupported && !app.Conformance.FullyVerified() {
			return fmt.Errorf("app %s cannot be oss_supported without full conformance", app.ID)
		}
		if app.Availability == AvailabilityOSSSupported {
			if err := validateOSSSupportedSupplyChain(app); err != nil {
				return err
			}
		}
		if err := validateFrameworkContract(app, manifestByID); err != nil {
			return err
		}
		if err := c.validateLaunchKitParity(app); err != nil {
			return err
		}
	}
	substrateIDs := map[string]struct{}{}
	for _, substrate := range c.Substrates {
		if substrate.ID == "" {
			return fmt.Errorf("substrate id is required")
		}
		if _, ok := substrateIDs[substrate.ID]; ok {
			return fmt.Errorf("duplicate substrate id %q", substrate.ID)
		}
		substrateIDs[substrate.ID] = struct{}{}
		if !validSubstrateKind(substrate.Kind) {
			return fmt.Errorf("substrate %s has unknown kind %q", substrate.ID, substrate.Kind)
		}
		if substrate.Network.Default != "deny" {
			return fmt.Errorf("substrate %s network default must be deny", substrate.ID)
		}
		if !validIsolationMode(substrate.Isolation.Mode) {
			return fmt.Errorf("substrate %s has unknown isolation mode %q", substrate.ID, substrate.Isolation.Mode)
		}
		if substrate.Isolation.Mode == "docker-default" && substrate.Isolation.HostileAgentGrade {
			return fmt.Errorf("substrate %s cannot claim hostile_agent_grade on docker-default isolation", substrate.ID)
		}
		for _, mode := range append(append([]string{}, substrate.Isolation.SupportedModes...), substrate.Isolation.HardenedModes...) {
			if !validIsolationMode(mode) {
				return fmt.Errorf("substrate %s has unknown isolation mode %q", substrate.ID, mode)
			}
		}
		if substrate.PolicyPack == "" {
			return fmt.Errorf("substrate %s policy_pack is required", substrate.ID)
		}
		if err := validateSubstrateCapabilities(substrate); err != nil {
			return err
		}
		if err := c.validatePolicyPack(substrate.ID, substrate.PolicyPack); err != nil {
			return err
		}
	}
	if err := validateMCPManifests(c.MCPManifests, appIDs); err != nil {
		return err
	}
	return nil
}

func validAvailability(a Availability) bool {
	switch a {
	case AvailabilityOSSSupported, AvailabilityOSSCandidate, AvailabilityExternalProprietaryAdapter, AvailabilityBlockedLicense, AvailabilityBlockedConformance:
		return true
	default:
		return false
	}
}

func validSupportLevel(level SupportLevel) bool {
	switch level {
	case SupportLevelOSSSupported, SupportLevelExternalBYOAdapter, SupportLevelVerifyOnly, SupportLevelAgentLive, SupportLevelDemo, SupportLevelImportQuarantined, SupportLevelBlockedRepairRequired:
		return true
	default:
		return false
	}
}

func validateSupportLevel(app AppSpec) error {
	if !validSupportLevel(app.SupportLevel) {
		return fmt.Errorf("app %s has unknown support_level %q", app.ID, app.SupportLevel)
	}
	switch app.Availability {
	case AvailabilityOSSSupported:
		if app.SupportLevel != SupportLevelOSSSupported && app.SupportLevel != SupportLevelAgentLive {
			return fmt.Errorf("app %s availability oss_supported requires support_level oss_supported or agent_live", app.ID)
		}
	case AvailabilityExternalProprietaryAdapter:
		if app.SupportLevel != SupportLevelExternalBYOAdapter {
			return fmt.Errorf("app %s external adapters must use support_level external_byo_adapter", app.ID)
		}
	}
	return nil
}

func validSubstrateKind(kind string) bool {
	switch kind {
	case "local-container", "local-microvm", "hosted-sandbox", "cloud":
		return true
	default:
		return false
	}
}

func validIsolationMode(mode string) bool {
	switch mode {
	case "docker-default", "docker-rootless-userns", "docker-eci", "gvisor", "kata-firecracker", "dedicated-vm":
		return true
	default:
		return false
	}
}

func validateModelGateway(app AppSpec) error {
	requiresGateway := hasEvidenceRequirement(app.EvidenceRequirements, "model_gateway_broker") ||
		contains(app.RequiredSecrets, "model_gateway") ||
		len(app.ModelGatewayEnv) > 0
	if !requiresGateway {
		return nil
	}
	if app.ModelGateway.LogicalSecret == "" {
		return fmt.Errorf("app %s model_gateway.logical_secret is required", app.ID)
	}
	if app.ModelGateway.Provider == "" {
		return fmt.Errorf("app %s model_gateway.provider is required", app.ID)
	}
	if app.ModelGateway.Mode == "" {
		return fmt.Errorf("app %s model_gateway.mode is required", app.ID)
	}
	switch app.ModelGateway.Mode {
	case "logical_binding_env_projection", "raw_provider_key", "external_byo":
		if !app.ModelGateway.RawProviderKeyProjected && len(app.ModelGatewayEnv) > 0 {
			return fmt.Errorf("app %s model_gateway mode %s must mark raw_provider_key_projected when runtime env keys are projected", app.ID, app.ModelGateway.Mode)
		}
	case "token_broker":
		if app.ModelGateway.RawProviderKeyProjected {
			return fmt.Errorf("app %s token_broker mode cannot project raw provider keys", app.ID)
		}
	default:
		return fmt.Errorf("app %s has unknown model_gateway.mode %q", app.ID, app.ModelGateway.Mode)
	}
	if app.ModelGateway.LogicalSecret != "model_gateway" && contains(app.RequiredSecrets, "model_gateway") {
		return fmt.Errorf("app %s model_gateway.logical_secret must match required secret model_gateway", app.ID)
	}
	if len(app.ModelGateway.ProviderIDs) > 0 {
		catalog, err := modelproviders.DefaultCatalog()
		if err != nil {
			return fmt.Errorf("app %s model provider catalog unavailable: %w", app.ID, err)
		}
		known := map[string]struct{}{}
		for _, provider := range catalog.Providers {
			known[provider.ID] = struct{}{}
		}
		for _, providerID := range app.ModelGateway.ProviderIDs {
			if _, ok := known[providerID]; !ok {
				return fmt.Errorf("app %s references unknown model_gateway.provider_ids entry %q", app.ID, providerID)
			}
		}
	}
	if app.Availability == AvailabilityOSSSupported && !hasEvidenceRequirement(app.EvidenceRequirements, "model_gateway_broker") {
		return fmt.Errorf("app %s cannot be oss_supported without model_gateway_broker evidence requirement", app.ID)
	}
	return nil
}

func validateAppMCPManifestRefs(app AppSpec, manifests map[string]MCPServerManifest) error {
	if app.Availability == AvailabilityOSSSupported && len(app.MCPManifests) == 0 {
		return fmt.Errorf("app %s cannot be oss_supported without signed MCP manifest refs", app.ID)
	}
	for _, ref := range app.MCPManifests {
		manifest, ok := manifests[ref]
		if !ok {
			return fmt.Errorf("app %s references missing MCP manifest %q", app.ID, ref)
		}
		if manifest.AppID != app.ID {
			return fmt.Errorf("app %s references MCP manifest %q for app %q", app.ID, ref, manifest.AppID)
		}
		if sha256DigestPattern.MatchString(app.Install.Digest) && sha256DigestPattern.MatchString(manifest.PackageDigest) && manifest.PackageDigest != app.Install.Digest {
			return fmt.Errorf("app %s MCP manifest %q package_digest must match install digest", app.ID, ref)
		}
		if app.SupplyChainEvidence.SignatureRef != "" && manifest.SignatureRef != "" && manifest.SignatureRef != app.SupplyChainEvidence.SignatureRef {
			return fmt.Errorf("app %s MCP manifest %q signature_ref must match supply-chain signature_ref", app.ID, ref)
		}
	}
	if app.Availability == AvailabilityOSSSupported && !hasEvidenceRequirement(app.EvidenceRequirements, "mcp_manifest") {
		return fmt.Errorf("app %s cannot be oss_supported without mcp_manifest evidence requirement", app.ID)
	}
	return nil
}

type launchKitAppSpec struct {
	ID                 string      `yaml:"id"`
	LegacyLaunchpadRef string      `yaml:"legacy_launchpad_ref"`
	Availability       string      `yaml:"availability"`
	Install            InstallSpec `yaml:"install"`
	Policy             string      `yaml:"policy"`
	Secrets            string      `yaml:"secrets"`
	MCPRegistry        string      `yaml:"mcp_registry"`
	Runtimes           struct {
		Demo  string `yaml:"demo"`
		Local string `yaml:"local"`
		Cloud string `yaml:"cloud"`
	} `yaml:"runtimes"`
	EvidenceProfile string `yaml:"evidence_profile"`
}

type launchKitRuntimeSpec struct {
	Mode                string   `yaml:"mode"`
	Target              string   `yaml:"target"`
	Command             []string `yaml:"command"`
	Healthcheck         string   `yaml:"healthcheck"`
	StateDirEnv         string   `yaml:"state_dir_env"`
	MCPRegistryRef      string   `yaml:"mcp_registry_ref"`
	ProviderHostGroups  []string `yaml:"provider_host_groups"`
	EgressProxyRequired bool     `yaml:"egress_proxy_required"`
}

func (c *Catalog) validateLaunchKitParity(app AppSpec) error {
	if c == nil || c.Root == "" || app.Install.Strategy == "byo_tool" {
		return nil
	}
	launchKitRoot := filepath.Join(c.Root, "registry", "launchkit", "apps")
	if !exists(launchKitRoot) {
		return nil
	}
	appDir := filepath.Join(launchKitRoot, app.ID)
	if !exists(appDir) {
		return fmt.Errorf("app %s requires LaunchKit spec parity at registry/launchkit/apps/%s", app.ID, app.ID)
	}
	var kit launchKitAppSpec
	if err := readLaunchKitYAML(filepath.Join(appDir, "helm.app.yaml"), &kit); err != nil {
		return fmt.Errorf("app %s LaunchKit helm.app.yaml: %w", app.ID, err)
	}
	if kit.ID != app.ID {
		return fmt.Errorf("app %s LaunchKit id must match AppSpec id", app.ID)
	}
	if kit.Availability != string(app.Availability) {
		return fmt.Errorf("app %s LaunchKit availability must match Launchpad AppSpec availability", app.ID)
	}
	if kit.LegacyLaunchpadRef != filepath.ToSlash(filepath.Join("registry", "launchpad", "apps", app.ID+".yaml")) {
		return fmt.Errorf("app %s LaunchKit legacy_launchpad_ref must point at Launchpad AppSpec", app.ID)
	}
	if kit.Install.Image != app.Install.Image || kit.Install.Digest != app.Install.Digest || kit.Install.Strategy != app.Install.Strategy {
		return fmt.Errorf("app %s LaunchKit install image/digest/strategy must match Launchpad AppSpec", app.ID)
	}
	if kit.Policy == "" || kit.Secrets == "" || kit.MCPRegistry == "" || kit.EvidenceProfile == "" {
		return fmt.Errorf("app %s LaunchKit must declare policy, secrets, MCP registry, and evidence profile refs", app.ID)
	}
	if kit.Runtimes.Local == "" {
		return fmt.Errorf("app %s LaunchKit local runtime ref is required", app.ID)
	}
	var runtime launchKitRuntimeSpec
	if err := readLaunchKitYAML(filepath.Join(appDir, kit.Runtimes.Local), &runtime); err != nil {
		return fmt.Errorf("app %s LaunchKit local runtime: %w", app.ID, err)
	}
	if !sameStringsOrdered(runtime.Command, app.Runtime.Command) {
		return fmt.Errorf("app %s LaunchKit local command must match Launchpad runtime.command", app.ID)
	}
	if runtime.Healthcheck != app.FrameworkContract.Healthcheck {
		return fmt.Errorf("app %s LaunchKit local healthcheck must match framework_contract.healthcheck", app.ID)
	}
	if app.FilesystemPolicy.StateDirEnv != "" && runtime.StateDirEnv != app.FilesystemPolicy.StateDirEnv {
		return fmt.Errorf("app %s LaunchKit local state_dir_env must match filesystem_policy.state_dir_env", app.ID)
	}
	if runtime.MCPRegistryRef != "" && runtime.MCPRegistryRef != kit.MCPRegistry {
		return fmt.Errorf("app %s LaunchKit local mcp_registry_ref must match helm.app.yaml mcp_registry", app.ID)
	}
	if !sameStringSet(runtime.ProviderHostGroups, app.FrameworkContract.ProviderHostGroups) {
		return fmt.Errorf("app %s LaunchKit provider_host_groups must match framework_contract.provider_host_groups", app.ID)
	}
	if runtime.EgressProxyRequired != app.FrameworkContract.EgressProxy.Required {
		return fmt.Errorf("app %s LaunchKit egress_proxy_required must match framework_contract.egress_proxy.required", app.ID)
	}
	return nil
}

func readLaunchKitYAML(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, out)
}

func sameStringsOrdered(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateFrameworkContract(app AppSpec, manifests map[string]MCPServerManifest) error {
	contract := app.FrameworkContract
	if !contract.F2ContractPreflight {
		return fmt.Errorf("app %s framework_contract.f2_contract_preflight must be true", app.ID)
	}
	if contract.ClaimLevel != app.SupportLevel {
		return fmt.Errorf("app %s framework_contract.claim_level must match support_level", app.ID)
	}
	if !validLiveCommandKind(contract.LiveCommandKind) {
		return fmt.Errorf("app %s has unknown framework_contract.live_command_kind %q", app.ID, contract.LiveCommandKind)
	}
	if contract.RuntimeInstallPolicy != "forbidden" {
		return fmt.Errorf("app %s framework_contract.runtime_install_policy must be forbidden", app.ID)
	}
	if len(contract.ForbiddenRuntimeInstallPatterns) == 0 {
		return fmt.Errorf("app %s framework_contract.forbidden_runtime_install_patterns is required", app.ID)
	}
	if err := validateNoRuntimeInstallers(app, contract.ForbiddenRuntimeInstallPatterns); err != nil {
		return err
	}
	if err := validateFrameworkWritablePaths(app); err != nil {
		return err
	}
	if err := validateContractMCPRefs(app, contract.MCPManifestRefs, manifests); err != nil {
		return err
	}
	if err := validateContractHealthcheck(app); err != nil {
		return err
	}
	if strings.TrimSpace(contract.EvidenceProfile) == "" {
		return fmt.Errorf("app %s framework_contract.evidence_profile is required", app.ID)
	}
	if err := validateContractImages(app); err != nil {
		return err
	}
	if requiresContractEgressProxy(app) {
		if !contract.EgressProxy.Required {
			return fmt.Errorf("app %s framework_contract.egress_proxy.required must be true for live/provider-backed F2 coverage", app.ID)
		}
		if err := validateEgressProxyContract(app.ID, contract.EgressProxy); err != nil {
			return err
		}
	} else if contract.EgressProxy.Required {
		if err := validateEgressProxyContract(app.ID, contract.EgressProxy); err != nil {
			return err
		}
	}
	return nil
}

func validLiveCommandKind(kind string) bool {
	switch kind {
	case "agent_live", "verify_only", "workstation_adapter", "demo", "import_quarantined", "blocked_repair_required":
		return true
	default:
		return false
	}
}

func validateNoRuntimeInstallers(app AppSpec, patterns []string) error {
	haystacks := []string{strings.Join(app.Runtime.Command, " ")}
	for _, healthcheck := range app.Healthchecks {
		haystacks = append(haystacks, healthcheck.Command)
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		for _, haystack := range haystacks {
			if strings.Contains(strings.ToLower(haystack), pattern) {
				return fmt.Errorf("app %s runtime command contains forbidden runtime install pattern %q", app.ID, pattern)
			}
		}
	}
	return nil
}

func validateFrameworkWritablePaths(app AppSpec) error {
	contract := app.FrameworkContract
	pathsByTarget := map[string]WritablePathContractSpec{}
	envs := map[string]struct{}{}
	for _, path := range contract.WritablePaths {
		target := strings.TrimSpace(path.Path)
		if target == "" {
			return fmt.Errorf("app %s framework_contract.writable_paths entries require path", app.ID)
		}
		if path.Required == false {
			return fmt.Errorf("app %s framework_contract.writable_paths entries must be required", app.ID)
		}
		pathsByTarget[target] = path
		if path.Env != "" {
			envs[path.Env] = struct{}{}
		}
	}
	if app.FilesystemPolicy.StateDirEnv != "" {
		if _, ok := envs[app.FilesystemPolicy.StateDirEnv]; !ok {
			return fmt.Errorf("app %s framework_contract.writable_paths must prove state_dir_env %s", app.ID, app.FilesystemPolicy.StateDirEnv)
		}
	}
	for _, mount := range app.FilesystemPolicy.Mounts {
		if strings.HasPrefix(mount, "workspace:") {
			continue
		}
		target := mountTarget(mount)
		if target == "" {
			if len(contract.WritablePaths) == 0 {
				return fmt.Errorf("app %s framework_contract.writable_paths must prove writable app state mounts", app.ID)
			}
			continue
		}
		if _, ok := pathsByTarget[target]; !ok {
			return fmt.Errorf("app %s framework_contract.writable_paths must include mount target %s", app.ID, target)
		}
	}
	return nil
}

func mountTarget(mount string) string {
	parts := strings.Split(mount, ":")
	if len(parts) >= 3 {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func validateContractMCPRefs(app AppSpec, refs []string, manifests map[string]MCPServerManifest) error {
	if !sameStringSet(app.MCPManifests, refs) {
		return fmt.Errorf("app %s framework_contract.mcp_manifest_refs must match mcp_manifests", app.ID)
	}
	for _, ref := range refs {
		if _, ok := manifests[ref]; !ok {
			return fmt.Errorf("app %s framework_contract.mcp_manifest_refs references missing MCP manifest %q", app.ID, ref)
		}
	}
	return nil
}

func validateContractHealthcheck(app AppSpec) error {
	contractHealthcheck := strings.TrimSpace(app.FrameworkContract.Healthcheck)
	if len(app.Healthchecks) == 0 {
		if contractHealthcheck == "" {
			return fmt.Errorf("app %s framework_contract.healthcheck is required", app.ID)
		}
		return nil
	}
	for _, healthcheck := range app.Healthchecks {
		if contractHealthcheck == strings.TrimSpace(healthcheck.Command) || contractHealthcheck == strings.TrimSpace(healthcheck.URL) {
			return nil
		}
	}
	return fmt.Errorf("app %s framework_contract.healthcheck must match a declared healthcheck", app.ID)
}

func validateContractImages(app AppSpec) error {
	if app.Install.Strategy != "signed_oci" {
		return nil
	}
	if len(app.FrameworkContract.Images) == 0 {
		return fmt.Errorf("app %s framework_contract.images is required for signed OCI runtime contracts", app.ID)
	}
	installDigestFound := false
	for _, image := range app.FrameworkContract.Images {
		if image.Name == "" || image.Purpose == "" {
			return fmt.Errorf("app %s framework_contract.images entries require name and purpose", app.ID)
		}
		if !sha256DigestPattern.MatchString(image.Digest) {
			return fmt.Errorf("app %s framework_contract image %s digest must be sha256:<64 lowercase hex>", app.ID, image.Name)
		}
		if digestFromImageRef(image.Image) != image.Digest {
			return fmt.Errorf("app %s framework_contract image %s must use image@sha256 matching digest", app.ID, image.Name)
		}
		if image.Digest == app.Install.Digest {
			installDigestFound = true
		}
	}
	if !installDigestFound {
		return fmt.Errorf("app %s framework_contract.images must include the install digest", app.ID)
	}
	return nil
}

func requiresContractEgressProxy(app AppSpec) bool {
	switch app.SupportLevel {
	case SupportLevelAgentLive, SupportLevelOSSSupported:
		return len(app.ModelGatewayEnv) > 0 || len(app.ModelGateway.ProviderIDs) > 0 || len(app.NetworkPolicy.Allowlist) > 0 || contains(app.EvidenceRequirements, "model_gateway_broker")
	default:
		return false
	}
}

func validateEgressProxyContract(appID string, proxy EgressProxyContractSpec) error {
	if proxy.Image == "" || proxy.Digest == "" || proxy.SignatureRef == "" || proxy.SBOMRef == "" || proxy.VulnerabilityScanRef == "" || proxy.ReceiptRef == "" {
		return fmt.Errorf("app %s framework_contract.egress_proxy must declare image, digest, signature, SBOM, vulnerability scan, and receipt refs", appID)
	}
	if !sha256DigestPattern.MatchString(proxy.Digest) {
		return fmt.Errorf("app %s framework_contract.egress_proxy.digest must be sha256:<64 lowercase hex>", appID)
	}
	if digestFromImageRef(proxy.Image) != proxy.Digest {
		return fmt.Errorf("app %s framework_contract.egress_proxy.image must be pinned by matching digest", appID)
	}
	return nil
}

func digestFromImageRef(image string) string {
	index := strings.LastIndex(image, "@sha256:")
	if index < 0 {
		return ""
	}
	return "sha256:" + image[index+len("@sha256:"):]
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := map[string]int{}
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func validateMCPManifests(manifests []MCPServerManifest, appIDs map[string]struct{}) error {
	for _, manifest := range manifests {
		if _, ok := appIDs[manifest.AppID]; !ok {
			return fmt.Errorf("MCP manifest %s references unknown app %q", manifest.ID, manifest.AppID)
		}
		if manifest.ServerID == "" {
			return fmt.Errorf("MCP manifest %s server_id is required", manifest.ID)
		}
		if !validMCPTransport(manifest.Transport) {
			return fmt.Errorf("MCP manifest %s has unsupported transport %q", manifest.ID, manifest.Transport)
		}
		if manifest.Transport == "stdio" && len(manifest.Command) == 0 {
			return fmt.Errorf("MCP manifest %s stdio transport requires pinned command", manifest.ID)
		}
		if !sha256DigestPattern.MatchString(manifest.PackageDigest) {
			return fmt.Errorf("MCP manifest %s package_digest must be sha256:<64 lowercase hex>", manifest.ID)
		}
		if manifest.SignatureRef == "" {
			return fmt.Errorf("MCP manifest %s signature_ref is required", manifest.ID)
		}
		if !sha256DigestPattern.MatchString(manifest.SchemaHash) {
			return fmt.Errorf("MCP manifest %s schema_hash must be sha256:<64 lowercase hex>", manifest.ID)
		}
		if len(manifest.Tools) == 0 {
			return fmt.Errorf("MCP manifest %s must declare at least one tool", manifest.ID)
		}
		for _, tool := range manifest.Tools {
			if tool.Name == "" {
				return fmt.Errorf("MCP manifest %s has tool without name", manifest.ID)
			}
			if !sha256DigestPattern.MatchString(tool.SchemaHash) {
				return fmt.Errorf("MCP manifest %s tool %s schema_hash must be sha256:<64 lowercase hex>", manifest.ID, tool.Name)
			}
			if !validMCPToolEffect(tool.Effect) {
				return fmt.Errorf("MCP manifest %s tool %s has unsupported effect %q", manifest.ID, tool.Name, tool.Effect)
			}
		}
	}
	return nil
}

func validMCPTransport(transport string) bool {
	switch transport {
	case "stdio", "http_sse", "websocket":
		return true
	default:
		return false
	}
}

func validMCPToolEffect(effect string) bool {
	switch effect {
	case "read", "side_effect", "destructive":
		return true
	default:
		return false
	}
}

func validateSubstrateCapabilities(substrate SubstrateSpec) error {
	caps := substrate.Capabilities
	required := map[string]string{
		"isolation_strength":  caps.IsolationStrength,
		"network_enforcement": caps.NetworkEnforcement,
		"secret_mode":         caps.SecretMode,
		"receipt_support":     caps.ReceiptSupport,
		"teardown_proof":      caps.TeardownProof,
		"status":              caps.Status,
	}
	for name, value := range required {
		if value == "" {
			return fmt.Errorf("substrate %s capabilities.%s is required", substrate.ID, name)
		}
	}
	requiredLifecycle := []string{"plan", "preflight", "launch", "healthcheck", "execute", "evidence_export", "reconcile", "delete", "post_delete_verify"}
	for _, step := range requiredLifecycle {
		if !contains(caps.Lifecycle, step) {
			return fmt.Errorf("substrate %s capabilities.lifecycle must include %s", substrate.ID, step)
		}
	}
	if substrate.Availability == "supported" {
		if caps.Status != "ga" {
			return fmt.Errorf("substrate %s cannot be supported unless capabilities.status is ga", substrate.ID)
		}
		if caps.ReceiptSupport != "required" {
			return fmt.Errorf("substrate %s cannot be supported unless receipt_support is required", substrate.ID)
		}
		if caps.TeardownProof != "required" {
			return fmt.Errorf("substrate %s cannot be supported unless teardown_proof is required", substrate.ID)
		}
	}
	return nil
}

func validateEvidenceRequirements(appID string, requirements []string) error {
	for _, req := range requirements {
		if _, ok := allowedEvidenceRequirements[req]; !ok {
			return fmt.Errorf("app %s has unknown evidence requirement %q", appID, req)
		}
	}
	return nil
}

func validateOSSSupportedSupplyChain(app AppSpec) error {
	if _, ok := ossSupportedInstallStrategies[app.Install.Strategy]; !ok {
		return fmt.Errorf("app %s cannot be oss_supported with install strategy %q", app.ID, app.Install.Strategy)
	}
	if !sha256DigestPattern.MatchString(app.Install.Digest) {
		return fmt.Errorf("app %s cannot be oss_supported without signed artifact digest in sha256:<64 lowercase hex> format", app.ID)
	}
	if app.Install.Strategy == "signed_oci" && !strings.Contains(app.Install.Image, "@sha256:") {
		return fmt.Errorf("app %s cannot be oss_supported without immutable OCI image@sha256 reference", app.ID)
	}
	evidence := app.SupplyChainEvidence
	if evidence.ArtifactDigest == "" {
		return fmt.Errorf("app %s cannot be oss_supported without artifact_digest evidence", app.ID)
	}
	if evidence.ArtifactDigest != app.Install.Digest {
		return fmt.Errorf("app %s supply-chain artifact_digest must match install digest", app.ID)
	}
	if !sha256DigestPattern.MatchString(evidence.ArtifactDigest) {
		return fmt.Errorf("app %s cannot be oss_supported without artifact_digest in sha256:<64 lowercase hex> format", app.ID)
	}
	if strings.ToLower(evidence.SignatureTool) != "cosign" || evidence.SignatureRef == "" {
		return fmt.Errorf("app %s cannot be oss_supported without cosign signature evidence", app.ID)
	}
	if strings.ToLower(evidence.SBOMTool) != "syft" || evidence.SBOMRef == "" {
		return fmt.Errorf("app %s cannot be oss_supported without syft SBOM evidence", app.ID)
	}
	switch strings.ToLower(evidence.VulnerabilityScanTool) {
	case "grype", "trivy":
		if evidence.VulnerabilityScanRef == "" {
			return fmt.Errorf("app %s cannot be oss_supported without vulnerability scan evidence", app.ID)
		}
	default:
		return fmt.Errorf("app %s cannot be oss_supported without grype or trivy vulnerability scan evidence", app.ID)
	}
	if !hasEvidenceRequirement(app.EvidenceRequirements, "artifact_digest") ||
		!hasEvidenceRequirement(app.EvidenceRequirements, "cosign_signature") ||
		!hasEvidenceRequirement(app.EvidenceRequirements, "syft_sbom") ||
		!(hasEvidenceRequirement(app.EvidenceRequirements, "grype_vulnerability_scan") || hasEvidenceRequirement(app.EvidenceRequirements, "trivy_vulnerability_scan")) {
		return fmt.Errorf("app %s cannot be oss_supported without artifact_digest, cosign_signature, syft_sbom, and grype/trivy vulnerability scan evidence requirements", app.ID)
	}
	if err := validatePromotionEvidence(app); err != nil {
		return err
	}
	return nil
}

func validatePromotionEvidence(app AppSpec) error {
	evidence := app.PromotionEvidence
	switch {
	case evidence.ArtifactVerificationRef == "":
		return fmt.Errorf("app %s cannot be oss_supported without promotion artifact verification evidence", app.ID)
	case evidence.LiveE2ERunID == "":
		return fmt.Errorf("app %s cannot be oss_supported without promotion live e2e run evidence", app.ID)
	case evidence.EvidencePackRef == "":
		return fmt.Errorf("app %s cannot be oss_supported without promotion EvidencePack ref", app.ID)
	case evidence.TeardownReceiptRef == "":
		return fmt.Errorf("app %s cannot be oss_supported without promotion teardown receipt ref", app.ID)
	default:
		return nil
	}
}

func hasEvidenceRequirement(requirements []string, target string) bool {
	for _, req := range requirements {
		if req == target {
			return true
		}
	}
	return false
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type policyPack struct {
	App       map[string]any `toml:"app"`
	Substrate map[string]any `toml:"substrate"`
}

func (c *Catalog) validatePolicyPack(id, ref string) error {
	path := ref
	if !filepath.IsAbs(ref) {
		path = filepath.Join(c.Root, ref)
	}
	var pack policyPack
	if _, err := toml.DecodeFile(path, &pack); err != nil {
		return fmt.Errorf("policy pack %s for %s is invalid: %w", ref, id, err)
	}
	body := pack.App
	if len(body) == 0 {
		body = pack.Substrate
	}
	if len(body) == 0 {
		return fmt.Errorf("policy pack %s for %s must contain [app] or [substrate]", ref, id)
	}
	if value, ok := body["permission_bypass_forbidden"].(bool); !ok || !value {
		return fmt.Errorf("policy pack %s must set permission_bypass_forbidden = true", ref)
	}
	if value, ok := body["recursive_launch_forbidden"].(bool); !ok || !value {
		return fmt.Errorf("policy pack %s must set recursive_launch_forbidden = true", ref)
	}
	if value, ok := body["network_default"].(string); ok && strings.ToLower(value) != "deny" {
		return fmt.Errorf("policy pack %s network_default must be deny", ref)
	}
	if len(pack.Substrate) > 0 {
		isolationMode, ok := body["isolation_mode"].(string)
		if !ok || !validIsolationMode(isolationMode) {
			return fmt.Errorf("policy pack %s must set a valid isolation_mode", ref)
		}
		if isolationMode == "docker-default" {
			if hostile, ok := body["hostile_agent_grade"].(bool); ok && hostile {
				return fmt.Errorf("policy pack %s cannot mark docker-default as hostile_agent_grade", ref)
			}
		}
	}
	return nil
}

func (c ConformanceSpec) FullyVerified() bool {
	return c.LicenseVerified &&
		c.ArtifactVerified &&
		c.PolicyPackPresent &&
		c.SandboxVerified &&
		c.HealthcheckPassing &&
		c.E2EPassing &&
		c.TeardownVerified &&
		c.ReceiptVerified &&
		c.EvidencePackVerified
}

func (c *Catalog) App(id string) (AppSpec, bool) {
	for _, app := range c.Apps {
		if app.ID == id {
			return app, true
		}
	}
	return AppSpec{}, false
}

func (c *Catalog) Substrate(id string) (SubstrateSpec, bool) {
	for _, substrate := range c.Substrates {
		if substrate.ID == id {
			return substrate, true
		}
	}
	return SubstrateSpec{}, false
}
