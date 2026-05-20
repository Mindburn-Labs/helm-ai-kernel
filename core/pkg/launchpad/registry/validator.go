package registry

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

var allowedEvidenceRequirements = map[string]struct{}{
	"cpi_output":               {},
	"kernel_verdict":           {},
	"sandbox_grant":            {},
	"launch_receipt":           {},
	"install_receipt":          {},
	"healthcheck_receipt":      {},
	"teardown_receipt":         {},
	"evidence_pack":            {},
	"evidence_graph":           {},
	"mcp_quarantine":           {},
	"mcp_manifest":             {},
	"model_gateway_broker":     {},
	"artifact_digest":          {},
	"cosign_signature":         {},
	"syft_sbom":                {},
	"grype_vulnerability_scan": {},
	"trivy_vulnerability_scan": {},
	"slsa_provenance":          {},
	"rebuild_attestation":      {},
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
	}
	if app.Availability == AvailabilityOSSSupported && !hasEvidenceRequirement(app.EvidenceRequirements, "mcp_manifest") {
		return fmt.Errorf("app %s cannot be oss_supported without mcp_manifest evidence requirement", app.ID)
	}
	return nil
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
