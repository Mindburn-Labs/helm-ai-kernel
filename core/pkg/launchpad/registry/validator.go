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
	"mcp_quarantine":           {},
	"artifact_digest":          {},
	"cosign_signature":         {},
	"syft_sbom":                {},
	"grype_vulnerability_scan": {},
	"trivy_vulnerability_scan": {},
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
		if substrate.PolicyPack == "" {
			return fmt.Errorf("substrate %s policy_pack is required", substrate.ID)
		}
		if err := c.validatePolicyPack(substrate.ID, substrate.PolicyPack); err != nil {
			return err
		}
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
	case "local-container", "cloud":
		return true
	default:
		return false
	}
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
