package conformance

import (
	"os"
	"os/exec"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/modelproviders"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

type GateStatus string

const (
	GatePass GateStatus = "PASS"
	GateFail GateStatus = "FAIL"
	GateWarn GateStatus = "WARN"
)

type Gate struct {
	ID      string     `json:"id"`
	Status  GateStatus `json:"status"`
	Message string     `json:"message"`
}

type ReadinessReport struct {
	AppID       string   `json:"app_id"`
	SubstrateID string   `json:"substrate_id"`
	Verdict     string   `json:"verdict"`
	Gates       []Gate   `json:"gates"`
	Blockers    []string `json:"blockers"`
}

type Options struct {
	EnvLookup  func(string) (string, bool)
	ToolLookup func(string) (string, bool)
}

func EvaluateMissionReadiness(app registry.AppSpec, substrate registry.SubstrateSpec, opts Options) ReadinessReport {
	if opts.EnvLookup == nil {
		opts.EnvLookup = os.LookupEnv
	}
	if opts.ToolLookup == nil {
		opts.ToolLookup = defaultToolLookup
	}
	report := ReadinessReport{AppID: app.ID, SubstrateID: substrate.ID, Verdict: "ALLOW"}
	add := func(id string, status GateStatus, message string) {
		report.Gates = append(report.Gates, Gate{ID: id, Status: status, Message: message})
		if status == GateFail {
			report.Verdict = "ESCALATE"
			report.Blockers = append(report.Blockers, id)
		}
	}

	if substrate.ID != "local-container" {
		add("substrate.local_container", GateFail, "mission completion requires local-container conformance for OSS app promotion")
	} else {
		add("substrate.local_container", GatePass, "local-container substrate selected")
	}
	if substrate.Network.Default != "deny" {
		add("substrate.network_default_deny", GateFail, "substrate network default must be deny")
	} else {
		add("substrate.network_default_deny", GatePass, "substrate network default is deny")
	}
	if substrate.Isolation.Mode == "docker-default" && substrate.Isolation.HostileAgentGrade {
		add("substrate.isolation_claim", GateFail, "docker-default cannot be claimed as hostile-agent-grade isolation")
	} else if substrate.Isolation.Mode == "" {
		add("substrate.isolation_claim", GateFail, "substrate isolation mode is required")
	} else {
		add("substrate.isolation_claim", GatePass, "substrate isolation mode is explicit")
	}

	requiredEnv := modelGatewayEnv(app)
	if modelGatewayAcceptsAnyProviderEnv(app, requiredEnv) {
		present := []string{}
		for _, group := range modelGatewayEnvGroups(app, requiredEnv) {
			complete := true
			for _, envName := range group {
				if value, ok := opts.EnvLookup(envName); !ok || value == "" {
					complete = false
					break
				}
			}
			if complete {
				present = group
				break
			}
		}
		if len(present) == 0 {
			add("secret.model_gateway_provider", GateFail, "one complete supported BYO model provider env group is required for live local-container e2e")
		} else {
			add("secret."+strings.Join(present, "."), GatePass, strings.Join(present, "+")+" is present")
		}
	} else {
		for _, envName := range requiredEnv {
			if value, ok := opts.EnvLookup(envName); !ok || value == "" {
				add("secret."+envName, GateFail, envName+" is required for live local-container e2e")
			} else {
				add("secret."+envName, GatePass, envName+" is present")
			}
		}
	}
	for _, tool := range []string{"docker", "cosign", "syft"} {
		if path, ok := opts.ToolLookup(tool); !ok || path == "" {
			add("tool."+tool, GateFail, tool+" is required for mission-complete signed OCI conformance")
		} else {
			add("tool."+tool, GatePass, tool+" available")
		}
	}
	if grype, ok := opts.ToolLookup("grype"); ok && grype != "" {
		add("tool.vulnerability_scan", GatePass, "grype available")
	} else if trivy, ok := opts.ToolLookup("trivy"); ok && trivy != "" {
		add("tool.vulnerability_scan", GatePass, "trivy available")
	} else {
		add("tool.vulnerability_scan", GateFail, "grype or trivy is required")
	}

	if app.Install.Strategy != "signed_oci" {
		add("artifact.strategy", GateFail, "mission-complete OpenClaw/Hermes support requires HELM-built signed OCI artifacts")
	} else {
		add("artifact.strategy", GatePass, "app is configured for signed OCI artifact authority")
	}
	if app.Install.Image == "" {
		add("artifact.image", GateFail, "signed OCI image reference is required")
	} else if app.Install.Strategy == "signed_oci" && !strings.Contains(app.Install.Image, "@sha256:") {
		add("artifact.image", GateFail, "signed OCI support requires immutable image@sha256 reference")
	} else {
		add("artifact.image", GatePass, "signed OCI image reference configured")
	}
	if app.Install.Digest == "" || !strings.HasPrefix(app.Install.Digest, "sha256:") {
		add("artifact.digest", GateFail, "signed OCI digest is required before app promotion")
	} else {
		add("artifact.digest", GatePass, "signed OCI digest configured")
	}
	if app.SupplyChainEvidence.SignatureTool != "cosign" || app.SupplyChainEvidence.SignatureRef == "" {
		add("artifact.cosign_signature", GateFail, "cosign signature evidence is required")
	} else {
		add("artifact.cosign_signature", GatePass, "cosign signature evidence configured")
	}
	if app.SupplyChainEvidence.SBOMTool != "syft" || app.SupplyChainEvidence.SBOMRef == "" {
		add("artifact.sbom", GateFail, "syft SBOM evidence is required")
	} else {
		add("artifact.sbom", GatePass, "syft SBOM evidence configured")
	}
	switch app.SupplyChainEvidence.VulnerabilityScanTool {
	case "grype", "trivy":
		if app.SupplyChainEvidence.VulnerabilityScanRef == "" {
			add("artifact.vulnerability_scan", GateFail, "vulnerability scan evidence ref is required")
		} else {
			add("artifact.vulnerability_scan", GatePass, "vulnerability scan evidence configured")
		}
	default:
		add("artifact.vulnerability_scan", GateFail, "grype or trivy vulnerability scan evidence is required")
	}

	if app.Availability != registry.AvailabilityOSSSupported {
		add("app.availability", GateFail, "app remains below oss_supported until all conformance gates pass")
	} else {
		add("app.availability", GatePass, "app availability is oss_supported")
	}
	if !app.Conformance.FullyVerified() {
		add("app.full_conformance", GateFail, "license, artifact, sandbox, healthcheck, e2e, teardown, receipt, and EvidencePack verification must all pass")
	} else {
		add("app.full_conformance", GatePass, "full conformance is recorded")
	}
	if report.Verdict == "" {
		report.Verdict = "ALLOW"
	}
	return report
}

func modelGatewayEnv(app registry.AppSpec) []string {
	if len(app.ModelGatewayEnv) > 0 {
		return append([]string{}, app.ModelGatewayEnv...)
	}
	if !modelGatewayUsesCatalog(app) {
		return nil
	}
	catalog, err := modelproviders.DefaultCatalog()
	if err != nil {
		return nil
	}
	envNames, err := catalog.EnvNamesForProviderIDs(app.ModelGateway.ProviderIDs)
	if err != nil {
		return nil
	}
	return envNames
}

func modelGatewayEnvGroups(app registry.AppSpec, envNames []string) [][]string {
	if !modelGatewayUsesCatalog(app) {
		return singletonEnvGroups(envNames)
	}
	catalog, err := modelproviders.DefaultCatalog()
	if err != nil {
		return singletonEnvGroups(envNames)
	}
	groups, err := catalog.EnvGroupsForProviderIDs(app.ModelGateway.ProviderIDs)
	if err != nil || len(groups) == 0 {
		return singletonEnvGroups(envNames)
	}
	return groups
}

func modelGatewayUsesCatalog(app registry.AppSpec) bool {
	provider := strings.ToLower(strings.TrimSpace(app.ModelGateway.Provider))
	return provider == "byo" || provider == "multi"
}

func modelGatewayAcceptsAnyProviderEnv(app registry.AppSpec, envNames []string) bool {
	provider := strings.ToLower(strings.TrimSpace(app.ModelGateway.Provider))
	return len(envNames) > 1 && (provider == "byo" || provider == "multi" || len(app.ModelGateway.ProviderIDs) > 1)
}

func singletonEnvGroups(envNames []string) [][]string {
	groups := make([][]string, 0, len(envNames))
	for _, envName := range envNames {
		groups = append(groups, []string{envName})
	}
	return groups
}

func defaultToolLookup(name string) (string, bool) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return path, path != ""
}
