package plan

import (
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

type ResultClass string

const (
	ResultClassModelRefused          ResultClass = "MODEL_REFUSED"
	ResultClassInputBlocked          ResultClass = "INPUT_BLOCKED"
	ResultClassToolBlocked           ResultClass = "TOOL_BLOCKED"
	ResultClassEgressDenied          ResultClass = "EGRESS_DENIED"
	ResultClassMCPQuarantined        ResultClass = "MCP_QUARANTINED"
	ResultClassPlanDeny              ResultClass = "PLAN_DENY"
	ResultClassPlanEscalate          ResultClass = "PLAN_ESCALATE"
	ResultClassRuntimeRepairRequired ResultClass = "RUNTIME_REPAIR_REQUIRED"
	ResultClassAttackBlocked         ResultClass = "ATTACK_BLOCKED"
)

type RepairClass string

const (
	RepairClassNone                   RepairClass = "NONE"
	RepairClassContractRepairRequired RepairClass = "CONTRACT_REPAIR_REQUIRED"
	RepairClassRebuildImageRequired   RepairClass = "REBUILD_IMAGE_REQUIRED"
	RepairClassProviderSecretRequired RepairClass = "PROVIDER_SECRET_REQUIRED"
	RepairClassRuntimeRepairRequired  RepairClass = "RUNTIME_REPAIR_REQUIRED"
)

type ContractPreflight struct {
	Stage          string                `json:"stage"`
	ContractStatus string                `json:"contract_status"`
	Verdict        string                `json:"verdict"`
	ResultClass    ResultClass           `json:"result_class,omitempty"`
	RepairClass    RepairClass           `json:"repair_class"`
	SupportLevel   registry.SupportLevel `json:"support_level"`
	Checks         []ContractCheck       `json:"checks"`
	EvidenceRefs   []string              `json:"evidence_refs,omitempty"`
}

type ContractCheck struct {
	ID          string      `json:"id"`
	Verdict     string      `json:"verdict"`
	ResultClass ResultClass `json:"result_class,omitempty"`
	RepairClass RepairClass `json:"repair_class,omitempty"`
	Message     string      `json:"message"`
	EvidenceRef string      `json:"evidence_ref,omitempty"`
	Expected    any         `json:"expected,omitempty"`
	Actual      any         `json:"actual,omitempty"`
}

func BuildContractPreflight(app registry.AppSpec, substrate registry.SubstrateSpec, launch LaunchPlan) ContractPreflight {
	preflight := ContractPreflight{
		Stage:          "f2_contract_preflight",
		ContractStatus: "PASS",
		Verdict:        "ALLOW",
		RepairClass:    RepairClassNone,
		SupportLevel:   app.SupportLevel,
		Checks:         []ContractCheck{},
		EvidenceRefs:   contractEvidenceRefs(app),
	}
	add := func(check ContractCheck) {
		preflight.Checks = append(preflight.Checks, check)
		if check.Verdict != "ALLOW" && preflight.Verdict == "ALLOW" {
			preflight.ContractStatus = "REPAIR_REQUIRED"
			preflight.Verdict = check.Verdict
			preflight.ResultClass = check.ResultClass
			preflight.RepairClass = check.RepairClass
		}
	}

	add(contractBoolCheck("image.digest_parity", imageDigestParitySatisfied(app),
		"registry image@sha256, install digest, supply-chain evidence digest, and report digest match",
		app.Install.Digest, []string{imageDigest(app.Install.Image), app.SupplyChainEvidence.ArtifactDigest}, "launch_plan.json"))
	add(contractBoolCheck("command.parity", sameStrings(app.Runtime.Command, launch.RuntimeCommand),
		"runtime command and args are identical between AppSpec and LaunchPlan",
		app.Runtime.Command, launch.RuntimeCommand, "launch_plan.json"))
	add(contractBoolCheck("sandbox.local_container", substrate.Kind == "local-container" && substrate.Network.Default == "deny" && app.FilesystemPolicy.Mode == "scoped_workspace",
		"local-container sandbox uses deny-by-default network and scoped filesystem",
		map[string]string{"kind": "local-container", "network_default": "deny", "filesystem_mode": "scoped_workspace"},
		map[string]string{"kind": substrate.Kind, "network_default": substrate.Network.Default, "filesystem_mode": app.FilesystemPolicy.Mode}, "sandbox_grant.json"))
	add(contractBoolCheck("egress_proxy.artifact", egressProxySatisfied(app),
		"pinned egress proxy artifact, signature, SBOM, vulnerability scan, and receipt ref are declared when provider egress is required",
		true, app.FrameworkContract.EgressProxy, "receipts/launchpad-egress-proxy.json"))
	add(contractBoolCheck("paths.writable_home_cache_state", writablePathsSatisfied(app),
		"HOME/cache/state writable paths are declared for all app state mounts",
		app.FilesystemPolicy.Mounts, app.FrameworkContract.WritablePaths, "runtime_environment.json"))
	add(contractBoolCheck("secrets.scoped_projection", secretProjectionSatisfied(app),
		"provider secrets are scoped and redacted before runtime injection",
		app.RequiredSecrets, app.ModelGatewayEnv, "receipts/launchpad-secret-grants.json"))
	add(contractBoolCheck("mcp.manifest_parity", sameStrings(app.MCPManifests, app.FrameworkContract.MCPManifestRefs) && app.MCPPolicy.UnknownServerPolicy == "quarantine" && app.MCPPolicy.RequireSchemaPin,
		"MCP registry refs match the framework contract and unknown tools remain quarantined with schema pins",
		app.MCPManifests, app.FrameworkContract.MCPManifestRefs, "mcp_quarantine.json"))
	add(contractBoolCheck("healthcheck.runtime_path", healthcheckSatisfied(app),
		"healthcheck reaches the intended runtime path",
		declaredHealthchecks(app), app.FrameworkContract.Healthcheck, "receipts/launchpad-healthcheck.json"))
	add(contractBoolCheck("evidence.offline_verify", evidenceSatisfied(app),
		"EvidencePack export and offline verify are required before any F2 claim",
		[]string{"contract_preflight", "evidence_pack", "offline_verify"}, app.EvidenceRequirements, "04_EXPORTS/launchpad_manifest.json"))
	add(contractBoolCheck("runtime_installs.forbidden", runtimeInstallPolicySatisfied(app),
		"runtime installer patterns are forbidden; missing dependencies require image rebuild",
		"forbidden", app.FrameworkContract.RuntimeInstallPolicy, "launch_plan.json"))

	if preflight.Verdict == "ALLOW" {
		return preflight
	}
	if preflight.ResultClass == "" {
		preflight.ResultClass = ResultClassRuntimeRepairRequired
	}
	if preflight.RepairClass == "" {
		preflight.RepairClass = RepairClassContractRepairRequired
	}
	return preflight
}

func contractBoolCheck(id string, ok bool, message string, expected, actual any, evidenceRef string) ContractCheck {
	if ok {
		return ContractCheck{ID: id, Verdict: "ALLOW", RepairClass: RepairClassNone, Message: message, EvidenceRef: evidenceRef, Expected: expected, Actual: actual}
	}
	return ContractCheck{ID: id, Verdict: "DENY", ResultClass: ResultClassRuntimeRepairRequired, RepairClass: RepairClassContractRepairRequired, Message: message, EvidenceRef: evidenceRef, Expected: expected, Actual: actual}
}

func contractEvidenceRefs(app registry.AppSpec) []string {
	refs := []string{
		"contract_preflight.json",
		"launch_plan.json",
		"kernel_verdict.json",
		"sandbox_grant.json",
		"mcp_quarantine.json",
		"runtime_environment.json",
	}
	refs = append(refs, app.FrameworkContract.EvidenceRefs...)
	return refs
}

func imageDigestParitySatisfied(app registry.AppSpec) bool {
	if app.Install.Strategy == "byo_tool" {
		return app.SupportLevel == registry.SupportLevelExternalBYOAdapter
	}
	return app.Install.Image != "" && imageDigest(app.Install.Image) == app.Install.Digest && app.Install.Digest == app.SupplyChainEvidence.ArtifactDigest
}

func egressProxySatisfied(app registry.AppSpec) bool {
	proxy := app.FrameworkContract.EgressProxy
	if !proxy.Required {
		return !requiresProviderEgress(app)
	}
	return imageDigest(proxy.Image) == proxy.Digest &&
		strings.HasPrefix(proxy.Digest, "sha256:") &&
		proxy.SignatureRef != "" &&
		proxy.SBOMRef != "" &&
		proxy.VulnerabilityScanRef != "" &&
		proxy.ReceiptRef != ""
}

func requiresProviderEgress(app registry.AppSpec) bool {
	switch app.SupportLevel {
	case registry.SupportLevelAgentLive, registry.SupportLevelOSSSupported:
		return len(app.ModelGatewayEnv) > 0 || len(app.ModelGateway.ProviderIDs) > 0 || containsString(app.EvidenceRequirements, "model_gateway_broker")
	default:
		return false
	}
}

func writablePathsSatisfied(app registry.AppSpec) bool {
	paths := map[string]struct{}{}
	envs := map[string]struct{}{}
	for _, path := range app.FrameworkContract.WritablePaths {
		if path.Required && path.Path != "" {
			paths[path.Path] = struct{}{}
		}
		if path.Env != "" {
			envs[path.Env] = struct{}{}
		}
	}
	if app.FilesystemPolicy.StateDirEnv != "" {
		if _, ok := envs[app.FilesystemPolicy.StateDirEnv]; !ok {
			return false
		}
	}
	for _, mount := range app.FilesystemPolicy.Mounts {
		if strings.HasPrefix(mount, "workspace:") {
			continue
		}
		target := mountTarget(mount)
		if target == "" {
			return len(paths) > 0
		}
		if _, ok := paths[target]; !ok {
			return false
		}
	}
	return true
}

func secretProjectionSatisfied(app registry.AppSpec) bool {
	if len(app.RequiredSecrets) == 0 && len(app.ModelGatewayEnv) == 0 {
		return true
	}
	if app.SupportLevel == registry.SupportLevelExternalBYOAdapter {
		return len(app.RequiredSecrets) > 0
	}
	if app.ModelGateway.Mode == "" && len(app.ModelGatewayEnv) == 0 {
		return len(app.RequiredSecrets) > 0
	}
	if app.ModelGateway.Mode == "token_broker" {
		return !app.ModelGateway.RawProviderKeyProjected
	}
	return app.ModelGateway.Mode != "" && strings.TrimSpace(app.ModelGateway.LogicalSecret) != ""
}

func healthcheckSatisfied(app registry.AppSpec) bool {
	contractHealthcheck := strings.TrimSpace(app.FrameworkContract.Healthcheck)
	if contractHealthcheck == "" {
		return false
	}
	if len(app.Healthchecks) == 0 {
		return true
	}
	for _, healthcheck := range app.Healthchecks {
		if contractHealthcheck == strings.TrimSpace(healthcheck.Command) || contractHealthcheck == strings.TrimSpace(healthcheck.URL) {
			return true
		}
	}
	return false
}

func evidenceSatisfied(app registry.AppSpec) bool {
	return containsString(app.EvidenceRequirements, "contract_preflight") &&
		containsString(app.EvidenceRequirements, "evidence_pack") &&
		containsString(app.EvidenceRequirements, "offline_verify")
}

func runtimeInstallPolicySatisfied(app registry.AppSpec) bool {
	if app.FrameworkContract.RuntimeInstallPolicy != "forbidden" {
		return false
	}
	values := append([]string{strings.Join(app.Runtime.Command, " ")}, declaredHealthchecks(app)...)
	for _, pattern := range app.FrameworkContract.ForbiddenRuntimeInstallPatterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), pattern) {
				return false
			}
		}
	}
	return true
}

func imageDigest(image string) string {
	index := strings.LastIndex(image, "@sha256:")
	if index < 0 {
		return ""
	}
	return "sha256:" + image[index+len("@sha256:"):]
}

func declaredHealthchecks(app registry.AppSpec) []string {
	out := make([]string, 0, len(app.Healthchecks))
	for _, healthcheck := range app.Healthchecks {
		if healthcheck.Command != "" {
			out = append(out, healthcheck.Command)
		}
		if healthcheck.URL != "" {
			out = append(out, healthcheck.URL)
		}
	}
	return out
}

func sameStrings(left, right []string) bool {
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

func mountTarget(mount string) string {
	parts := strings.Split(mount, ":")
	if len(parts) >= 3 {
		return strings.TrimSpace(parts[2])
	}
	return ""
}
