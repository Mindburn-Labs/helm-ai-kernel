package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/modelproviders"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func Compile(app registry.AppSpec, substrate registry.SubstrateSpec, principal string) (LaunchPlan, error) {
	return CompileWithRoot(app, substrate, principal, "")
}

func CompileWithRoot(app registry.AppSpec, substrate registry.SubstrateSpec, principal, root string) (LaunchPlan, error) {
	if principal == "" {
		principal = "local.operator"
	}
	appHash := hashCanonical(app)
	substrateHash := hashCanonical(substrate)
	policyHash := hashPolicyRefs(root, app.FilesystemPolicy.PolicyRef, substrate.PolicyPack)
	sandboxHash := hashStrings(substrate.ID, substrate.Filesystem.Mode, substrate.Network.Default)
	modelGatewayEnv, err := modelGatewayEnvNames(app)
	if err != nil {
		return FailurePlan(app.ID, substrate.ID, principal, "ESCALATE", "ESCALATED", "ERR_LAUNCHPAD_MODEL_PROVIDER_CATALOG"), err
	}
	networkAllowlist, err := networkAllowlist(app)
	if err != nil {
		return FailurePlan(app.ID, substrate.ID, principal, "ESCALATE", "ESCALATED", "ERR_LAUNCHPAD_MODEL_PROVIDER_CATALOG"), err
	}
	base := LaunchPlan{
		LaunchID:                uuid.NewString(),
		AppID:                   app.ID,
		AppVersion:              app.Version,
		SubstrateID:             substrate.ID,
		Principal:               principal,
		ArtifactImage:           app.Install.Image,
		ArtifactDigest:          app.Install.Digest,
		SupportLevel:            app.SupportLevel,
		RuntimeCommand:          cloneStrings(app.Runtime.Command),
		RuntimeTimeout:          app.Runtime.Timeout,
		RuntimeDetached:         app.Runtime.Detached,
		RuntimeReadinessTimeout: app.Runtime.ReadinessTimeout,
		Healthchecks:            cloneHealthchecks(app.Healthchecks),
		ModelGatewayEnv:         modelGatewayEnv,
		ModelGatewayMode:        modelGatewayMode(app),
		ModelGatewayProvider:    app.ModelGateway.Provider,
		RawProviderKeyProjected: rawProviderKeyProjected(app),
		RiskClass:               app.RiskClass,
		PolicyHash:              policyHash,
		AppSpecHash:             appHash,
		SubstrateSpecHash:       substrateHash,
		SandboxProfileHash:      sandboxHash,
		RequiredSecretRefs:      requiredSecretRefs(app, modelGatewayEnv),
		NetworkAllowlist:        networkAllowlist,
		FilesystemMounts:        cloneStrings(app.FilesystemPolicy.Mounts),
		StateDirEnv:             app.FilesystemPolicy.StateDirEnv,
		MCPPolicy:               app.MCPPolicy,
		Budgets:                 app.BudgetCeiling,
		FrameworkContract:       app.FrameworkContract,
		Nodes:                   map[string]any{"plan": "launch", "app": app.ID, "substrate": substrate.ID},
		Edges:                   []any{},
		TeardownPlan:            map[string]any{"required": true, "receipt": "teardown_receipt", "cascade_supported": substrate.SupportsTeardown},
		EvidenceRequirements:    cloneStrings(app.EvidenceRequirements),
	}
	contractPreflight := BuildContractPreflight(app, substrate, base)
	base.ContractPreflight = &contractPreflight
	base.EvidenceRefs = cloneStrings(contractPreflight.EvidenceRefs)
	base.Nodes["contract_preflight"] = contractPreflight.Verdict
	base.Nodes["support_level"] = app.SupportLevel
	if contractPreflight.Verdict != "ALLOW" {
		base.KernelVerdict = "DENY"
		base.Status = "DENIED"
		base.ReasonCode = "ERR_LAUNCHPAD_F2_CONTRACT_REPAIR_REQUIRED"
		base.ResultClass = contractPreflight.ResultClass
		base.RepairClass = contractPreflight.RepairClass
		base.Nodes["blocked"] = "f2_contract_preflight_failed"
		finalizeStableIR(&base)
		cpiOutput, _ := EvaluateActions(base, base.ActionIR)
		base.CPIOutput = &cpiOutput
		finalizeStableIR(&base)
		return base, fmt.Errorf("app %s F2 contract preflight failed", app.ID)
	}
	if reason := artifactVerificationFailure(app); reason != "" {
		base.KernelVerdict = "DENY"
		base.Status = "DENIED"
		base.ReasonCode = reason
		base.ResultClass = ResultClassPlanDeny
		base.RepairClass = RepairClassContractRepairRequired
		base.Nodes["blocked"] = "artifact_verification_failed"
		finalizeStableIR(&base)
		cpiOutput, _ := EvaluateActions(base, base.ActionIR)
		base.CPIOutput = &cpiOutput
		finalizeStableIR(&base)
		return base, fmt.Errorf("app %s artifact verification failed: %s", app.ID, reason)
	}
	if missing := missingRequiredSecretEnv(app, modelGatewayEnv); missing != "" {
		base.KernelVerdict = "ESCALATE"
		base.Status = "ESCALATED"
		base.ReasonCode = "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING"
		base.ResultClass = ResultClassPlanEscalate
		base.RepairClass = RepairClassProviderSecretRequired
		base.Nodes["blocked"] = "required_secret_missing"
		base.Nodes["missing_secret"] = missing
		base.Nodes["required_secret_refs"] = base.RequiredSecretRefs
		finalizeStableIR(&base)
		cpiOutput, _ := EvaluateActions(base, base.ActionIR)
		base.CPIOutput = &cpiOutput
		finalizeStableIR(&base)
		return base, fmt.Errorf("app %s requires missing secret %s", app.ID, missing)
	}
	if app.SupportLevel != registry.SupportLevelVerifyOnly && (app.Availability != registry.AvailabilityOSSSupported || !app.Conformance.FullyVerified()) {
		base.KernelVerdict = "ESCALATE"
		base.Status = "ESCALATED"
		base.ReasonCode = "ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED"
		base.ResultClass = ResultClassPlanEscalate
		base.RepairClass = RepairClassContractRepairRequired
		base.Nodes["blocked"] = "app_conformance_required"
		finalizeStableIR(&base)
		cpiOutput, _ := EvaluateActions(base, base.ActionIR)
		base.CPIOutput = &cpiOutput
		finalizeStableIR(&base)
		return base, fmt.Errorf("app %s is not fully verified for Launchpad availability", app.ID)
	}
	base.KernelVerdict = "ALLOW"
	base.Status = "VALIDATED"
	base.RepairClass = RepairClassNone
	finalizeStableIR(&base)
	cpiOutput, err := EvaluateActions(base, base.ActionIR)
	if err != nil {
		base.KernelVerdict = "ESCALATE"
		base.Status = "ESCALATED"
		base.ReasonCode = "ERR_LAUNCHPAD_CPI_UNAVAILABLE"
		base.ResultClass = ResultClassPlanEscalate
		base.RepairClass = RepairClassContractRepairRequired
		finalizeStableIR(&base)
		return base, err
	}
	base.CPIOutput = &cpiOutput
	if cpiOutput.Verdict != CPIVerdictAllow {
		base.KernelVerdict = string(cpiOutput.Verdict)
		base.Status = "ESCALATED"
		base.ReasonCode = cpiOutput.ReasonCode
		base.ResultClass = ResultClassPlanEscalate
		base.RepairClass = RepairClassContractRepairRequired
		finalizeStableIR(&base)
		return base, fmt.Errorf("launchpad CPI verdict %s", cpiOutput.Verdict)
	}
	finalizeStableIR(&base)
	return base, nil
}

func FailurePlan(appID, substrateID, principal, verdict, status, reasonCode string) LaunchPlan {
	if principal == "" {
		principal = "local.operator"
	}
	base := LaunchPlan{
		LaunchID:             uuid.NewString(),
		AppID:                appID,
		SubstrateID:          substrateID,
		Principal:            principal,
		RiskClass:            "T1",
		PolicyHash:           hashStrings("missing-policy", appID, substrateID),
		AppSpecHash:          hashStrings("missing-app-spec", appID),
		SubstrateSpecHash:    hashStrings("missing-substrate-spec", substrateID),
		SandboxProfileHash:   hashStrings("missing-sandbox-profile", substrateID),
		RequiredSecretRefs:   []string{},
		NetworkAllowlist:     []string{},
		FilesystemMounts:     []string{},
		MCPPolicy:            registry.MCPPolicy{UnknownServerPolicy: "quarantine", UnknownToolPolicy: "ESCALATE", RequireSchemaPin: true},
		Budgets:              registry.BudgetCeiling{},
		Nodes:                map[string]any{"blocked": reasonCode},
		Edges:                []any{},
		TeardownPlan:         map[string]any{"required": true, "receipt": "teardown_receipt"},
		EvidenceRequirements: []string{"cpi_output", "kernel_verdict", "sandbox_grant", "launch_receipt", "teardown_receipt", "evidence_pack"},
		KernelVerdict:        verdict,
		Status:               status,
		ReasonCode:           reasonCode,
		ResultClass:          resultClassForFailurePlan(verdict, reasonCode),
		RepairClass:          repairClassForFailurePlan(reasonCode),
	}
	finalizeStableIR(&base)
	cpiOutput, _ := EvaluateActions(base, base.ActionIR)
	base.CPIOutput = &cpiOutput
	finalizeStableIR(&base)
	return base
}

func resultClassForFailurePlan(verdict, reasonCode string) ResultClass {
	switch verdict {
	case "DENY":
		if strings.Contains(reasonCode, "CONTRACT") {
			return ResultClassRuntimeRepairRequired
		}
		return ResultClassPlanDeny
	case "ALLOW":
		return ""
	default:
		return ResultClassPlanEscalate
	}
}

func repairClassForFailurePlan(reasonCode string) RepairClass {
	switch {
	case strings.Contains(reasonCode, "SECRET"):
		return RepairClassProviderSecretRequired
	case strings.Contains(reasonCode, "REPAIR"):
		return RepairClassRuntimeRepairRequired
	default:
		return RepairClassContractRepairRequired
	}
}

func hashCanonical(v any) string {
	data, _ := json.Marshal(v)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashStableLaunchPlan(plan LaunchPlan) string {
	stable := plan
	stable.LaunchID = ""
	stable.PlanHash = ""
	stable.CPIOutput = nil
	stable.ActionIR = nil
	stable.TeardownIR = nil
	return hashCanonical(stable)
}

func finalizeStableIR(plan *LaunchPlan) {
	plan.PlanHash = hashStableLaunchPlan(*plan)
	plan.ActionIR = CompileActionIR(*plan)
	plan.TeardownIR = CompileTeardownIR(*plan)
}

func hashStrings(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func hashPolicyRefs(root string, refs ...string) string {
	h := sha256.New()
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		path := ref
		if root != "" && !filepath.IsAbs(ref) {
			path = filepath.Join(root, ref)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			_, _ = h.Write([]byte(ref))
		} else {
			_, _ = h.Write(data)
		}
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneHealthchecks(in []registry.HealthcheckSpec) []registry.HealthcheckSpec {
	if in == nil {
		return []registry.HealthcheckSpec{}
	}
	out := make([]registry.HealthcheckSpec, len(in))
	copy(out, in)
	return out
}

func requiredSecretRefs(app registry.AppSpec, modelGatewayEnv []string) []string {
	refs := cloneStrings(app.RequiredSecrets)
	if modelGatewayMode(app) == "token_broker" && !containsString(refs, "model_gateway_token") {
		refs = append(refs, "model_gateway_token")
	}
	if modelGatewayAcceptsAnyProviderEnv(app, modelGatewayEnv) {
		return refs
	}
	for _, envName := range modelGatewayEnv {
		if !containsString(refs, envName) {
			refs = append(refs, envName)
		}
	}
	return refs
}

func requiredSecretEnvNames(app registry.AppSpec, modelGatewayEnv []string) []string {
	if modelGatewayMode(app) == "token_broker" {
		return []string{"HELM_MODEL_GATEWAY_TOKEN"}
	}
	if len(modelGatewayEnv) > 0 {
		return cloneStrings(modelGatewayEnv)
	}
	return cloneStrings(app.RequiredSecrets)
}

func missingRequiredSecretEnv(app registry.AppSpec, modelGatewayEnv []string) string {
	names := requiredSecretEnvNames(app, modelGatewayEnv)
	if len(names) == 0 {
		return ""
	}
	if modelGatewayAcceptsAnyProviderEnv(app, modelGatewayEnv) {
		for _, group := range modelGatewayRequiredEnvGroups(app, modelGatewayEnv) {
			complete := true
			for _, name := range group {
				if value, ok := os.LookupEnv(name); !ok || value == "" {
					complete = false
					break
				}
			}
			if complete {
				return ""
			}
		}
		return missingProviderEnvGroupMessage(modelGatewayRequiredEnvGroups(app, modelGatewayEnv))
	}
	for _, name := range names {
		if value, ok := os.LookupEnv(name); !ok || value == "" {
			return name
		}
	}
	return ""
}

func modelGatewayMode(app registry.AppSpec) string {
	if app.ModelGateway.Mode != "" {
		return app.ModelGateway.Mode
	}
	if len(app.ModelGatewayEnv) > 0 {
		return "raw_provider_key"
	}
	return ""
}

func modelGatewayAcceptsAnyProviderEnv(app registry.AppSpec, modelGatewayEnv []string) bool {
	provider := strings.ToLower(strings.TrimSpace(app.ModelGateway.Provider))
	return len(modelGatewayEnv) > 1 && (provider == "byo" || provider == "multi" || len(app.ModelGateway.ProviderIDs) > 1)
}

func modelGatewayUsesCatalog(app registry.AppSpec) bool {
	provider := strings.ToLower(strings.TrimSpace(app.ModelGateway.Provider))
	return provider == "byo" || provider == "multi"
}

func modelGatewayRequiredEnvGroups(app registry.AppSpec, modelGatewayEnv []string) [][]string {
	if !modelGatewayUsesCatalog(app) {
		groups := make([][]string, 0, len(modelGatewayEnv))
		for _, envName := range modelGatewayEnv {
			groups = append(groups, []string{envName})
		}
		return groups
	}
	catalog, err := modelproviders.DefaultCatalog()
	if err != nil {
		groups := make([][]string, 0, len(modelGatewayEnv))
		for _, envName := range modelGatewayEnv {
			groups = append(groups, []string{envName})
		}
		return groups
	}
	groups, err := catalog.EnvGroupsForProviderIDs(app.ModelGateway.ProviderIDs)
	if err != nil || len(groups) == 0 {
		groups = make([][]string, 0, len(modelGatewayEnv))
		for _, envName := range modelGatewayEnv {
			groups = append(groups, []string{envName})
		}
	}
	return groups
}

func modelGatewayEnvNames(app registry.AppSpec) ([]string, error) {
	if len(app.ModelGatewayEnv) > 0 {
		return cloneStrings(app.ModelGatewayEnv), nil
	}
	if !modelGatewayUsesCatalog(app) {
		return []string{}, nil
	}
	catalog, err := modelproviders.DefaultCatalog()
	if err != nil {
		return nil, err
	}
	return catalog.EnvNamesForProviderIDs(app.ModelGateway.ProviderIDs)
}

func networkAllowlist(app registry.AppSpec) ([]string, error) {
	if len(app.NetworkPolicy.Allowlist) > 0 || !modelGatewayUsesCatalog(app) {
		return cloneStrings(app.NetworkPolicy.Allowlist), nil
	}
	catalog, err := modelproviders.DefaultCatalog()
	if err != nil {
		return nil, err
	}
	return catalog.BaseURLsForProviderIDsWithEnv(app.ModelGateway.ProviderIDs, os.LookupEnv)
}

func rawProviderKeyProjected(app registry.AppSpec) bool {
	switch modelGatewayMode(app) {
	case "token_broker":
		return false
	case "raw_provider_key":
		return true
	default:
		return app.ModelGateway.RawProviderKeyProjected
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func formatEnvGroups(groups [][]string) string {
	formatted := make([]string, 0, len(groups))
	for _, group := range groups {
		formatted = append(formatted, strings.Join(group, "+"))
	}
	return strings.Join(formatted, " or ")
}

func missingProviderEnvGroupMessage(groups [][]string) string {
	if len(groups) > 8 {
		return "one complete catalog-backed provider env group"
	}
	return "one complete provider env group: " + formatEnvGroups(groups)
}

func artifactVerificationFailure(app registry.AppSpec) string {
	if app.Availability != registry.AvailabilityOSSSupported {
		return ""
	}
	if app.Install.Digest == "" || !strings.HasPrefix(app.Install.Digest, "sha256:") {
		return "ERR_LAUNCHPAD_ARTIFACT_DIGEST_NOT_PINNED"
	}
	if app.Install.Strategy == "signed_oci" && !strings.Contains(app.Install.Image, "@sha256:") {
		return "ERR_LAUNCHPAD_ARTIFACT_DIGEST_NOT_PINNED"
	}
	evidence := app.SupplyChainEvidence
	if evidence.ArtifactDigest == "" || evidence.ArtifactDigest != app.Install.Digest {
		return "ERR_LAUNCHPAD_ARTIFACT_DIGEST_MISMATCH"
	}
	if strings.ToLower(evidence.SignatureTool) != "cosign" || evidence.SignatureRef == "" {
		return "ERR_LAUNCHPAD_COSIGN_SIGNATURE_REQUIRED"
	}
	if strings.ToLower(evidence.SBOMTool) != "syft" || evidence.SBOMRef == "" {
		return "ERR_LAUNCHPAD_SBOM_REQUIRED"
	}
	scanTool := strings.ToLower(evidence.VulnerabilityScanTool)
	if (scanTool != "grype" && scanTool != "trivy") || evidence.VulnerabilityScanRef == "" {
		return "ERR_LAUNCHPAD_VULNERABILITY_SCAN_REQUIRED"
	}
	return ""
}
