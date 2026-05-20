package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

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
	base := LaunchPlan{
		LaunchID:                uuid.NewString(),
		AppID:                   app.ID,
		AppVersion:              app.Version,
		SubstrateID:             substrate.ID,
		Principal:               principal,
		ArtifactImage:           app.Install.Image,
		ArtifactDigest:          app.Install.Digest,
		RuntimeCommand:          cloneStrings(app.Runtime.Command),
		Healthchecks:            cloneHealthchecks(app.Healthchecks),
		ModelGatewayEnv:         cloneStrings(app.ModelGatewayEnv),
		ModelGatewayMode:        modelGatewayMode(app),
		ModelGatewayProvider:    app.ModelGateway.Provider,
		RawProviderKeyProjected: rawProviderKeyProjected(app),
		RiskClass:               app.RiskClass,
		PolicyHash:              policyHash,
		AppSpecHash:             appHash,
		SubstrateSpecHash:       substrateHash,
		SandboxProfileHash:      sandboxHash,
		RequiredSecretRefs:      requiredSecretRefs(app),
		NetworkAllowlist:        cloneStrings(app.NetworkPolicy.Allowlist),
		FilesystemMounts:        cloneStrings(app.FilesystemPolicy.Mounts),
		MCPPolicy:               app.MCPPolicy,
		Budgets:                 app.BudgetCeiling,
		Nodes:                   map[string]any{"plan": "launch", "app": app.ID, "substrate": substrate.ID},
		Edges:                   []any{},
		TeardownPlan:            map[string]any{"required": true, "receipt": "teardown_receipt", "cascade_supported": substrate.SupportsTeardown},
		EvidenceRequirements:    cloneStrings(app.EvidenceRequirements),
	}
	for _, secret := range requiredSecretEnvNames(app) {
		if value, ok := os.LookupEnv(secret); !ok || value == "" {
			base.KernelVerdict = "ESCALATE"
			base.Status = "ESCALATED"
			base.ReasonCode = "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING"
			base.Nodes["blocked"] = "required_secret_missing"
			base.Nodes["missing_secret"] = secret
			base.Nodes["required_secret_refs"] = base.RequiredSecretRefs
			finalizeStableIR(&base)
			cpiOutput, _ := EvaluateActions(base, base.ActionIR)
			base.CPIOutput = &cpiOutput
			finalizeStableIR(&base)
			return base, fmt.Errorf("app %s requires missing secret %s", app.ID, secret)
		}
	}
	if app.Availability != registry.AvailabilityOSSSupported || !app.Conformance.FullyVerified() {
		base.KernelVerdict = "ESCALATE"
		base.Status = "ESCALATED"
		base.ReasonCode = "ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED"
		base.Nodes["blocked"] = "app_conformance_required"
		finalizeStableIR(&base)
		cpiOutput, _ := EvaluateActions(base, base.ActionIR)
		base.CPIOutput = &cpiOutput
		finalizeStableIR(&base)
		return base, fmt.Errorf("app %s is not fully verified for Launchpad availability", app.ID)
	}
	base.KernelVerdict = "ALLOW"
	base.Status = "VALIDATED"
	finalizeStableIR(&base)
	cpiOutput, err := EvaluateActions(base, base.ActionIR)
	if err != nil {
		base.KernelVerdict = "ESCALATE"
		base.Status = "ESCALATED"
		base.ReasonCode = "ERR_LAUNCHPAD_CPI_UNAVAILABLE"
		finalizeStableIR(&base)
		return base, err
	}
	base.CPIOutput = &cpiOutput
	if cpiOutput.Verdict != CPIVerdictAllow {
		base.KernelVerdict = string(cpiOutput.Verdict)
		base.Status = "ESCALATED"
		base.ReasonCode = cpiOutput.ReasonCode
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
	}
	finalizeStableIR(&base)
	cpiOutput, _ := EvaluateActions(base, base.ActionIR)
	base.CPIOutput = &cpiOutput
	finalizeStableIR(&base)
	return base
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

func requiredSecretRefs(app registry.AppSpec) []string {
	refs := cloneStrings(app.RequiredSecrets)
	if modelGatewayMode(app) == "token_broker" && !containsString(refs, "model_gateway_token") {
		refs = append(refs, "model_gateway_token")
	}
	for _, envName := range app.ModelGatewayEnv {
		if !containsString(refs, envName) {
			refs = append(refs, envName)
		}
	}
	return refs
}

func requiredSecretEnvNames(app registry.AppSpec) []string {
	if modelGatewayMode(app) == "token_broker" {
		return []string{"HELM_MODEL_GATEWAY_TOKEN"}
	}
	if len(app.ModelGatewayEnv) > 0 {
		return cloneStrings(app.ModelGatewayEnv)
	}
	return cloneStrings(app.RequiredSecrets)
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
