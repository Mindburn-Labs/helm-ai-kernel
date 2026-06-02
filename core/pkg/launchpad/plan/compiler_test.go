package plan

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestCompileEscalatesMissingSecretBeforeRuntime(t *testing.T) {
	t.Setenv("HELM_TEST_OPENAI_API_KEY", "")
	app := verifiedAppSpec()
	app.RequiredSecrets = []string{"HELM_TEST_OPENAI_API_KEY"}

	compiled, err := Compile(app, supportedSubstrate(), "console-test")
	if err == nil {
		t.Fatal("expected missing secret error")
	}
	if compiled.KernelVerdict != "ESCALATE" || compiled.Status != "ESCALATED" {
		t.Fatalf("expected ESCALATE/ESCALATED, got %s/%s", compiled.KernelVerdict, compiled.Status)
	}
	if compiled.ReasonCode != "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING" {
		t.Fatalf("unexpected reason code %q", compiled.ReasonCode)
	}
	if got := compiled.Nodes["missing_secret"]; got != "HELM_TEST_OPENAI_API_KEY" {
		t.Fatalf("missing secret was not bound into proof nodes: %#v", compiled.Nodes)
	}
}

func TestCompileDeniesBadArtifactBeforeSecretCheck(t *testing.T) {
	app := verifiedAppSpec()
	app.RequiredSecrets = []string{"HELM_TEST_NOT_SET_FOR_BAD_ARTIFACT"}
	app.SupplyChainEvidence.SignatureRef = ""

	compiled, err := Compile(app, supportedSubstrate(), "console-test")
	if err == nil {
		t.Fatal("expected artifact verification error")
	}
	if compiled.KernelVerdict != "DENY" || compiled.Status != "DENIED" {
		t.Fatalf("expected DENY/DENIED, got %s/%s", compiled.KernelVerdict, compiled.Status)
	}
	if compiled.ReasonCode != "ERR_LAUNCHPAD_COSIGN_SIGNATURE_REQUIRED" {
		t.Fatalf("unexpected reason code %q", compiled.ReasonCode)
	}
	if strings.Contains(err.Error(), "requires missing secret") {
		t.Fatalf("artifact verification must fail before secret checks: %v", err)
	}
}

func TestCompileAllowsBYOProviderWhenAnyDeclaredGatewayEnvIsPresent(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-anthropic")
	app := verifiedAppSpec()
	app.ModelGateway = registry.ModelGatewaySpec{
		LogicalSecret:           "model_gateway",
		Provider:                "byo",
		ProviderIDs:             []string{"openai", "anthropic"},
		Mode:                    "external_byo",
		RawProviderKeyProjected: true,
	}
	app.ModelGatewayEnv = []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}
	app.RequiredSecrets = []string{"model_gateway"}
	app.EvidenceRequirements = append(app.EvidenceRequirements, "model_gateway_broker")

	compiled, err := Compile(app, supportedSubstrate(), "console-test")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if compiled.KernelVerdict != "ALLOW" {
		t.Fatalf("expected ALLOW with one BYO provider key present, got %s", compiled.KernelVerdict)
	}
}

func TestCompileEscalatesBYOProviderWhenNoDeclaredGatewayEnvIsPresent(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	app := verifiedAppSpec()
	app.ModelGateway = registry.ModelGatewaySpec{
		LogicalSecret:           "model_gateway",
		Provider:                "byo",
		ProviderIDs:             []string{"openai", "anthropic"},
		Mode:                    "external_byo",
		RawProviderKeyProjected: true,
	}
	app.ModelGatewayEnv = []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}
	app.RequiredSecrets = []string{"model_gateway"}
	app.EvidenceRequirements = append(app.EvidenceRequirements, "model_gateway_broker")

	compiled, err := Compile(app, supportedSubstrate(), "console-test")
	if err == nil {
		t.Fatal("expected missing BYO provider secret error")
	}
	if got := compiled.Nodes["missing_secret"]; got != "one complete provider env group: ANTHROPIC_API_KEY or OPENAI_API_KEY" {
		t.Fatalf("missing secret = %#v", got)
	}
}

func TestCompileRequiresCompleteDynamicProviderEnvGroup(t *testing.T) {
	t.Setenv("AZURE_OPENAI_API_KEY", "sk-test-azure")
	t.Setenv("AZURE_OPENAI_ENDPOINT", "")
	app := verifiedAppSpec()
	app.ModelGateway = registry.ModelGatewaySpec{
		LogicalSecret:           "model_gateway",
		Provider:                "byo",
		ProviderIDs:             []string{"azure-openai"},
		Mode:                    "external_byo",
		RawProviderKeyProjected: true,
	}
	app.ModelGatewayEnv = nil
	app.NetworkPolicy.Allowlist = nil
	app.RequiredSecrets = []string{"model_gateway"}

	compiled, err := Compile(app, supportedSubstrate(), "console-test")
	if err == nil {
		t.Fatal("expected missing endpoint to fail the Azure provider env group")
	}
	if got := compiled.Nodes["missing_secret"]; got != "one complete provider env group: AZURE_OPENAI_API_KEY+AZURE_OPENAI_ENDPOINT" {
		t.Fatalf("missing secret = %#v", got)
	}

	t.Setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com/")
	compiled, err = Compile(app, supportedSubstrate(), "console-test")
	if err != nil {
		t.Fatalf("Compile with complete Azure group: %v", err)
	}
	if !containsString(compiled.NetworkAllowlist, "https://example.openai.azure.com") {
		t.Fatalf("dynamic Azure endpoint not added to allowlist: %#v", compiled.NetworkAllowlist)
	}
}

func TestCompileExpandsBYOProviderCatalogScope(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test-openai")
	t.Setenv("ANTHROPIC_API_KEY", "")
	app := verifiedAppSpec()
	app.ModelGateway = registry.ModelGatewaySpec{
		LogicalSecret:           "model_gateway",
		Provider:                "byo",
		ProviderIDs:             []string{"openai", "anthropic"},
		Mode:                    "external_byo",
		RawProviderKeyProjected: true,
	}
	app.ModelGatewayEnv = nil
	app.NetworkPolicy.Allowlist = nil
	app.RequiredSecrets = []string{"model_gateway"}
	app.EvidenceRequirements = append(app.EvidenceRequirements, "model_gateway_broker")

	compiled, err := Compile(app, supportedSubstrate(), "console-test")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !containsString(compiled.ModelGatewayEnv, "OPENAI_API_KEY") || !containsString(compiled.ModelGatewayEnv, "ANTHROPIC_API_KEY") {
		t.Fatalf("catalog provider env not expanded: %#v", compiled.ModelGatewayEnv)
	}
	if !containsString(compiled.NetworkAllowlist, "https://api.openai.com/v1") || !containsString(compiled.NetworkAllowlist, "https://api.anthropic.com/v1") {
		t.Fatalf("catalog provider allowlist not expanded: %#v", compiled.NetworkAllowlist)
	}
	if containsString(compiled.RequiredSecretRefs, "OPENAI_API_KEY") || containsString(compiled.RequiredSecretRefs, "ANTHROPIC_API_KEY") {
		t.Fatalf("BYO required secret refs must remain any-of logical refs, got %#v", compiled.RequiredSecretRefs)
	}
}

func verifiedAppSpec() registry.AppSpec {
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return registry.AppSpec{
		ID:             "openclaw",
		Name:           "OpenClaw",
		Version:        "0.1.0",
		Availability:   registry.AvailabilityOSSSupported,
		Redistribution: "oss",
		Install: registry.InstallSpec{
			Strategy: "signed_oci",
			Image:    "ghcr.io/mindburn-labs/openclaw@" + digest,
			Digest:   digest,
		},
		Runtime: registry.RuntimeSpec{Command: []string{"openclaw", "--serve"}},
		FilesystemPolicy: registry.PolicyRef{
			Mode:      "deny",
			Mounts:    []string{"/workspace:ro", "/tmp/helm-runs:rw"},
			PolicyRef: "oss.default.deny-by-default",
		},
		NetworkPolicy: registry.NetworkPolicy{Default: "deny", Allowlist: []string{"api.openai.com:443"}},
		MCPPolicy: registry.MCPPolicy{
			UnknownServerPolicy: "quarantine",
			UnknownToolPolicy:   "ESCALATE",
			RequireSchemaPin:    true,
		},
		Healthchecks:         []registry.HealthcheckSpec{{Type: "command", Command: "openclaw --version"}},
		EvidenceRequirements: []string{"launch_receipt", "healthcheck_receipt", "evidence_pack"},
		SupplyChainEvidence: registry.SupplyChainEvidenceSpec{
			ArtifactDigest:        digest,
			SignatureTool:         "cosign",
			SignatureRef:          "cosign://openclaw",
			SBOMTool:              "syft",
			SBOMRef:               "syft://openclaw",
			VulnerabilityScanTool: "grype",
			VulnerabilityScanRef:  "grype://openclaw",
		},
		Conformance: registry.ConformanceSpec{
			LicenseVerified:      true,
			ArtifactVerified:     true,
			PolicyPackPresent:    true,
			SandboxVerified:      true,
			HealthcheckPassing:   true,
			E2EPassing:           true,
			TeardownVerified:     true,
			ReceiptVerified:      true,
			EvidencePackVerified: true,
		},
	}
}

func supportedSubstrate() registry.SubstrateSpec {
	return registry.SubstrateSpec{
		ID:               "local-container",
		Name:             "Local container",
		Kind:             "local-container",
		Availability:     "supported",
		PolicyPack:       "oss.default.deny-by-default",
		SupportsTeardown: true,
		Network:          registry.NetworkPolicy{Default: "deny"},
		Filesystem:       registry.PolicyRef{Mode: "deny"},
	}
}
