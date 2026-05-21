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
