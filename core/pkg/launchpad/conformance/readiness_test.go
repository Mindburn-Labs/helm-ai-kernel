package conformance

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestMissionReadinessRequiresOpenRouterSecret(t *testing.T) {
	app := supportedFixture()
	substrate := localContainerFixture()
	report := EvaluateMissionReadiness(app, substrate, Options{
		EnvLookup:  func(string) (string, bool) { return "", false },
		ToolLookup: presentTools,
	})
	if report.Verdict != "ESCALATE" {
		t.Fatalf("missing OpenRouter secret must escalate, got %s", report.Verdict)
	}
	if !hasBlocker(report, "secret.OPENROUTER_API_KEY") {
		t.Fatalf("expected OPENROUTER_API_KEY blocker, got %#v", report.Blockers)
	}
}

func TestMissionReadinessRequiresSignedOCIEvidence(t *testing.T) {
	app := supportedFixture()
	app.Install.Digest = ""
	app.SupplyChainEvidence = registry.SupplyChainEvidenceSpec{}
	substrate := localContainerFixture()
	report := EvaluateMissionReadiness(app, substrate, Options{
		EnvLookup:  func(string) (string, bool) { return "sk-test", true },
		ToolLookup: presentTools,
	})
	for _, blocker := range []string{"artifact.digest", "artifact.cosign_signature", "artifact.sbom", "artifact.vulnerability_scan"} {
		if !hasBlocker(report, blocker) {
			t.Fatalf("expected %s blocker, got %#v", blocker, report.Blockers)
		}
	}
}

func TestMissionReadinessAllowsFullyVerifiedSignedOCI(t *testing.T) {
	app := supportedFixture()
	substrate := localContainerFixture()
	report := EvaluateMissionReadiness(app, substrate, Options{
		EnvLookup:  func(string) (string, bool) { return "sk-test", true },
		ToolLookup: presentTools,
	})
	if report.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %#v", report)
	}
}

func supportedFixture() registry.AppSpec {
	return registry.AppSpec{
		ID:              "openclaw",
		Availability:    registry.AvailabilityOSSSupported,
		ModelGatewayEnv: []string{"OPENROUTER_API_KEY"},
		Install: registry.InstallSpec{
			Strategy: "signed_oci",
			Image:    "ghcr.io/mindburn-labs/helm-launchpad/openclaw@sha256:" + strings.Repeat("a", 64),
			Digest:   "sha256:" + strings.Repeat("a", 64),
		},
		SupplyChainEvidence: registry.SupplyChainEvidenceSpec{
			ArtifactDigest:        "sha256:" + strings.Repeat("a", 64),
			SignatureTool:         "cosign",
			SignatureRef:          "oci://ghcr.io/mindburn-labs/helm-launchpad/openclaw:v2026.5.12.sig",
			SBOMTool:              "syft",
			SBOMRef:               "oci://ghcr.io/mindburn-labs/helm-launchpad/openclaw:v2026.5.12.sbom",
			VulnerabilityScanTool: "grype",
			VulnerabilityScanRef:  "oci://ghcr.io/mindburn-labs/helm-launchpad/openclaw:v2026.5.12.grype",
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

func localContainerFixture() registry.SubstrateSpec {
	return registry.SubstrateSpec{
		ID:           "local-container",
		Availability: "supported",
		Network:      registry.NetworkPolicy{Default: "deny"},
	}
}

func presentTools(name string) (string, bool) {
	switch name {
	case "docker", "cosign", "syft", "grype":
		return "/usr/bin/" + name, true
	default:
		return "", false
	}
}

func hasBlocker(report ReadinessReport, blocker string) bool {
	for _, value := range report.Blockers {
		if value == blocker {
			return true
		}
	}
	return false
}
