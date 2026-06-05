package plan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestCoverageFailurePlanDefaultsAndStableIR(t *testing.T) {
	plan := FailurePlan("app-a", "substrate-a", "", "ESCALATE", "ESCALATED", "ERR_TEST")

	if plan.Principal != "local.operator" {
		t.Fatalf("principal = %q, want local.operator", plan.Principal)
	}
	if plan.KernelVerdict != "ESCALATE" || plan.Status != "ESCALATED" || plan.ReasonCode != "ERR_TEST" {
		t.Fatalf("unexpected verdict/status/reason: %s/%s/%s", plan.KernelVerdict, plan.Status, plan.ReasonCode)
	}
	if plan.PlanHash == "" || plan.ActionIR == nil || plan.TeardownIR == nil || plan.CPIOutput == nil {
		t.Fatalf("failure plan was not finalized: hash=%q action=%v teardown=%v cpi=%v", plan.PlanHash, plan.ActionIR, plan.TeardownIR, plan.CPIOutput)
	}
	if !containsString(plan.EvidenceRequirements, "evidence_pack") {
		t.Fatalf("failure plan evidence requirements missing evidence_pack: %#v", plan.EvidenceRequirements)
	}
}

func TestCoverageCompileEscalatesUnverifiedConformance(t *testing.T) {
	app := verifiedAppSpec()
	app.Conformance.E2EPassing = false

	compiled, err := Compile(app, supportedSubstrate(), "")
	if err == nil {
		t.Fatal("expected conformance escalation error")
	}
	if compiled.Principal != "local.operator" {
		t.Fatalf("default principal = %q, want local.operator", compiled.Principal)
	}
	if compiled.KernelVerdict != "ESCALATE" || compiled.Status != "ESCALATED" {
		t.Fatalf("expected ESCALATE/ESCALATED, got %s/%s", compiled.KernelVerdict, compiled.Status)
	}
	if compiled.ReasonCode != "ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED" {
		t.Fatalf("reason = %q", compiled.ReasonCode)
	}
}

func TestCoveragePolicyHashReadsRelativeAndAbsoluteRefs(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "policy.rego")
	if err := os.WriteFile(policyPath, []byte("package launchpad\nallow := true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	relative := hashPolicyRefs(root, "", "policy.rego", "missing.rego")
	absolute := hashPolicyRefs("", policyPath, "missing.rego")
	if relative != absolute {
		t.Fatalf("relative root hash = %s, absolute hash = %s", relative, absolute)
	}
	if relative == hashPolicyRefs("", "policy.rego", "missing.rego") {
		t.Fatal("policy file contents should affect hash when read through root")
	}
}

func TestCoverageModelGatewayHelperEdges(t *testing.T) {
	tokenBroker := verifiedAppSpec()
	tokenBroker.ModelGateway.Mode = "token_broker"
	tokenBroker.ModelGatewayEnv = []string{"RAW_PROVIDER_KEY"}
	tokenBroker.RequiredSecrets = []string{"existing_secret"}
	if rawProviderKeyProjected(tokenBroker) {
		t.Fatal("token broker mode must not project raw provider keys")
	}
	if got := requiredSecretEnvNames(tokenBroker, []string{"RAW_PROVIDER_KEY"}); len(got) != 1 || got[0] != "HELM_MODEL_GATEWAY_TOKEN" {
		t.Fatalf("token broker env names = %#v", got)
	}
	if refs := requiredSecretRefs(tokenBroker, []string{"RAW_PROVIDER_KEY"}); !containsString(refs, "model_gateway_token") {
		t.Fatalf("token broker refs missing broker token: %#v", refs)
	}

	rawKey := verifiedAppSpec()
	rawKey.ModelGateway.Mode = "raw_provider_key"
	if !rawProviderKeyProjected(rawKey) {
		t.Fatal("raw provider key mode should project raw key")
	}

	flagged := verifiedAppSpec()
	flagged.ModelGateway.RawProviderKeyProjected = true
	if !rawProviderKeyProjected(flagged) {
		t.Fatal("explicit raw provider projection flag should be honored")
	}
	if mode := modelGatewayMode(verifiedAppSpec()); mode != "" {
		t.Fatalf("empty gateway mode = %q", mode)
	}

	nonCatalogGroups := modelGatewayRequiredEnvGroups(registry.AppSpec{}, []string{"A", "B"})
	if len(nonCatalogGroups) != 2 || nonCatalogGroups[0][0] != "A" || nonCatalogGroups[1][0] != "B" {
		t.Fatalf("non-catalog groups = %#v", nonCatalogGroups)
	}

	fallbackGroups := modelGatewayRequiredEnvGroups(registry.AppSpec{
		ModelGateway: registry.ModelGatewaySpec{Provider: "byo", ProviderIDs: []string{"missing-provider"}},
	}, []string{"A", "B"})
	if len(fallbackGroups) != 2 || fallbackGroups[0][0] != "A" || fallbackGroups[1][0] != "B" {
		t.Fatalf("catalog fallback groups = %#v", fallbackGroups)
	}

	var manyGroups [][]string
	for i := 0; i < 9; i++ {
		manyGroups = append(manyGroups, []string{string(rune('A' + i))})
	}
	if msg := missingProviderEnvGroupMessage(manyGroups); msg != "one complete catalog-backed provider env group" {
		t.Fatalf("large group message = %q", msg)
	}

	t.Setenv("SIMPLE_SECRET", "set")
	simpleSecret := verifiedAppSpec()
	simpleSecret.RequiredSecrets = []string{"SIMPLE_SECRET"}
	if missing := missingRequiredSecretEnv(simpleSecret, nil); missing != "" {
		t.Fatalf("complete simple secret reported missing: %q", missing)
	}
}

func TestCoverageArtifactVerificationFailureReasons(t *testing.T) {
	valid := verifiedAppSpec()
	unsupported := valid
	unsupported.Availability = "enterprise-only"
	if reason := artifactVerificationFailure(unsupported); reason != "" {
		t.Fatalf("unsupported app should skip artifact verification, got %q", reason)
	}

	cases := []struct {
		name   string
		mutate func(*registry.AppSpec)
		want   string
	}{
		{
			name: "digest missing",
			mutate: func(app *registry.AppSpec) {
				app.Install.Digest = ""
			},
			want: "ERR_LAUNCHPAD_ARTIFACT_DIGEST_NOT_PINNED",
		},
		{
			name: "signed image not pinned",
			mutate: func(app *registry.AppSpec) {
				app.Install.Image = strings.TrimSuffix(app.Install.Image, "@"+app.Install.Digest)
			},
			want: "ERR_LAUNCHPAD_ARTIFACT_DIGEST_NOT_PINNED",
		},
		{
			name: "evidence digest mismatch",
			mutate: func(app *registry.AppSpec) {
				app.SupplyChainEvidence.ArtifactDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			},
			want: "ERR_LAUNCHPAD_ARTIFACT_DIGEST_MISMATCH",
		},
		{
			name: "sbom missing",
			mutate: func(app *registry.AppSpec) {
				app.SupplyChainEvidence.SBOMRef = ""
			},
			want: "ERR_LAUNCHPAD_SBOM_REQUIRED",
		},
		{
			name: "vulnerability scan missing",
			mutate: func(app *registry.AppSpec) {
				app.SupplyChainEvidence.VulnerabilityScanTool = "other"
			},
			want: "ERR_LAUNCHPAD_VULNERABILITY_SCAN_REQUIRED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := verifiedAppSpec()
			tc.mutate(&app)
			if got := artifactVerificationFailure(app); got != tc.want {
				t.Fatalf("artifactVerificationFailure() = %q, want %q", got, tc.want)
			}
		})
	}
	if reason := artifactVerificationFailure(valid); reason != "" {
		t.Fatalf("valid artifact reason = %q", reason)
	}
}
