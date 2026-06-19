package launchpad_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestLaunchpadClaimsReflectContractFirstSupportLevels(t *testing.T) {
	root := repoRoot(t)
	releaseTag := chartReleaseTag(t, root)
	catalog, err := registry.LoadCatalog(root)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	for _, appID := range []string{"opencode", "kilocode"} {
		app, ok := catalog.App(appID)
		if !ok {
			t.Fatalf("%s missing from catalog", appID)
		}
		if app.Availability == registry.AvailabilityOSSSupported || app.SupportLevel != registry.SupportLevelVerifyOnly {
			t.Fatalf("%s availability/support_level = %s/%s, want non-oss verify_only until live-agent command evidence exists", appID, app.Availability, app.SupportLevel)
		}
	}

	for _, doc := range []string{
		"docs/LAUNCHPAD.md",
		"docs/launchpad/CLEAN_INSTALL_GA.md",
		"docs/launchpad/CONFORMANCE.md",
	} {
		body := readDoc(t, root, doc)
		for _, verifyOnlyClaim := range []string{
			"OpenCode | `verify_only`",
			"Kilo Code | `verify_only`",
			"`--version` smoke checks do not count as live-agent F2 coverage",
		} {
			requireContains(t, body, verifyOnlyClaim)
		}
	}

	cleanGate := readDoc(t, root, "scripts/launch/clean_install_gate.sh")
	requireContains(t, cleanGate, "SUPPORTED_APPS=(openclaw hermes)")
	requireContains(t, cleanGate, "VERIFY_ONLY_APPS=(opencode kilocode)")
	requireContains(t, cleanGate, "--include-candidates")
	requireContains(t, cleanGate, `RELEASE_TAG="`+releaseTag+`"`)
	requireContains(t, cleanGate, `ARTIFACT_RUN_ID="26198407296"`)
	requireContains(t, cleanGate, "output, status, commands_path")
	requireNotContains(t, cleanGate, "status = sys.stdin.read()", "scripts/launch/clean_install_gate.sh")
	requireContains(t, cleanGate, `"supported_apps": ["openclaw", "hermes"]`)
	requireContains(t, cleanGate, `"verify_only_apps": ["opencode", "kilocode"]`)
	requireContains(t, cleanGate, `"candidate_promotion_apps": []`)
	requireContains(t, cleanGate, `"deprecated_include_candidates_flag": "accepted_noop_verify_only_apps_are_not_launched"`)
	requireContains(t, cleanGate, "gh run list --repo \"$REPO\" --workflow release.yml --branch \"$RELEASE_TAG\"")
	requireNotContains(t, cleanGate, "gh run view 26131090671", "scripts/launch/clean_install_gate.sh")

	cleanWorkflow := readDoc(t, root, ".github/workflows/launchpad-clean-install.yml")
	requireContains(t, cleanWorkflow, "default: "+releaseTag)
	requireContains(t, cleanWorkflow, `default: "26198407296"`)
	requireContains(t, cleanWorkflow, "brew install colima docker jq qemu lima-additional-guestagents")
	requireContains(t, cleanWorkflow, "colima delete -f")

	artifactWorkflow := readDoc(t, root, ".github/workflows/launchpad-artifacts.yml")
	requireContains(t, artifactWorkflow, "run_candidate_live_conformance")
	requireContains(t, artifactWorkflow, "include_candidate_artifacts")
	requireContains(t, artifactWorkflow, "Deprecated no-op")
	requireContains(t, artifactWorkflow, "Resolve Launchpad artifact matrix")
	requireContains(t, artifactWorkflow, "openclaw,hermes")
	requireContains(t, artifactWorkflow, `"app_id": "opencode"`)
	requireContains(t, artifactWorkflow, `"app_id": "kilocode"`)
	requireContains(t, artifactWorkflow, "artifact_only_no_live_conformance")
	requireContains(t, artifactWorkflow, ".app_id as $appID")
	requireContains(t, artifactWorkflow, "if: ${{ always() }}")
}

func TestLaunchpadF2ReportsRequireContractEvidenceArtifacts(t *testing.T) {
	root := repoRoot(t)
	report := readDoc(t, root, "docs/launchpad/v1_report.json")
	for _, want := range []string{
		`"stage": "f2_contract_preflight"`,
		`"required_before_attack_matrix": true`,
		`"setup_failures_count_as_attack_blocked": false`,
		`"contract_preflight_json"`,
		`"launch_plan"`,
		`"kernel_verdict"`,
		`"sandbox_grant"`,
		`"egress_proxy_receipt"`,
		`"mcp_quarantine_receipt"`,
		`"healthcheck_receipt"`,
		`"runtime_environment"`,
		`"EvidencePack"`,
		`"offline_verify_output"`,
		`"raw_per_case_results"`,
		`"MODEL_REFUSED"`,
		`"INPUT_BLOCKED"`,
		`"TOOL_BLOCKED"`,
		`"EGRESS_DENIED"`,
		`"MCP_QUARANTINED"`,
		`"PLAN_DENY"`,
		`"PLAN_ESCALATE"`,
		`"RUNTIME_REPAIR_REQUIRED"`,
		`"ATTACK_BLOCKED"`,
		`"runtime_installs": "forbidden"`,
		`"egress_proxy_artifact"`,
		`"production_minimal"`,
		`"eval_full"`,
	} {
		requireContains(t, report, want)
	}
	requireNotContains(t, report, `"controlled_live_apps": [
        "openclaw",
        "hermes",
        "opencode",
        "kilocode"
      ]`, "docs/launchpad/v1_report.json")
}

func TestLaunchConformanceReviewOracleIsWired(t *testing.T) {
	root := repoRoot(t)
	oracle := readDoc(t, root, "docs/launchpad/launch-conformance.md")
	for _, want := range []string{
		"U-LAUNCH-02",
		"U-LAUNCH-03",
		"ERR_LAUNCHPAD_F2_CONTRACT_REPAIR_REQUIRED",
		"ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING",
		"ERR_MCP_SERVER_QUARANTINED",
		"`curl | bash`",
		"`git pull` in `current/`",
		"`npm install` in `current/`",
		"`launchpad-egress-proxy.json`",
		"`helm-ai-kernel verify --bundle <pack>`",
	} {
		requireContains(t, oracle, want)
	}

	conformance := readDoc(t, root, "docs/launchpad/CONFORMANCE.md")
	requireContains(t, conformance, "docs/launchpad/launch-conformance.md")

	prTemplate := readDoc(t, root, ".github/PULL_REQUEST_TEMPLATE.md")
	requireContains(t, prTemplate, "docs/launchpad/launch-conformance.md")
}

func TestLiveConformanceDefaultsToSupportedAppsOnly(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_LIVE_APPS", "")
	t.Setenv("HELM_LAUNCHPAD_LIVE_INCLUDE_CANDIDATES", "")
	assertStringList(t, liveConformanceAppIDs(), []string{"openclaw", "hermes"})

	t.Setenv("HELM_LAUNCHPAD_LIVE_INCLUDE_CANDIDATES", "1")
	assertStringList(t, liveConformanceAppIDs(), []string{"openclaw", "hermes"})

	t.Setenv("HELM_LAUNCHPAD_LIVE_APPS", " openclaw , hermes ")
	assertStringList(t, liveConformanceAppIDs(), []string{"openclaw", "hermes"})
}

func TestLaunchpadCurrentDocsDoNotUseStaleCandidateLanguage(t *testing.T) {
	root := repoRoot(t)
	for _, doc := range []string{
		"docs/LAUNCHPAD.md",
		"docs/launchpad/APP_SPEC.md",
		"docs/launchpad/CLEAN_INSTALL_GA.md",
		"docs/launchpad/CONFORMANCE.md",
		"docs/launchpad/FLOW_CATALOG.md",
		"docs/launchpad/SECURITY_REVIEW.md",
		"docs/launchpad/THREAT_MODEL_ADDENDUM.md",
	} {
		body := readDoc(t, root, doc)
		for _, stale := range []string{
			"OpenCode and Kilo Code are `oss_supported`",
			"OpenCode and Kilo Code are oss_supported",
			"OpenCode and Kilo Code pass live-agent F2",
			"OpenClaw and Hermes are release-backed",
			"OpenClaw and Hermes are `oss_supported` from signed `v0.5.4`",
		} {
			requireNotContains(t, body, stale, doc)
		}
	}
}

func TestHistoricalLaunchpadReportsDeclareSupersededTruth(t *testing.T) {
	root := repoRoot(t)
	report := readDoc(t, root, "docs/launchpad/FINAL_IMPLEMENTATION_REPORT.md")
	requireContains(t, report, "historical `v0.5.4` production report")
	requireContains(t, report, "This file is not the current Launchpad GA support truth")
	requireContains(t, report, "docs/launchpad/v1_report.json")
	requireContains(t, report, "OpenClaw, Hermes,")
	requireContains(t, report, "OpenCode, and Kilo Code are `oss_supported`")

	jsonReport := readDoc(t, root, "docs/launchpad/final_report.json")
	requireContains(t, jsonReport, `"historical_report": true`)
	requireContains(t, jsonReport, `"superseded_by": "docs/launchpad/v1_report.json"`)
	requireContains(t, jsonReport, `"artifact_workflow_run_id": "26186959337"`)
	requireContains(t, jsonReport, `"opencode"`)
	requireContains(t, jsonReport, `"kilocode"`)
}

func TestLaunchpadClaimsDoNotOverstateIsolationEgressOrWebSocketMCP(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"CONFORMANCE.md",
		"SECURITY_REVIEW.md",
		"FINAL_IMPLEMENTATION_REPORT.md",
		"THREAT_MODEL_ADDENDUM.md",
		"v1_report.json",
	} {
		body := strings.ToLower(readLaunchpadDoc(t, root, rel))
		for _, forbidden := range []string{
			"market_best",
			"best on market",
			"no sensitive prompt data left",
			"hostile-agent-grade docker",
			"websocket mcp is supported",
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s contains unsupported claim %q", rel, forbidden)
			}
		}
	}
}

func readLaunchpadDoc(t *testing.T, root, rel string) string {
	t.Helper()
	return readDoc(t, root, filepath.Join("docs", "launchpad", rel))
}

func readDoc(t *testing.T, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func chartReleaseTag(t *testing.T, root string) string {
	t.Helper()
	body := readDoc(t, root, "deploy/helm-chart/Chart.yaml")
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "version:") {
			continue
		}
		version := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version:")), `"'`)
		if version == "" {
			t.Fatalf("deploy/helm-chart/Chart.yaml has empty version")
		}
		return "v" + version
	}
	t.Fatalf("deploy/helm-chart/Chart.yaml missing version")
	return ""
}

func requireContains(t *testing.T, content, want string) {
	t.Helper()
	if !strings.Contains(content, want) {
		t.Fatalf("expected content to contain %q", want)
	}
}

func requireNotContains(t *testing.T, content, forbidden, doc string) {
	t.Helper()
	if strings.Contains(content, forbidden) {
		t.Fatalf("%s contains stale claim %q", doc, forbidden)
	}
}

func assertStringList(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("list length = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("list[%d] = %q in %v, want %q in %v", i, got[i], got, want[i], want)
		}
	}
}
