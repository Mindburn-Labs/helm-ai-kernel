package launchpad_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestLaunchpadClaimsMarketPromotedAppsAsSupported(t *testing.T) {
	root := repoRoot(t)
	catalog, err := registry.LoadCatalog(root)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	for _, appID := range []string{"opencode", "kilocode"} {
		app, ok := catalog.App(appID)
		if !ok {
			t.Fatalf("%s missing from catalog", appID)
		}
		if app.Availability != registry.AvailabilityOSSSupported {
			t.Fatalf("%s availability = %s, want oss_supported after live conformance and EvidencePack verification", appID, app.Availability)
		}
	}

	for _, doc := range []string{
		"docs/LAUNCHPAD.md",
		"docs/launchpad/CLEAN_INSTALL_GA.md",
		"docs/launchpad/CONFORMANCE.md",
	} {
		body := readDoc(t, root, doc)
		for _, supportedCommand := range []string{
			"helm-ai-kernel launch opencode local-container --headless --output json",
			"helm-ai-kernel launch kilocode local-container --headless --output json",
		} {
			requireContains(t, body, supportedCommand)
		}
	}

	cleanGate := readDoc(t, root, "scripts/launch/clean_install_gate.sh")
	requireContains(t, cleanGate, "SUPPORTED_APPS=(openclaw hermes opencode kilocode)")
	requireContains(t, cleanGate, "--include-candidates")
	requireContains(t, cleanGate, `RELEASE_TAG="v0.5.5"`)
	requireContains(t, cleanGate, `ARTIFACT_RUN_ID="26186959337"`)
	requireContains(t, cleanGate, "output, status, commands_path")
	requireNotContains(t, cleanGate, "status = sys.stdin.read()", "scripts/launch/clean_install_gate.sh")
	requireContains(t, cleanGate, `"supported_apps": ["openclaw", "hermes", "opencode", "kilocode"]`)
	requireContains(t, cleanGate, `"candidate_promotion_apps": []`)
	requireContains(t, cleanGate, `"deprecated_include_candidates_flag": "accepted_noop_all_four_apps_are_supported"`)

	cleanWorkflow := readDoc(t, root, ".github/workflows/launchpad-clean-install.yml")
	requireContains(t, cleanWorkflow, "default: v0.5.5")
	requireContains(t, cleanWorkflow, `default: "26186959337"`)

	artifactWorkflow := readDoc(t, root, ".github/workflows/launchpad-artifacts.yml")
	requireContains(t, artifactWorkflow, "run_candidate_live_conformance")
	requireContains(t, artifactWorkflow, "include_candidate_artifacts")
	requireContains(t, artifactWorkflow, "Deprecated no-op")
	requireContains(t, artifactWorkflow, "Resolve Launchpad artifact matrix")
	requireContains(t, artifactWorkflow, "openclaw,hermes,opencode,kilocode")
	requireContains(t, artifactWorkflow, "opencode,kilocode")
	requireContains(t, artifactWorkflow, "artifact_only_no_live_conformance")
	requireContains(t, artifactWorkflow, ".app_id as $appID")
	requireContains(t, artifactWorkflow, "if: ${{ always() }}")
}

func TestLiveConformanceDefaultsToSupportedAppsOnly(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_LIVE_APPS", "")
	t.Setenv("HELM_LAUNCHPAD_LIVE_INCLUDE_CANDIDATES", "")
	assertStringList(t, liveConformanceAppIDs(), []string{"openclaw", "hermes", "opencode", "kilocode"})

	t.Setenv("HELM_LAUNCHPAD_LIVE_INCLUDE_CANDIDATES", "1")
	assertStringList(t, liveConformanceAppIDs(), []string{"openclaw", "hermes", "opencode", "kilocode"})

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
			"OpenCode and Kilo Code remain `oss_candidate`",
			"OpenCode and Kilo Code remain oss_candidate",
			"OpenCode and Kilo Code must pass",
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
