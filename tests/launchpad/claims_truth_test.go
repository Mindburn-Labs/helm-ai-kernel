package launchpad_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestLaunchpadClaimsDoNotMarketCandidateAppsAsSupported(t *testing.T) {
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
		if app.Availability == registry.AvailabilityOSSSupported {
			t.Fatalf("%s must remain below oss_supported until live conformance and EvidencePack verification pass", appID)
		}
	}

	for _, doc := range []string{
		"docs/LAUNCHPAD.md",
		"docs/launchpad/CLEAN_INSTALL_GA.md",
		"docs/launchpad/CONFORMANCE.md",
	} {
		body := readDoc(t, root, doc)
		for _, candidateCommand := range []string{
			"helm-ai-kernel launch opencode local-container --headless --output json",
			"helm-ai-kernel launch kilocode local-container --headless --output json",
		} {
			if strings.Contains(body, candidateCommand) {
				t.Fatalf("%s must not include candidate launch command %q as supported GA validation", doc, candidateCommand)
			}
		}
	}

	cleanGate := readDoc(t, root, "scripts/launch/clean_install_gate.sh")
	requireContains(t, cleanGate, "SUPPORTED_APPS=(openclaw hermes)")
	requireContains(t, cleanGate, "CANDIDATE_APPS=(opencode kilocode)")
	requireContains(t, cleanGate, "--include-candidates")

	artifactWorkflow := readDoc(t, root, ".github/workflows/launchpad-artifacts.yml")
	requireContains(t, artifactWorkflow, "run_candidate_live_conformance")
	requireContains(t, artifactWorkflow, "openclaw,hermes")
	requireContains(t, artifactWorkflow, "opencode,kilocode")
	requireContains(t, artifactWorkflow, "artifact_only_no_live_conformance")
	requireContains(t, artifactWorkflow, "if: ${{ always() }}")
}

func TestLiveConformanceDefaultsToSupportedAppsOnly(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_LIVE_APPS", "")
	t.Setenv("HELM_LAUNCHPAD_LIVE_INCLUDE_CANDIDATES", "")
	assertStringList(t, liveConformanceAppIDs(), []string{"openclaw", "hermes"})

	t.Setenv("HELM_LAUNCHPAD_LIVE_INCLUDE_CANDIDATES", "1")
	assertStringList(t, liveConformanceAppIDs(), []string{"openclaw", "hermes", "opencode", "kilocode"})

	t.Setenv("HELM_LAUNCHPAD_LIVE_APPS", " openclaw , hermes ")
	assertStringList(t, liveConformanceAppIDs(), []string{"openclaw", "hermes"})
}

func TestLaunchpadClaimsDoNotOverstateIsolationEgressOrWebSocketMCP(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"CONFORMANCE.md",
		"SECURITY_REVIEW.md",
		"FINAL_IMPLEMENTATION_REPORT.md",
		"THREAT_MODEL_ADDENDUM.md",
	} {
		body := strings.ToLower(readLaunchpadDoc(t, root, rel))
		for _, forbidden := range []string{
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
