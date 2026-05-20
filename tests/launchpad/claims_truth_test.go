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
