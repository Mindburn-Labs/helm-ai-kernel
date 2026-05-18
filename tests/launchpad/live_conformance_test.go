package launchpad_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/promotion"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func TestLiveOpenRouterLocalContainerConformance(t *testing.T) {
	if testing.Short() || getenv("HELM_LAUNCHPAD_LIVE_E2E") != "1" {
		t.Skip("live Launchpad conformance requires HELM_LAUNCHPAD_LIVE_E2E=1")
	}
	openRouterKey := getenv("OPENROUTER_API_KEY")
	if openRouterKey == "" {
		t.Fatal("OPENROUTER_API_KEY is required for live Launchpad conformance")
	}
	manifestPath := getenv("HELM_LAUNCHPAD_ARTIFACT_MANIFEST")
	if manifestPath == "" {
		t.Fatal("HELM_LAUNCHPAD_ARTIFACT_MANIFEST is required for live Launchpad conformance")
	}
	proxyURL := getenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL")
	proxyReceipt := getenv("HELM_LAUNCHPAD_EGRESS_PROXY_RECEIPT_REF")

	manifest, err := promotion.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	catalog, err := registry.LoadCatalog("")
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	for _, appID := range []string{"openclaw", "hermes"} {
		t.Run(appID, func(t *testing.T) {
			app, ok := catalog.App(appID)
			if !ok {
				t.Fatalf("app %s not found", appID)
			}
			substrate, ok := catalog.Substrate("local-container")
			if !ok {
				t.Fatal("local-container substrate not found")
			}
			entry, ok := manifest.Entry(appID)
			if !ok {
				t.Fatalf("artifact entry for %s not found", appID)
			}
			refs, err := manifest.EvidenceRefsFor(entry, promotion.EvidenceRefs{
				ArtifactVerificationRef: "github-actions://" + manifest.GitHubRunID + "/artifact-verification/" + appID,
				LiveE2ERunID:            "github-actions://" + manifest.GitHubRunID + "/live-e2e/" + appID,
				EvidencePackRef:         "github-actions://" + manifest.GitHubRunID + "/evidencepack/" + appID,
				TeardownReceiptRef:      "github-actions://" + manifest.GitHubRunID + "/teardown/" + appID,
			})
			if err != nil {
				t.Fatalf("EvidenceRefsFor: %v", err)
			}
			promoted, err := promotion.Promote(app, entry, refs)
			if err != nil {
				t.Fatalf("Promote: %v", err)
			}
			compiled, err := plan.CompileWithRoot(promoted, substrate, "ci.launchpad", catalog.Root)
			if err != nil {
				t.Fatalf("CompileWithRoot: %v", err)
			}
			store := session.NewStore(t.TempDir())
			compiled.RuntimeCommand = []string{"helm-launchpad-openrouter-check"}
			compiled.Healthchecks = []registry.HealthcheckSpec{{Type: "command", Command: "helm-launchpad-openrouter-check"}}
			opts := session.ExecuteOptions{
				Reason:           "live OpenRouter Launchpad conformance",
				WorkspaceMount:   t.TempDir(),
				RuntimeSecretEnv: map[string]string{"OPENROUTER_API_KEY": openRouterKey},
			}
			if proxyURL != "" {
				t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL", proxyURL)
			}
			if proxyReceipt != "" {
				t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_RECEIPT_REF", proxyReceipt)
			}
			run, err := session.NewExecutor(store).ExecuteLaunch(compiled, opts)
			if err != nil {
				t.Fatalf("ExecuteLaunch: %v", err)
			}
			if run.State != session.StateRunning {
				t.Fatalf("state = %s, want RUNNING: %+v", run.State, run)
			}
			deleted, err := session.NewExecutor(store).DeleteLaunch(run.LaunchID, true)
			if err != nil {
				t.Fatalf("DeleteLaunch: %v", err)
			}
			if deleted.State != session.StateDeleted || len(deleted.TeardownReceiptRefs) == 0 {
				t.Fatalf("teardown did not emit receipt: %+v", deleted)
			}
		})
	}
}

func getenv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
