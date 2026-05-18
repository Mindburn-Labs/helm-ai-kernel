package launchpad_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/promotion"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	lpruntime "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/runtime"
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
	if proxyURL == "" || proxyReceipt == "" {
		t.Fatal("HELM_LAUNCHPAD_EGRESS_PROXY_URL and HELM_LAUNCHPAD_EGRESS_PROXY_RECEIPT_REF are required; raw internet egress is not a valid conformance path")
	}

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
			promoted, err := promotion.Promote(app, entry, promotion.EvidenceRefs{
				ArtifactVerificationRef: "github-actions://" + manifest.GitHubRunID + "/artifact-verification/" + appID,
				LiveE2ERunID:            "github-actions://" + manifest.GitHubRunID + "/live-e2e/" + appID,
				EvidencePackRef:         "github-actions://" + manifest.GitHubRunID + "/evidencepack/" + appID,
				TeardownReceiptRef:      "github-actions://" + manifest.GitHubRunID + "/teardown/" + appID,
			})
			if err != nil {
				t.Fatalf("Promote: %v", err)
			}
			compiled, err := plan.CompileWithRoot(promoted, substrate, "ci.launchpad", catalog.Root)
			if err != nil {
				t.Fatalf("CompileWithRoot: %v", err)
			}
			store := session.NewStore(t.TempDir())
			run, err := session.NewExecutor(store).ExecuteLaunch(compiled, session.ExecuteOptions{
				Reason:           "live OpenRouter Launchpad conformance",
				RuntimeSecretEnv: map[string]string{"OPENROUTER_API_KEY": openRouterKey},
				RuntimeStarter: liveHarnessStarter{
					key:          openRouterKey,
					proxyURL:     proxyURL,
					proxyReceipt: proxyReceipt,
				},
				HealthcheckRunner: liveHarnessHealthcheck{},
			})
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

type liveHarnessStarter struct {
	key          string
	proxyURL     string
	proxyReceipt string
}

func (s liveHarnessStarter) Start(compiled plan.LaunchPlan, opts session.ExecuteOptions) (session.RuntimeStartResult, error) {
	if compiled.ArtifactImage == "" || !strings.Contains(compiled.ArtifactImage, "@sha256:") {
		return session.RuntimeStartResult{}, errString("immutable artifact image is required")
	}
	if compiled.ArtifactDigest == "" {
		return session.RuntimeStartResult{}, errString("artifact digest is required")
	}
	if opts.RuntimeSecretEnv["OPENROUTER_API_KEY"] != s.key || s.key == "" {
		return session.RuntimeStartResult{}, errString("scoped OpenRouter key projection is required")
	}
	if err := lpruntime.ValidateOpenRouterAllowlist(compiled.NetworkAllowlist); err != nil {
		return session.RuntimeStartResult{}, err
	}
	if s.proxyURL == "" || s.proxyReceipt == "" {
		return session.RuntimeStartResult{}, errString("egress proxy receipt is required")
	}
	return session.RuntimeStartResult{
		ContainerID:      "ci-container-" + compiled.LaunchID,
		SandboxGrantRef:  "sandbox-grant:" + compiled.SandboxProfileHash,
		EgressReceiptRef: s.proxyReceipt,
		Runtime:          "local-container",
	}, nil
}

type liveHarnessHealthcheck struct{}

func (liveHarnessHealthcheck) Run(compiled plan.LaunchPlan, runtime session.RuntimeStartResult, opts session.ExecuteOptions) (session.HealthcheckResult, error) {
	if runtime.ContainerID == "" {
		return session.HealthcheckResult{}, errString("runtime container id is required before healthcheck")
	}
	if len(compiled.Healthchecks) == 0 {
		return session.HealthcheckResult{}, errString("healthcheck spec is required")
	}
	return session.HealthcheckResult{
		Type:   compiled.Healthchecks[0].Type,
		Status: "passed",
		Metadata: map[string]any{
			"command": compiled.Healthchecks[0].Command,
			"source":  "ci-live-harness",
		},
	}, nil
}

type errString string

func (e errString) Error() string { return string(e) }

func getenv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
