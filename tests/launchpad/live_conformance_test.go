package launchpad_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/promotion"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
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

	for _, appID := range liveConformanceAppIDs() {
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
			verifyLiveEvidenceRefs(t, appID, deleted.EvidencePackRefs)
			copyLiveEvidenceRefs(t, appID, deleted.EvidencePackRefs)
		})
	}
}

var (
	defaultLiveConformanceApps   = []string{"openclaw", "hermes"}
	candidateLiveConformanceApps = []string{"opencode", "kilocode"}
)

func liveConformanceAppIDs() []string {
	if override := getenv("HELM_LAUNCHPAD_LIVE_APPS"); override != "" {
		return splitAppIDs(override)
	}
	apps := append([]string(nil), defaultLiveConformanceApps...)
	if truthy(getenv("HELM_LAUNCHPAD_LIVE_INCLUDE_CANDIDATES")) {
		apps = append(apps, candidateLiveConformanceApps...)
	}
	return apps
}

func splitAppIDs(value string) []string {
	parts := strings.Split(value, ",")
	apps := make([]string, 0, len(parts))
	for _, part := range parts {
		if appID := strings.TrimSpace(part); appID != "" {
			apps = append(apps, appID)
		}
	}
	return apps
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func verifyLiveEvidenceRefs(t *testing.T, appID string, refs []string) {
	t.Helper()
	var dirRef string
	var archiveRef string
	for _, ref := range refs {
		info, err := os.Stat(ref)
		if err != nil {
			continue
		}
		if info.IsDir() && dirRef == "" {
			dirRef = ref
		}
		if !info.IsDir() && strings.HasSuffix(ref, ".tar") && archiveRef == "" {
			archiveRef = ref
		}
	}
	if dirRef == "" {
		t.Fatalf("%s did not produce an EvidencePack directory ref: %#v", appID, refs)
	}
	if archiveRef == "" {
		t.Fatalf("%s did not produce an EvidencePack tar archive ref: %#v", appID, refs)
	}
	report, err := verifier.VerifyBundle(dirRef)
	if err != nil {
		t.Fatalf("%s EvidencePack directory verifier error: %v", appID, err)
	}
	if !report.Verified {
		t.Fatalf("%s EvidencePack directory did not verify: %s", appID, report.Summary)
	}
	root := repoRoot(t)
	cmd := exec.Command("go", "run", "./core/cmd/helm-ai-kernel", "verify", "--bundle", archiveRef, "--json")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s EvidencePack tar did not verify offline: %v\n%s", appID, err, string(out))
	}
}

func copyLiveEvidenceRefs(t *testing.T, appID string, refs []string) {
	t.Helper()
	outputRoot := getenv("HELM_LAUNCHPAD_LIVE_EVIDENCE_DIR")
	if outputRoot == "" {
		return
	}
	appRoot := filepath.Join(outputRoot, appID)
	if err := os.MkdirAll(appRoot, 0o700); err != nil {
		t.Fatalf("create live evidence output dir: %v", err)
	}
	for _, ref := range refs {
		info, err := os.Stat(ref)
		if err != nil {
			continue
		}
		target := filepath.Join(appRoot, filepath.Base(ref))
		if info.IsDir() {
			if err := copyDir(target, ref); err != nil {
				t.Fatalf("copy EvidencePack directory for %s: %v", appID, err)
			}
			continue
		}
		if err := copyFile(target, ref); err != nil {
			t.Fatalf("copy EvidencePack archive for %s: %v", appID, err)
		}
	}
}

func copyDir(dst, src string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return copyFile(target, path)
	})
}

func copyFile(dst, src string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func getenv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
