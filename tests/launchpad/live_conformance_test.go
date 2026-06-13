package launchpad_test

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/modelproviders"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/promotion"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func TestLiveModelProviderLocalContainerConformance(t *testing.T) {
	if testing.Short() || getenv("HELM_LAUNCHPAD_LIVE_E2E") != "1" {
		t.Skip("live Launchpad conformance requires HELM_LAUNCHPAD_LIVE_E2E=1")
	}
	providerSecrets := firstLiveModelProviderSecrets(t)
	if len(providerSecrets) == 0 {
		t.Fatal("one complete catalog-backed BYO model provider env group is required for live Launchpad conformance")
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
			if manifest.EgressProxy != nil && manifest.EgressProxy.Image != "" && promoted.FrameworkContract.EgressProxy.Required {
				if promoted.FrameworkContract.EgressProxy.Image != manifest.EgressProxy.Image {
					t.Fatalf("%s promoted egress proxy image = %q, want run artifact %q", appID, promoted.FrameworkContract.EgressProxy.Image, manifest.EgressProxy.Image)
				}
				if promoted.FrameworkContract.EgressProxy.Digest != manifest.EgressProxy.Digest {
					t.Fatalf("%s promoted egress proxy digest = %q, want run artifact %q", appID, promoted.FrameworkContract.EgressProxy.Digest, manifest.EgressProxy.Digest)
				}
			}
			compiled, err := plan.CompileWithRoot(promoted, substrate, "ci.launchpad", catalog.Root)
			if err != nil {
				t.Fatalf("CompileWithRoot: %v", err)
			}
			if manifest.EgressProxy != nil && manifest.EgressProxy.Image != "" && compiled.FrameworkContract.EgressProxy.Required && compiled.FrameworkContract.EgressProxy.Image != manifest.EgressProxy.Image {
				t.Fatalf("%s compiled egress proxy image = %q, want run artifact %q", appID, compiled.FrameworkContract.EgressProxy.Image, manifest.EgressProxy.Image)
			}
			if len(compiled.RuntimeCommand) == 0 {
				t.Fatalf("%s compiled without an AppSpec runtime command", appID)
			}
			if len(compiled.Healthchecks) == 0 {
				t.Fatalf("%s compiled without an AppSpec healthcheck", appID)
			}
			store := session.NewStore(t.TempDir())
			opts := session.ExecuteOptions{
				Reason:           "live BYO model-provider Launchpad conformance",
				WorkspaceMount:   t.TempDir(),
				RuntimeSecretEnv: providerSecrets,
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
				copyLiveRunEvidenceBestEffort(t, appID, run)
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

func firstLiveModelProviderSecrets(t *testing.T) map[string]string {
	t.Helper()
	catalog, err := modelproviders.DefaultCatalog()
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	for _, group := range catalogEnvGroups(catalog) {
		values := map[string]string{}
		for _, envName := range group {
			value := getenv(envName)
			if value == "" {
				values = nil
				break
			}
			values[envName] = value
		}
		if len(values) > 0 {
			return values
		}
	}
	if payload := getenv("HELM_LAUNCHPAD_CI_MODEL_PROVIDER_SECRET_JSON"); payload != "" {
		var values map[string]string
		if err := json.Unmarshal([]byte(payload), &values); err != nil {
			t.Fatalf("HELM_LAUNCHPAD_CI_MODEL_PROVIDER_SECRET_JSON is not valid JSON: %v", err)
		}
		for _, group := range catalogEnvGroups(catalog) {
			out := map[string]string{}
			for _, envName := range group {
				value := strings.TrimSpace(values[envName])
				if value == "" {
					out = nil
					break
				}
				out[envName] = value
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func catalogEnvGroups(catalog modelproviders.Catalog) [][]string {
	var out [][]string
	for _, provider := range catalog.Providers {
		out = append(out, provider.RequiredGroups()...)
	}
	return out
}

var (
	defaultLiveConformanceApps   = []string{"openclaw", "hermes"}
	candidateLiveConformanceApps = []string{}
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
	verifyLiveRuntimeTelemetry(t, appID, dirRef)
	root := repoRoot(t)
	cmd := exec.Command("go", "run", "./core/cmd/helm-ai-kernel", "verify", "--bundle", archiveRef, "--json")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s EvidencePack tar did not verify offline: %v\n%s", appID, err, string(out))
	}
}

func verifyLiveRuntimeTelemetry(t *testing.T, appID, dirRef string) {
	t.Helper()
	path := filepath.Join(dirRef, "03_TELEMETRY", "runtime.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s EvidencePack missing runtime telemetry proof %s: %v", appID, path, err)
	}
	var telemetry map[string]any
	if err := json.Unmarshal(data, &telemetry); err != nil {
		t.Fatalf("%s runtime telemetry proof is not JSON: %v", appID, err)
	}
	for _, key := range []string{"schema_version", "launch_id", "app_id", "state", "runtime", "kernel_verdict"} {
		if strings.TrimSpace(fmt.Sprint(telemetry[key])) == "" {
			t.Fatalf("%s runtime telemetry proof missing %s: %#v", appID, key, telemetry)
		}
	}
	if telemetry["app_id"] != appID {
		t.Fatalf("%s runtime telemetry app_id = %#v, want %q", appID, telemetry["app_id"], appID)
	}
	if telemetry["state"] != "RUNNING" && telemetry["state"] != "DELETED" {
		t.Fatalf("%s runtime telemetry state = %#v, want RUNNING or DELETED", appID, telemetry["state"])
	}
}

func copyLiveEvidenceRefs(t *testing.T, appID string, refs []string) {
	t.Helper()
	if err := copyLiveEvidenceRefsToOutput(appID, refs); err != nil {
		t.Fatalf("copy live evidence for %s: %v", appID, err)
	}
}

func copyLiveRunEvidenceBestEffort(t *testing.T, appID string, run session.LaunchRun) {
	t.Helper()
	if outputRoot := getenv("HELM_LAUNCHPAD_LIVE_EVIDENCE_DIR"); outputRoot != "" {
		appRoot := filepath.Join(outputRoot, appID)
		if err := os.MkdirAll(appRoot, 0o700); err != nil {
			t.Logf("create failed-run evidence output dir for %s: %v", appID, err)
		} else {
			payload, err := json.MarshalIndent(run, "", "  ")
			if err != nil {
				t.Logf("marshal failed launch run for %s: %v", appID, err)
			} else if err := os.WriteFile(filepath.Join(appRoot, "launch_run.json"), payload, 0o600); err != nil {
				t.Logf("write failed launch run for %s: %v", appID, err)
			}
			if run.LogPath != "" {
				if _, err := os.Stat(run.LogPath); err == nil {
					target := filepath.Join(appRoot, "logs", filepath.Base(run.LogPath))
					if err := copyFile(target, run.LogPath); err != nil {
						t.Logf("copy failed launch log for %s: %v", appID, err)
					}
				}
			}
		}
	}
	if err := copyLiveEvidenceRefsToOutput(appID, run.EvidencePackRefs); err != nil {
		t.Logf("copy failed-run EvidencePack refs for %s: %v", appID, err)
	}
}

func copyLiveEvidenceRefsToOutput(appID string, refs []string) error {
	outputRoot := getenv("HELM_LAUNCHPAD_LIVE_EVIDENCE_DIR")
	if outputRoot == "" {
		return nil
	}
	appRoot := filepath.Join(outputRoot, appID)
	if err := os.MkdirAll(appRoot, 0o700); err != nil {
		return fmt.Errorf("create live evidence output dir: %w", err)
	}
	for _, ref := range refs {
		info, err := os.Stat(ref)
		if err != nil {
			continue
		}
		target := filepath.Join(appRoot, filepath.Base(ref))
		if info.IsDir() {
			if err := copyDir(target, ref); err != nil {
				return fmt.Errorf("copy EvidencePack directory: %w", err)
			}
			continue
		}
		if err := copyFile(target, ref); err != nil {
			return fmt.Errorf("copy EvidencePack archive: %w", err)
		}
	}
	return nil
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
