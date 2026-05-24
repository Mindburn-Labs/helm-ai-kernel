package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	launchsession "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func TestLaunchpadServeRuntimeUsesConfiguredStore(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	storeRoot := t.TempDir()
	svc.DataDir = t.TempDir()
	svc.DatabaseMode = "sqlite"
	svc.DatabaseStatus = "ready"
	svc.LaunchpadStore = launchsession.NewStore(storeRoot)

	mux := http.NewServeMux()
	RegisterSubsystemRoutes(mux, svc)

	body := []byte(`{"app_id":"openclaw","substrate_id":"local-container","principal":"console-test"}`)
	launchReq := httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/launch", bytes.NewReader(body))
	authorizeTestRequest(launchReq)
	launchRec := httptest.NewRecorder()
	mux.ServeHTTP(launchRec, launchReq)
	if launchRec.Code != http.StatusAccepted {
		t.Fatalf("launch status=%d body=%s", launchRec.Code, launchRec.Body.String())
	}
	var run launchsession.LaunchRun
	if err := json.NewDecoder(launchRec.Body).Decode(&run); err != nil {
		t.Fatalf("decode launch: %v", err)
	}
	if run.LaunchID == "" {
		t.Fatalf("launch id missing: %#v", run)
	}
	if _, err := os.Stat(filepath.Join(storeRoot, "runs", run.LaunchID+".json")); err != nil {
		t.Fatalf("launch run was not written to configured store %s: %v", storeRoot, err)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/launchpad/launches/"+run.LaunchID, nil)
	authorizeTestRequest(statusReq)
	statusRec := httptest.NewRecorder()
	mux.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", statusRec.Code, statusRec.Body.String())
	}
}

func TestLaunchpadImportRoutesAnalyzeLocalRepoAndBlockUnsafeLaunch(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	storeRoot := t.TempDir()
	svc.DataDir = t.TempDir()
	svc.DatabaseMode = "sqlite"
	svc.DatabaseStatus = "ready"
	svc.LaunchpadStore = launchsession.NewStore(storeRoot)

	repoRoot := t.TempDir()
	t.Setenv("HELM_LAUNCHPAD_LOCAL_IMPORT_ROOT", filepath.Dir(repoRoot))
	writeLaunchpadImportFixture(t, repoRoot)

	mux := http.NewServeMux()
	RegisterSubsystemRoutes(mux, svc)

	importBody, err := json.Marshal(map[string]string{
		"repo_url":       filepath.Base(repoRoot),
		"desired_target": "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	importReq := httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/imports", bytes.NewReader(importBody))
	authorizeTestRequest(importReq)
	importRec := httptest.NewRecorder()
	mux.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusAccepted {
		t.Fatalf("import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var created struct {
		Import struct {
			ID              string `json:"id"`
			State           string `json:"state"`
			CapabilityGraph struct {
				Capabilities []string `json:"capabilities"`
			} `json:"capability_graph"`
			LaunchRecipe struct {
				GeneratedAppSpecs []struct {
					Trusted bool `json:"trusted"`
				} `json:"generated_app_specs"`
				TargetPlans []struct {
					TargetID string `json:"target_id"`
				} `json:"target_plans"`
			} `json:"launch_recipe"`
		} `json:"import"`
	}
	if err := json.NewDecoder(importRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode import: %v", err)
	}
	if created.Import.ID == "" {
		t.Fatal("import id missing")
	}
	if !containsString(created.Import.CapabilityGraph.Capabilities, "desktopUI") || !containsString(created.Import.CapabilityGraph.Capabilities, "compose") {
		t.Fatalf("capabilities=%#v", created.Import.CapabilityGraph.Capabilities)
	}
	if len(created.Import.LaunchRecipe.GeneratedAppSpecs) == 0 || created.Import.LaunchRecipe.GeneratedAppSpecs[0].Trusted {
		t.Fatalf("generated AppSpec trust invariant broken: %#v", created.Import.LaunchRecipe.GeneratedAppSpecs)
	}

	preflightReq := httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/imports/"+created.Import.ID+"/preflight", nil)
	authorizeTestRequest(preflightReq)
	preflightRec := httptest.NewRecorder()
	mux.ServeHTTP(preflightRec, preflightReq)
	if preflightRec.Code != http.StatusAccepted {
		t.Fatalf("preflight status=%d body=%s", preflightRec.Code, preflightRec.Body.String())
	}
	var preflight struct {
		Preflight struct {
			Status         string   `json:"status"`
			BlockedReasons []string `json:"blocked_reasons"`
		} `json:"preflight"`
	}
	if err := json.NewDecoder(preflightRec.Body).Decode(&preflight); err != nil {
		t.Fatalf("decode preflight: %v", err)
	}
	if preflight.Preflight.Status != "ESCALATE" || len(preflight.Preflight.BlockedReasons) == 0 {
		t.Fatalf("preflight=%#v", preflight.Preflight)
	}

	launchReq := httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/imports/"+created.Import.ID+"/launch", nil)
	authorizeTestRequest(launchReq)
	launchRec := httptest.NewRecorder()
	mux.ServeHTTP(launchRec, launchReq)
	if launchRec.Code != http.StatusConflict {
		t.Fatalf("unsafe import launch should be blocked, status=%d body=%s", launchRec.Code, launchRec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(storeRoot, "runs")); err == nil {
		t.Fatal("import launch route created a run before promotion")
	}
}

func writeLaunchpadImportFixture(t *testing.T, root string) {
	t.Helper()
	writeFixtureFile(t, root, "package.json", `{"scripts":{"dev":"vite --host 127.0.0.1 --port 5173","tauri":"tauri dev"},"dependencies":{"@tauri-apps/api":"latest","@ag-ui/client":"latest"}}`)
	writeFixtureFile(t, root, "src-tauri/Cargo.toml", "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
	writeFixtureFile(t, root, "docker-compose.yml", "services:\n  app:\n    build: .\n    ports:\n      - \"3000:3000\"\n")
	writeFixtureFile(t, root, ".env.example", "OPENAI_API_KEY=\n")
	writeFixtureFile(t, root, "README.md", "Desktop agent with MCP tools and AG-UI.")
	writeFixtureFile(t, root, "LICENSE", "MIT License\n")
}

func writeFixtureFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
