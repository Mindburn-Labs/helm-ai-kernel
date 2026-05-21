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
