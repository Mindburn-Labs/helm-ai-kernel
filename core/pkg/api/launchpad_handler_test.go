package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func TestLaunchpadAPIPlanLaunchDeleteEvidence(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	t.Setenv("model_gateway", "")
	srv := newTestServer(t)

	matrixReq := httptest.NewRequest(http.MethodGet, "/api/v1/launchpad/matrix", nil)
	matrixRec := httptest.NewRecorder()
	srv.ServeHTTP(matrixRec, matrixReq)
	if matrixRec.Code != http.StatusOK {
		t.Fatalf("matrix status=%d body=%s", matrixRec.Code, matrixRec.Body.String())
	}

	body := []byte(`{"app_id":"openclaw","substrate_id":"local-container","principal":"api-test"}`)
	launchReq := httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/launch", bytes.NewReader(body))
	launchRec := httptest.NewRecorder()
	srv.ServeHTTP(launchRec, launchReq)
	if launchRec.Code != http.StatusAccepted {
		t.Fatalf("launch status=%d body=%s", launchRec.Code, launchRec.Body.String())
	}
	var run session.LaunchRun
	if err := json.NewDecoder(launchRec.Body).Decode(&run); err != nil {
		t.Fatalf("decode launch: %v", err)
	}
	if run.State != session.StateEscalated || run.KernelVerdict != "ESCALATE" {
		t.Fatalf("launch should fail closed on missing secret: %#v", run)
	}
	if run.Principal != "operator-1" {
		t.Fatalf("launch principal = %q, want authenticated operator", run.Principal)
	}
	if len(run.SandboxGrantRefs) == 0 || len(run.MCPRefs) == 0 || len(run.LaunchReceiptRefs) == 0 || len(run.HealthcheckRefs) == 0 || len(run.EvidencePackRefs) == 0 {
		t.Fatalf("launch missing authority/proof refs: %#v", run)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/launchpad/launches/"+run.LaunchID, nil)
	statusRec := httptest.NewRecorder()
	srv.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", statusRec.Code, statusRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/launches/"+run.LaunchID+"/delete", bytes.NewReader([]byte(`{"cascade":true}`)))
	deleteRec := httptest.NewRecorder()
	srv.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusAccepted {
		t.Fatalf("delete code=%d body=%s", deleteRec.Code, deleteRec.Body.String())
	}
	var deleted session.LaunchRun
	if err := json.NewDecoder(deleteRec.Body).Decode(&deleted); err != nil {
		t.Fatalf("decode delete: %v", err)
	}
	if deleted.State != session.StateDeleted || len(deleted.TeardownReceiptRefs) == 0 {
		t.Fatalf("delete missing terminal receipt: %#v", deleted)
	}
	report, err := verifier.VerifyBundle(filepath.Join(session.NewStore("").Root(), "evidencepacks", run.LaunchID))
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !report.Verified {
		t.Fatalf("EvidencePack did not verify: %s", report.Summary)
	}
}

func TestLaunchpadAPIFailsClosedWithoutAuthentication(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	t.Setenv("model_gateway", "")
	srv := NewServer(ServerConfig{})

	body := []byte(`{"app_id":"openclaw","substrate_id":"local-container","principal":"attacker"}`)
	for name, req := range map[string]*http.Request{
		"matrix": httptest.NewRequest(http.MethodGet, "/api/v1/launchpad/matrix", nil),
		"launch": httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/launch", bytes.NewReader(body)),
		"delete": httptest.NewRequest(http.MethodPost, "/api/v1/launchpad/launches/lp-attacker/delete", bytes.NewReader([]byte(`{"cascade":true}`))),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
