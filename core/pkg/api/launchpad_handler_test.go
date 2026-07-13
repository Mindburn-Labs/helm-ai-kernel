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

	matrixReq := httptest.NewRequest(http.MethodGet, "/api/legacy/v1/launchpad/matrix", nil)
	matrixRec := httptest.NewRecorder()
	srv.ServeHTTP(matrixRec, matrixReq)
	if matrixRec.Code != http.StatusOK {
		t.Fatalf("matrix status=%d body=%s", matrixRec.Code, matrixRec.Body.String())
	}

	body := []byte(`{"app_id":"openclaw","substrate_id":"local-container","principal":"api-test"}`)
	launchReq := httptest.NewRequest(http.MethodPost, "/api/legacy/v1/launchpad/launch", bytes.NewReader(body))
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

	statusReq := httptest.NewRequest(http.MethodGet, "/api/legacy/v1/launchpad/launches/"+run.LaunchID, nil)
	statusRec := httptest.NewRecorder()
	srv.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", statusRec.Code, statusRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodPost, "/api/legacy/v1/launchpad/launches/"+run.LaunchID+"/delete", bytes.NewReader([]byte(`{"cascade":true}`)))
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
		"matrix": httptest.NewRequest(http.MethodGet, "/api/legacy/v1/launchpad/matrix", nil),
		"launch": httptest.NewRequest(http.MethodPost, "/api/legacy/v1/launchpad/launch", bytes.NewReader(body)),
		"delete": httptest.NewRequest(http.MethodPost, "/api/legacy/v1/launchpad/launches/lp-attacker/delete", bytes.NewReader([]byte(`{"cascade":true}`))),
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

// TestLaunchpadAPIRejectsCrossPrincipalAccess verifies a launch owned by one
// principal cannot be read or deleted by a different authenticated principal
// (MIN-712 / SUBAGENT-0053 + 0162). Runs are addressed by caller-supplied launch
// IDs, so read and destructive operations must be scoped to the owning principal.
func TestLaunchpadAPIRejectsCrossPrincipalAccess(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	t.Setenv("model_gateway", "")
	srv := newTestServer(t) // authenticates every request as operator-1

	// Seed a run owned by a different principal.
	store := session.NewStore("")
	if err := store.Save(session.LaunchRun{
		LaunchID:  "lp-victim",
		AppID:     "openclaw",
		Principal: "victim-7",
		State:     session.StatePlanned,
	}); err != nil {
		t.Fatalf("seed victim run: %v", err)
	}

	// operator-1 must not be able to read the victim's run.
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/api/legacy/v1/launchpad/launches/lp-victim", nil))
	if getRec.Code != http.StatusForbidden {
		t.Fatalf("cross-principal GET status=%d, want 403; body=%s", getRec.Code, getRec.Body.String())
	}

	// operator-1 must not be able to delete the victim's run.
	delRec := httptest.NewRecorder()
	srv.ServeHTTP(delRec, httptest.NewRequest(http.MethodPost, "/api/legacy/v1/launchpad/launches/lp-victim/delete", bytes.NewReader([]byte(`{"cascade":true}`))))
	if delRec.Code != http.StatusForbidden {
		t.Fatalf("cross-principal delete status=%d, want 403; body=%s", delRec.Code, delRec.Body.String())
	}

	// The victim's run must still exist — the unauthorized delete must not take effect.
	if _, err := store.Get("lp-victim"); err != nil {
		t.Fatalf("victim run was removed by unauthorized delete: %v", err)
	}
}
