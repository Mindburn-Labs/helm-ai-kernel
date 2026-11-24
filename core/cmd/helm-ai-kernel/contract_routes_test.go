package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"

	_ "modernc.org/sqlite"
)

const testAdminAPIKey = "test-admin-key"

type receiptRouteStaticDriver struct{}

func (receiptRouteStaticDriver) Execute(context.Context, string, map[string]any) (any, error) {
	return "result", nil
}

func TestContractRoutesServeDocumentedEvidenceAndProofgraphPaths(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	checks := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/api/v1/proofgraph/sessions", ""},
		{http.MethodGet, "/api/v1/proofgraph/sessions/session-test/receipts", ""},
		{http.MethodGet, "/api/v1/proofgraph/receipts/rcpt-test", ""},
	}
	for _, check := range checks {
		t.Run(check.method+" "+check.path, func(t *testing.T) {
			req := httptest.NewRequest(check.method, check.path, strings.NewReader(check.body))
			authorizeTestRequest(req)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound {
				t.Fatalf("route returned 404: %s", rec.Body.String())
			}
			if rec.Code >= 500 {
				t.Fatalf("route returned %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestBoundaryStatusRouteReturnsRuntimeContract(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/boundary/status", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("boundary status=%d body=%s", rec.Code, rec.Body.String())
	}

	var status contracts.BoundaryStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode boundary status: %v", err)
	}
	if status.Status != "degraded" || status.Mode != "oss-local" {
		t.Fatalf("boundary posture = status=%q mode=%q", status.Status, status.Mode)
	}
	if status.ReceiptStore != "ready" || status.ReceiptSigner != "unavailable" {
		t.Fatalf("boundary receipt mechanisms = store=%q signer=%q", status.ReceiptStore, status.ReceiptSigner)
	}
	if status.PDP != "fail-closed" || status.MCPFirewall != "enabled" || status.Sandbox != "deny-default" {
		t.Fatalf("boundary mechanisms = pdp=%q mcp=%q sandbox=%q", status.PDP, status.MCPFirewall, status.Sandbox)
	}
	if status.Version == "" || status.LastCheckpointHash == "" || status.UpdatedAt.IsZero() {
		t.Fatalf("boundary provenance is incomplete: %+v", status)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode boundary status keys: %v", err)
	}
	for _, key := range []string{
		"status", "mode", "receipt_signer", "receipt_store", "pdp",
		"mcp_firewall", "sandbox", "authz", "evidence_verifier",
		"checkpoint_log", "open_approval_count", "quarantined_mcp_count",
		"updated_at",
	} {
		if _, ok := payload[key]; !ok {
			t.Errorf("boundary status is missing required key %q", key)
		}
	}
	for _, stale := range []string{
		"receipt_store_ready", "signer_ready", "open_approvals",
		"quarantined_mcp_servers", "last_checkpoint_id", "checked_at",
	} {
		if _, ok := payload[stale]; ok {
			t.Errorf("boundary status exposed stale key %q", stale)
		}
	}
}

func TestBoundaryContractRoutesExposeNewControlSurfaces(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	negativeReq := httptest.NewRequest(http.MethodGet, "/api/v1/conformance/negative", nil)
	negativeRec := httptest.NewRecorder()
	mux.ServeHTTP(negativeRec, negativeReq)
	if negativeRec.Code != http.StatusOK {
		t.Fatalf("negative vectors status=%d body=%s", negativeRec.Code, negativeRec.Body.String())
	}

	discoverReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry", strings.NewReader(`{"server_id":"srv-1","risk":"high"}`))
	authorizeTestRequest(discoverReq)
	discoverRec := httptest.NewRecorder()
	mux.ServeHTTP(discoverRec, discoverReq)
	if discoverRec.Code != http.StatusAccepted {
		t.Fatalf("discover status=%d body=%s", discoverRec.Code, discoverRec.Body.String())
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry/approve", strings.NewReader(`{"server_id":"srv-1","approver_id":"user:alice","approval_receipt_id":"approval-r1","reason":"reviewed","tool_names":["local.echo"]}`))
	authorizeTestRequest(approveReq)
	approveRec := httptest.NewRecorder()
	mux.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("approve status=%d body=%s", approveRec.Code, approveRec.Body.String())
	}
	if contentType := approveRec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/problem+json") {
		t.Fatalf("approve content type = %q", contentType)
	}
	var approvalProblem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approvalProblem); err != nil {
		t.Fatal(err)
	}
	if approvalProblem.Detail != boundarypkg.ErrApprovalVerificationUnavailable.Error() {
		t.Fatalf("approve detail = %q", approvalProblem.Detail)
	}

	pathApproveReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry/srv-1/approve", strings.NewReader(`{"approver_id":"user:alice","approval_receipt_id":"approval-r1","reason":"reviewed"}`))
	authorizeTestRequest(pathApproveReq)
	pathApproveRec := httptest.NewRecorder()
	mux.ServeHTTP(pathApproveRec, pathApproveReq)
	if pathApproveRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("path approve status=%d body=%s", pathApproveRec.Code, pathApproveRec.Body.String())
	}

	getAfterApproveReq := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/registry/srv-1", nil)
	authorizeTestRequest(getAfterApproveReq)
	getAfterApproveRec := httptest.NewRecorder()
	mux.ServeHTTP(getAfterApproveRec, getAfterApproveReq)
	if getAfterApproveRec.Code != http.StatusOK {
		t.Fatalf("registry get status=%d body=%s", getAfterApproveRec.Code, getAfterApproveRec.Body.String())
	}
	var quarantined map[string]any
	if err := json.Unmarshal(getAfterApproveRec.Body.Bytes(), &quarantined); err != nil {
		t.Fatal(err)
	}
	if quarantined["state"] == "approved" {
		t.Fatalf("caller-body approve minted authority: %+v", quarantined)
	}

	sandboxReq := httptest.NewRequest(http.MethodGet, "/api/v1/sandbox/grants/inspect?runtime=wazero", nil)
	authorizeTestRequest(sandboxReq)
	sandboxRec := httptest.NewRecorder()
	mux.ServeHTTP(sandboxRec, sandboxReq)
	if sandboxRec.Code != http.StatusOK {
		t.Fatalf("sandbox status=%d body=%s", sandboxRec.Code, sandboxRec.Body.String())
	}
	var grant map[string]any
	if err := json.Unmarshal(sandboxRec.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if grant["grant_hash"] == "" {
		t.Fatalf("grant hash missing: %+v", grant)
	}

	envelopeReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/envelopes", strings.NewReader(`{"manifest_id":"manifest-1","envelope":"dsse","native_evidence_hash":"sha256:evidence"}`))
	authorizeTestRequest(envelopeReq)
	envelopeRec := httptest.NewRecorder()
	mux.ServeHTTP(envelopeRec, envelopeReq)
	if envelopeRec.Code != http.StatusOK {
		t.Fatalf("envelope status=%d body=%s", envelopeRec.Code, envelopeRec.Body.String())
	}
	payloadReq := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/envelopes/manifest-1/payload", nil)
	authorizeTestRequest(payloadReq)
	payloadRec := httptest.NewRecorder()
	mux.ServeHTTP(payloadRec, payloadReq)
	if payloadRec.Code != http.StatusOK {
		t.Fatalf("payload status=%d body=%s", payloadRec.Code, payloadRec.Body.String())
	}
}

func TestProofGraphSessionRouteRejectsUnsafeCompatibilityValues(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	for name, path := range map[string]string{
		"blank":     "/api/v1/proofgraph/sessions/%20/receipts",
		"slash":     "/api/v1/proofgraph/sessions/bad%2Fsession/receipts",
		"backslash": "/api/v1/proofgraph/sessions/bad%5Csession/receipts",
		"nul":       "/api/v1/proofgraph/sessions/bad%00session/receipts",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			authorizeTestRequest(req)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("unsafe proofgraph session route status=%d body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "rcpt-test") {
				t.Fatalf("unsafe session route exposed receipt data: %s", rec.Body.String())
			}
		})
	}
}

func TestProtectedRuntimeRoutesFailClosedWithoutCredentials(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "")

	contractMux := http.NewServeMux()
	registerContractRoutes(contractMux, &Services{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evidence/envelopes", nil)
	rec := httptest.NewRecorder()
	contractMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("evidence envelopes without credentials status = %d body=%s", rec.Code, rec.Body.String())
	}

	receiptMux := http.NewServeMux()
	registerReceiptRoutes(receiptMux, &Services{})
	receiptReq := httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil)
	receiptRec := httptest.NewRecorder()
	receiptMux.ServeHTTP(receiptRec, receiptReq)
	if receiptRec.Code != http.StatusUnauthorized {
		t.Fatalf("receipt list without credentials status = %d body=%s", receiptRec.Code, receiptRec.Body.String())
	}
}

func newContractRouteTestServices(t *testing.T) (*Services, func()) {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-test",
		DecisionID:   "dec-test",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictDeny),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-test",
		DecisionHash: "sha256:test-decision",
		ArgsHash:     "args-test",
	}
	appendTenantScopedReceipt(t, receiptStore, defaultRuntimeTenantID, "session-test", receipt)
	return &Services{ReceiptStore: receiptStore}, func() { _ = db.Close() }
}

func authorizeTestRequest(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, defaultRuntimeTenantID)
	req.Header.Set(principalHeader, "system-admin")
}
