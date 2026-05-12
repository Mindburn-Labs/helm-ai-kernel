package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-oss/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"

	_ "modernc.org/sqlite"
)

const testAdminAPIKey = "test-admin-key"

func TestContractRoutesServeDocumentedEvidenceProofgraphAndConformancePaths(t *testing.T) {
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
		{http.MethodGet, "/api/v1/proofgraph/sessions/agent.test/receipts", ""},
		{http.MethodGet, "/api/v1/proofgraph/receipts/rcpt-test", ""},
		{http.MethodPost, "/api/v1/conformance/run", `{"level":"L1","profile":"runtime"}`},
		{http.MethodGet, "/api/v1/conformance/reports/conf_test", ""},
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

func TestEvidenceExportAndVerifyRoundTrip(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"agent.test","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRec.Code, exportRec.Body.String())
	}
	if exportRec.Header().Get("X-Helm-Evidence-Hash") == "" {
		t.Fatal("export missing evidence hash header")
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verify", bytes.NewReader(exportRec.Body.Bytes()))
	verifyReq.Header.Set("Content-Type", "application/octet-stream")
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["verdict"] != "PASS" {
		t.Fatalf("verification result = %+v", result)
	}
}

func TestEvidenceExportFailsWhenReceiptLimitWouldTruncate(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptStore: &overflowReceiptStore{}})

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"agent.overflow","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("export status = %d body=%s", exportRec.Code, exportRec.Body.String())
	}
	if !strings.Contains(exportRec.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("export error content type = %q", exportRec.Header().Get("Content-Type"))
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

	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry/approve", strings.NewReader(`{"server_id":"srv-1","approver_id":"user:alice","approval_receipt_id":"approval-r1"}`))
	authorizeTestRequest(approveReq)
	approveRec := httptest.NewRecorder()
	mux.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", approveRec.Code, approveRec.Body.String())
	}
	var approval map[string]any
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approval); err != nil {
		t.Fatal(err)
	}
	if approval["state"] != "approved" {
		t.Fatalf("approval state = %+v", approval)
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
	verifyEnvelopeReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/envelopes/manifest-1/verify", nil)
	authorizeTestRequest(verifyEnvelopeReq)
	verifyEnvelopeRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyEnvelopeRec, verifyEnvelopeReq)
	if verifyEnvelopeRec.Code != http.StatusOK {
		t.Fatalf("envelope verify status=%d body=%s", verifyEnvelopeRec.Code, verifyEnvelopeRec.Body.String())
	}
}

func TestMCPAuthorizeCallAPIFailClosedAndPinnedAllow(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"text": map[string]any{"type": "string"},
		},
		"required": []string{"text"},
	}
	hash, err := mcppkg.ToolSchemaHash(mcppkg.ToolRef{Name: "local.echo", Schema: schema})
	if err != nil {
		t.Fatalf("schema hash: %v", err)
	}

	unknownServer := postMCPAuthorizeForTest(t, mux, map[string]any{
		"server_id":          "api-unknown-server",
		"tool_name":          "local.echo",
		"args_hash":          "sha256:unknown-server",
		"tool_schema":        schema,
		"pinned_schema_hash": hash,
	}, http.StatusForbidden)
	if unknownServer["verdict"] != "DENY" && unknownServer["verdict"] != "ESCALATE" {
		t.Fatalf("unknown server verdict = %+v", unknownServer)
	}

	discoverReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry", strings.NewReader(`{"server_id":"api-fixture","tool_names":["local.echo"],"risk":"high"}`))
	authorizeTestRequest(discoverReq)
	discoverRec := httptest.NewRecorder()
	mux.ServeHTTP(discoverRec, discoverReq)
	if discoverRec.Code != http.StatusAccepted {
		t.Fatalf("discover status=%d body=%s", discoverRec.Code, discoverRec.Body.String())
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry/api-fixture/approve", strings.NewReader(`{"approver_id":"user:alice","approval_receipt_id":"approval-r1"}`))
	authorizeTestRequest(approveReq)
	approveRec := httptest.NewRecorder()
	mux.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", approveRec.Code, approveRec.Body.String())
	}

	unknownTool := postMCPAuthorizeForTest(t, mux, map[string]any{
		"server_id": "api-fixture",
		"tool_name": "local.missing",
		"args_hash": "sha256:unknown-tool",
	}, http.StatusForbidden)
	if unknownTool["verdict"] != "DENY" && unknownTool["verdict"] != "ESCALATE" {
		t.Fatalf("unknown tool verdict = %+v", unknownTool)
	}

	missingPin := postMCPAuthorizeForTest(t, mux, map[string]any{
		"server_id":   "api-fixture",
		"tool_name":   "local.echo",
		"args_hash":   "sha256:missing-pin",
		"tool_schema": schema,
	}, http.StatusForbidden)
	if missingPin["verdict"] != "DENY" && missingPin["verdict"] != "ESCALATE" {
		t.Fatalf("missing pin verdict = %+v", missingPin)
	}

	allowed := postMCPAuthorizeForTest(t, mux, map[string]any{
		"server_id":          "api-fixture",
		"tool_name":          "local.echo",
		"args_hash":          "sha256:pinned-allow",
		"tool_schema":        schema,
		"pinned_schema_hash": hash,
	}, http.StatusOK)
	if allowed["verdict"] != "ALLOW" {
		t.Fatalf("allow verdict = %+v", allowed)
	}
	if allowed["record_hash"] == "" {
		t.Fatal("allowed record_hash missing")
	}
}

func TestReplayVerifyDetectsTamperedEvidenceBundle(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"agent.test","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRec.Code, exportRec.Body.String())
	}

	tampered, err := tamperEvidenceReceipt(exportRec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/replay/verify", bytes.NewReader(tampered))
	verifyReq.Header.Set("Content-Type", "application/octet-stream")
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["verdict"] != "FAIL" {
		t.Fatalf("expected tampered bundle to fail verification, got %+v", result)
	}
}

func TestApprovalRoutesSupportWebAuthnChallengeAssertion(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", strings.NewReader(`{"approval_id":"approval-webauthn","subject":"mcp:srv","action":"mcp.approve","requested_by":"agent:test","quorum":1}`))
	authorizeTestRequest(createReq)
	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create approval status=%d body=%s", createRec.Code, createRec.Body.String())
	}

	challengeReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-webauthn/webauthn/challenge", strings.NewReader(`{"method":"passkey","ttl_ms":60000}`))
	authorizeTestRequest(challengeReq)
	challengeRec := httptest.NewRecorder()
	mux.ServeHTTP(challengeRec, challengeReq)
	if challengeRec.Code != http.StatusCreated {
		t.Fatalf("challenge status=%d body=%s", challengeRec.Code, challengeRec.Body.String())
	}
	var challenge map[string]any
	if err := json.Unmarshal(challengeRec.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	challengeID, _ := challenge["challenge_id"].(string)
	if challengeID == "" {
		t.Fatalf("challenge missing id: %+v", challenge)
	}

	assertReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-webauthn/webauthn/assert", strings.NewReader(fmt.Sprintf(`{"challenge_id":%q,"actor":"user:alice","assertion":"signed-client-data","receipt_id":"rcpt-approval"}`, challengeID)))
	authorizeTestRequest(assertReq)
	assertRec := httptest.NewRecorder()
	mux.ServeHTTP(assertRec, assertReq)
	if assertRec.Code != http.StatusOK {
		t.Fatalf("assert status=%d body=%s", assertRec.Code, assertRec.Body.String())
	}
	var approval map[string]any
	if err := json.Unmarshal(assertRec.Body.Bytes(), &approval); err != nil {
		t.Fatal(err)
	}
	if approval["state"] != "approved" || approval["auth_method"] != "passkey" {
		t.Fatalf("approval did not bind passkey assertion: %+v", approval)
	}
}

func TestReplayVerifyDetectsReceiptChainBreakWithValidManifest(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	broken := &contracts.Receipt{
		ReceiptID:    "rcpt-broken",
		DecisionID:   "dec-broken",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 1, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-broken",
		PrevHash:     "wrong-prev-hash",
		LamportClock: 2,
		ArgsHash:     "args-broken",
	}
	if err := svc.ReceiptStore.Store(context.Background(), broken); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"agent.test","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRec.Code, exportRec.Body.String())
	}

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/replay/verify", bytes.NewReader(exportRec.Body.Bytes()))
	verifyReq.Header.Set("Content-Type", "application/octet-stream")
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["verdict"] != "FAIL" {
		t.Fatalf("expected chain break to fail verification, got %+v", result)
	}
	checks, _ := result["checks"].(map[string]any)
	if checks["causal_chain"] != "FAIL" || checks["replay"] != "FAIL" {
		t.Fatalf("expected replay causal failure, got %+v", result)
	}
}

func TestEvidenceVerifyRejectsUnsafeArchivePaths(t *testing.T) {
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{})

	bundle, err := unsafeEvidenceBundle()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verify", bytes.NewReader(bundle))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["verdict"] != "FAIL" {
		t.Fatalf("expected unsafe archive to fail verification, got %+v", result)
	}
}

func TestProtectedRuntimeRoutesFailClosedWithoutCredentials(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", "")

	contractMux := http.NewServeMux()
	registerContractRoutes(contractMux, &Services{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/conformance/run", strings.NewReader(`{"level":"L1"}`))
	rec := httptest.NewRecorder()
	contractMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("conformance run without credentials status = %d body=%s", rec.Code, rec.Body.String())
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

func TestReceiptListReturnsCursorPagination(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	second := &contracts.Receipt{
		ReceiptID:    "rcpt-next",
		DecisionID:   "dec-next",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 1, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-next",
		LamportClock: 2,
		ArgsHash:     "args-next",
	}
	if err := svc.ReceiptStore.Store(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	firstPage := requestReceiptList(t, mux, "/api/v1/receipts?limit=1")
	if firstPage["count"] != float64(1) || firstPage["has_more"] != true || firstPage["next_cursor"] != "lamport:1" {
		t.Fatalf("first page pagination metadata = %+v", firstPage)
	}
	secondPage := requestReceiptList(t, mux, "/api/v1/receipts?since=lamport:1&limit=1")
	if secondPage["count"] != float64(1) || secondPage["has_more"] != false || secondPage["next_cursor"] != "lamport:2" {
		t.Fatalf("second page pagination metadata = %+v", secondPage)
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
		LamportClock: 1,
		ArgsHash:     "args-test",
	}
	if err := receiptStore.Store(context.Background(), receipt); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return &Services{ReceiptStore: receiptStore}, func() { _ = db.Close() }
}

func requestReceiptList(t *testing.T, mux *http.ServeMux, target string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("receipt list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func postMCPAuthorizeForTest(t *testing.T, mux *http.ServeMux, body map[string]any, wantStatus int) map[string]any {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/authorize-call", bytes.NewReader(data))
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("authorize status=%d want=%d body=%s", rec.Code, wantStatus, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func authorizeTestRequest(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant.test")
}

type overflowReceiptStore struct {
	captureReceiptStore
}

func (s *overflowReceiptStore) ListByAgent(_ context.Context, agentID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	return overflowReceipts(agentID, since, limit), nil
}

func (s *overflowReceiptStore) ListSince(_ context.Context, since uint64, limit int) ([]*contracts.Receipt, error) {
	return overflowReceipts("agent.overflow", since, limit), nil
}

func overflowReceipts(agentID string, since uint64, limit int) []*contracts.Receipt {
	receipts := make([]*contracts.Receipt, 0, limit)
	for i := 0; i < limit; i++ {
		lamport := since + uint64(i) + 1
		receipts = append(receipts, &contracts.Receipt{
			ReceiptID:    fmt.Sprintf("rcpt-overflow-%d", lamport),
			DecisionID:   fmt.Sprintf("dec-overflow-%d", lamport),
			EffectID:     "EXECUTE_TOOL",
			Status:       string(contracts.VerdictDeny),
			Timestamp:    time.Unix(int64(lamport), 0).UTC(),
			ExecutorID:   agentID,
			Signature:    "sig-overflow",
			LamportClock: lamport,
		})
	}
	return receipts
}

func tamperEvidenceReceipt(bundle []byte) ([]byte, error) {
	parsed, err := readEvidenceBundle(bundle)
	if err != nil {
		return nil, err
	}
	for name, data := range parsed.Files {
		if strings.HasPrefix(name, "receipts/") {
			parsed.Files[name] = bytes.Replace(data, []byte("sig-test"), []byte("sig-tampered"), 1)
			break
		}
	}
	manifestData, err := json.Marshal(parsed.Manifest)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{"manifest.json": manifestData}
	for name, data := range parsed.Files {
		files[name] = data
	}

	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeTarEntry(tarWriter, name, files[name]); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func unsafeEvidenceBundle() ([]byte, error) {
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "../receipt.json", Size: 2, Mode: 0644}); err != nil {
		return nil, err
	}
	if _, err := tarWriter.Write([]byte("{}")); err != nil {
		return nil, err
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
