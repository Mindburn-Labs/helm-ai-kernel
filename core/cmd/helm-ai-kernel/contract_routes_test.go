package main

// quantum_posture: contract-route tests verify existing classical Ed25519 receipts; no post-quantum cryptographic control is added or claimed.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"

	_ "modernc.org/sqlite"
)

const testAdminAPIKey = "test-admin-key"

type receiptRouteStaticDriver struct{}

func (receiptRouteStaticDriver) Execute(context.Context, string, map[string]any) (any, error) {
	return "result", nil
}

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
		{http.MethodGet, "/api/v1/proofgraph/sessions/session-test/receipts", ""},
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

func TestEvidenceExportAndVerifyRoundTrip(t *testing.T) {
	svc, cleanup := newVerifiedEvidenceRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"verified-session","format":"tar.gz"}`))
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

func TestTenantEvidenceExportIncludesReferencedSurfaceArtifactsOnly(t *testing.T) {
	svc, cleanup := newVerifiedEvidenceRouteTestServices(t)
	defer cleanup()
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "tenant-a-scope",
		SubjectHash:         "sha256:tenant-a-subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatalf("seed tenant scope: %v", err)
	}
	if _, err := registry.PutHarnessTrace(contracts.HarnessTrace{
		TraceID:    "tenant-a-trace",
		PlanHash:   "sha256:plan",
		PolicyHash: "sha256:policy",
		ReceiptRefs: []string{
			"rcpt-evidence-a",
		},
	}); err != nil {
		t.Fatalf("seed tenant trace: %v", err)
	}
	if _, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "tenant-b-global-scope",
		SubjectHash:         "sha256:tenant-b-sensitive-subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	}); err != nil {
		t.Fatalf("seed global verification scope: %v", err)
	}
	if _, err := registry.PutHarnessTrace(contracts.HarnessTrace{
		TraceID:    "tenant-b-global-trace",
		PlanHash:   "sha256:other-plan",
		PolicyHash: "sha256:other-policy",
		ReceiptRefs: []string{
			"rcpt-other",
		},
	}); err != nil {
		t.Fatalf("seed global harness trace: %v", err)
	}
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), defaultRuntimeTenantID, "evidence-session", &contracts.Receipt{
		ReceiptID:    "rcpt-evidence-a",
		DecisionID:   "dec-evidence-a",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 1, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-evidence-a",
		DecisionHash: "sha256:evidence-decision",
		ArgsHash:     "args-evidence",
		ScopeHash:    scope.ScopeHash,
		Metadata: map[string]any{
			"risk_class":     "T2",
			"side_effectful": true,
			"scope_hash":     scope.ScopeHash,
		},
	}, svc.ReceiptSigner)
	svc.BoundarySurfaces = registry

	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)
	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"evidence-session","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRec.Code, exportRec.Body.String())
	}
	bundle, err := readEvidenceBundle(exportRec.Body.Bytes())
	if err != nil {
		t.Fatalf("read evidence bundle: %v", err)
	}
	for _, name := range []string{
		"verification_scopes/tenant-a-scope.json",
		"harness_traces/tenant-a-trace.json",
	} {
		if _, ok := bundle.Files[name]; !ok {
			t.Fatalf("tenant evidence export omitted referenced artifact %q: %v", name, bundle.Files)
		}
	}
	for _, name := range []string{
		"verification_scopes/tenant-b-global-scope.json",
		"harness_traces/tenant-b-global-trace.json",
	} {
		if _, ok := bundle.Files[name]; ok {
			t.Fatalf("tenant evidence export included global artifact %q", name)
		}
	}
	for name, data := range bundle.Files {
		if bytes.Contains(data, []byte("tenant-b-sensitive-subject")) {
			t.Fatalf("tenant evidence export leaked global artifact content in %q", name)
		}
	}
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verify", bytes.NewReader(exportRec.Body.Bytes()))
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	var result map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if verifyRec.Code != http.StatusOK || result["verdict"] != "PASS" {
		t.Fatalf("referenced evidence verification status=%d result=%+v", verifyRec.Code, result)
	}
}

func TestContractReceiptsForExportUsesTenantKeysetCursorAcrossSessions(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	second := &contracts.Receipt{
		ReceiptID:  "rcpt-next",
		DecisionID: "dec-next",
		EffectID:   "EXECUTE_TOOL",
		Status:     string(contracts.VerdictAllow),
		Timestamp:  time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID: "agent.peer",
		Signature:  "sig-next",
		ArgsHash:   "args-next",
	}
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), defaultRuntimeTenantID, "session-peer", second)

	receipts, err := contractReceiptsForExportWithPageSize(context.Background(), svc, defaultRuntimeTenantID, "", 1)
	if err != nil {
		t.Fatalf("collect tenant evidence receipts: %v", err)
	}
	if got := receiptIDSet(receipts); len(got) != 2 || !got["rcpt-test"] || !got["rcpt-next"] {
		t.Fatalf("tenant evidence pagination omitted or duplicated tied-Lamport receipts: %+v", got)
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

func TestContractReceiptsForExportAllowsExactReceiptLimit(t *testing.T) {
	receipts, err := contractReceiptsForExportWithPageSize(context.Background(), &Services{ReceiptStore: &exactLimitReceiptStore{}}, defaultRuntimeTenantID, "exact-limit", evidenceExportPageSize)
	if err != nil {
		t.Fatalf("collect exact receipt limit: %v", err)
	}
	if len(receipts) != maxEvidenceExportReceipts {
		t.Fatalf("exact receipt export count=%d, want %d", len(receipts), maxEvidenceExportReceipts)
	}
}

func TestBoundaryCheckpointCountsAllDurableReceipts(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), "tenant-live", "live-session", &contracts.Receipt{
		ReceiptID:    "rcpt-live",
		DecisionID:   "dec-live",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 1, 0, time.UTC),
		ExecutorID:   "agent.live",
		Signature:    "sig-live",
		DecisionHash: "sha256:live-decision",
		ArgsHash:     "args-live",
	})
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/boundary/checkpoints", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("checkpoint status=%d body=%s", rec.Code, rec.Body.String())
	}
	var checkpoint contracts.BoundaryCheckpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &checkpoint); err != nil {
		t.Fatal(err)
	}
	if checkpoint.ReceiptCount != 2 {
		t.Fatalf("global checkpoint receipt_count=%d, want 2", checkpoint.ReceiptCount)
	}
}

func TestEvaluateReceiptIsRetrievableAndExportableBySignedSession(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	svc, _ := newEvaluateRouteTestServices(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatal(err)
	}
	svc.ReceiptStore = receiptStore

	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)
	registerContractRoutes(mux, svc)

	const sessionID = "evaluate-session-e2e"
	evaluateReq := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", strings.NewReader(`{"tool":"EXECUTE_TOOL","effect_level":"local.echo","session_id":"`+sessionID+`"}`))
	authorizeTestRequest(evaluateReq)
	evaluateRec := httptest.NewRecorder()
	mux.ServeHTTP(evaluateRec, evaluateReq)
	if evaluateRec.Code != http.StatusOK {
		t.Fatalf("evaluate status=%d body=%s", evaluateRec.Code, evaluateRec.Body.String())
	}
	var response api.EvaluateResponse
	if err := json.Unmarshal(evaluateRec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ReceiptID == "" || response.ID != response.DecisionID || response.Action != "EXECUTE_TOOL" || response.Resource != "local.echo" {
		t.Fatalf("evaluate did not retain compatibility response fields: %+v", response)
	}
	if response.DecisionHash == "" {
		t.Fatalf("evaluate response did not include decision_hash: %+v", response)
	}
	signer, ok := svc.ReceiptSigner.(*helmcrypto.Ed25519Signer)
	if !ok {
		t.Fatalf("evaluate receipt signer type = %T, want Ed25519 signer", svc.ReceiptSigner)
	}
	persisted, err := receiptStore.GetByReceiptIDForTenant(context.Background(), defaultRuntimeTenantID, response.ReceiptID)
	if err != nil {
		t.Fatalf("tenant get persisted evaluate receipt: %v", err)
	}
	if persisted.DecisionHash != response.DecisionHash {
		t.Fatalf("persisted decision_hash = %q, evaluate response = %q", persisted.DecisionHash, response.DecisionHash)
	}
	if valid, err := signer.VerifyReceipt(persisted); err != nil || !valid {
		t.Fatalf("persisted V5 receipt did not verify: valid=%v err=%v", valid, err)
	}
	listed, err := receiptStore.ListByTenantCursor(context.Background(), defaultRuntimeTenantID, store.TenantReceiptCursor{}, 10)
	if err != nil || len(listed) != 1 || listed[0].DecisionHash != response.DecisionHash {
		t.Fatalf("tenant list decision_hash = %+v err=%v, want %q", listed, err, response.DecisionHash)
	}
	if valid, err := signer.VerifyReceipt(listed[0]); err != nil || !valid {
		t.Fatalf("listed V5 receipt did not verify: valid=%v err=%v", valid, err)
	}

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":`+strconv.Quote(sessionID)+`,"format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("evidence export status=%d body=%s", exportRec.Code, exportRec.Body.String())
	}
	bundle, err := readEvidenceBundle(exportRec.Body.Bytes())
	if err != nil {
		t.Fatalf("read evidence bundle: %v", err)
	}
	var exported contracts.Receipt
	if err := json.Unmarshal(bundle.Files["receipts/"+response.ReceiptID+".json"], &exported); err != nil {
		t.Fatalf("decode exported receipt: %v", err)
	}
	if exported.DecisionHash != response.DecisionHash {
		t.Fatalf("exported decision_hash = %q, evaluate response = %q", exported.DecisionHash, response.DecisionHash)
	}
	if valid, err := signer.VerifyReceipt(&exported); err != nil || !valid {
		t.Fatalf("exported V5 receipt did not verify: valid=%v err=%v", valid, err)
	}
	assertReceiptSessionRetrievalAndExport(t, mux, sessionID, response.ReceiptID)
}

func TestStandaloneExecutorReceiptIsRetrievableAndExportableBySignedSession(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helmcrypto.NewEd25519Signer("standalone-route-test")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1700000000, 0).UTC()
	effect := &contracts.Effect{
		EffectID:   "effect-standalone-route",
		EffectType: "EXECUTE_TOOL",
		ArgsHash:   "args-standalone-route",
		Params:     map[string]any{"tool_name": "ls"},
	}
	effectDigest, err := contracts.CanonicalEffectDigest(effect)
	if err != nil {
		t.Fatal(err)
	}
	decision := &contracts.DecisionRecord{
		ID:                "decision-standalone-route",
		Verdict:           string(contracts.VerdictAllow),
		ReasonCode:        "ALLOW_BY_POLICY",
		PolicyContentHash: "policy-standalone-route",
		EffectDigest:      effectDigest,
		InputContext:      map[string]any{"tenant_id": "untrusted-tenant"},
	}
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:       decision.ID,
		EffectDigestHash: decision.EffectDigest,
		AllowedTool:      "ls",
		ExpiresAt:        clock.Add(time.Hour),
	}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
	safeExecutor := executor.NewSafeExecutor(signer, signer, receiptRouteStaticDriver{}, receiptStore, nil, nil, "", nil, nil, nil, func() time.Time {
		return clock
	})
	ctx := helmauth.WithPrincipal(context.Background(), &helmauth.BasePrincipal{ID: "standalone-route", TenantID: defaultRuntimeTenantID})
	receipt, _, err := safeExecutor.Execute(ctx, effect, decision, intent)
	if err != nil {
		t.Fatalf("execute standalone receipt: %v", err)
	}
	wantSessionID := "standalone:decision:" + decision.ID
	if receipt.SessionID != wantSessionID || receipt.SignatureVersion != contracts.ReceiptSignatureV5 {
		t.Fatalf("standalone receipt identity=%q version=%q", receipt.SessionID, receipt.SignatureVersion)
	}
	expectedDecisionHash, err := helmcrypto.DecisionSemanticHash(decision)
	if err != nil {
		t.Fatalf("derive decision hash: %v", err)
	}
	repeatedDecisionHash, err := helmcrypto.DecisionSemanticHash(decision)
	if err != nil || repeatedDecisionHash != expectedDecisionHash {
		t.Fatalf("semantic decision hash must be deterministic: first=%q second=%q err=%v", expectedDecisionHash, repeatedDecisionHash, err)
	}
	if receipt.DecisionHash != expectedDecisionHash || receipt.DecisionHash == receipt.OutputHash {
		t.Fatalf("receipt decision_hash must use the canonical decision preimage, not execution output: receipt=%+v expected=%q", receipt, expectedDecisionHash)
	}
	if receipts, err := receiptStore.ListByTenantSession(context.Background(), "other-tenant", wantSessionID, 0, 10); err != nil || len(receipts) != 0 {
		t.Fatalf("cross-tenant session read receipts=%+v err=%v, want no records", receipts, err)
	}
	if _, err := receiptStore.GetByReceiptIDForTenant(context.Background(), "other-tenant", receipt.ReceiptID); err == nil {
		t.Fatal("cross-tenant receipt lookup unexpectedly succeeded")
	}

	mux := http.NewServeMux()
	registerReceiptRoutes(mux, &Services{ReceiptStore: receiptStore})
	registerContractRoutes(mux, &Services{ReceiptStore: receiptStore})
	assertReceiptSessionRetrievalAndExport(t, mux, wantSessionID, receipt.ReceiptID)
}

func assertReceiptSessionRetrievalAndExport(t *testing.T, mux *http.ServeMux, sessionID, receiptID string) {
	t.Helper()
	sessionPath := "/api/v1/proofgraph/sessions/" + url.PathEscape(sessionID) + "/receipts"
	sessionReq := httptest.NewRequest(http.MethodGet, sessionPath, nil)
	authorizeTestRequest(sessionReq)
	sessionRec := httptest.NewRecorder()
	mux.ServeHTTP(sessionRec, sessionReq)
	if sessionRec.Code != http.StatusOK {
		t.Fatalf("session receipts status=%d body=%s", sessionRec.Code, sessionRec.Body.String())
	}
	var sessionReceipts []*contracts.Receipt
	if err := json.Unmarshal(sessionRec.Body.Bytes(), &sessionReceipts); err != nil {
		t.Fatal(err)
	}
	if len(sessionReceipts) != 1 || sessionReceipts[0].ReceiptID != receiptID || sessionReceipts[0].SessionID != sessionID {
		t.Fatalf("session receipts=%+v, want receipt=%q session=%q", sessionReceipts, receiptID, sessionID)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/receipts?session_id="+url.QueryEscape(sessionID), nil)
	authorizeTestRequest(listReq)
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), receiptID) {
		t.Fatalf("receipt list status=%d body=%s", listRec.Code, listRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/receipts/"+receiptID, nil)
	authorizeTestRequest(getReq)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), `"session_id":"`+sessionID+`"`) {
		t.Fatalf("receipt get status=%d body=%s", getRec.Code, getRec.Body.String())
	}

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":`+strconv.Quote(sessionID)+`,"format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("evidence export status=%d body=%s", exportRec.Code, exportRec.Body.String())
	}
	bundle, err := readEvidenceBundle(exportRec.Body.Bytes())
	if err != nil {
		t.Fatalf("read evidence bundle: %v", err)
	}
	if bundle.Manifest.SessionID != sessionID {
		t.Fatalf("evidence manifest session=%q, want %q", bundle.Manifest.SessionID, sessionID)
	}
	if _, ok := bundle.Files["receipts/"+receiptID+".json"]; !ok {
		t.Fatalf("evidence bundle omitted receipt %q: %v", receiptID, bundle.Files)
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

	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry/api-fixture/approve", strings.NewReader(`{"approver_id":"user:alice","approval_receipt_id":"approval-r1","reason":"reviewed","tool_names":["local.echo"]}`))
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
	svc, cleanup := newVerifiedEvidenceRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"verified-session","format":"tar.gz"}`))
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
	if !resultErrorsContain(result, "trusted evidence bundle seal verification failed") {
		t.Fatalf("expected trusted seal failure, got %+v", result)
	}
}

func TestEvidenceAndReplayVerifyRejectForgedSelfConsistentBundle(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	trustedSigner, err := helmcrypto.NewHybridSigner("trusted")
	if err != nil {
		t.Fatalf("create trusted signer: %v", err)
	}
	forgedSigner, err := helmcrypto.NewHybridSigner("forged")
	if err != nil {
		t.Fatalf("create forged signer: %v", err)
	}
	valid := &contracts.Receipt{
		ReceiptID:    "rcpt-trusted",
		DecisionID:   "dec-trusted",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		SessionID:    "trusted-session",
		LamportClock: 1,
		ArgsHash:     "args-trusted",
	}
	if err := trustedSigner.SignReceipt(valid); err != nil {
		t.Fatalf("sign trusted receipt: %v", err)
	}
	forged := *valid
	forged.ReceiptID = "rcpt-forged"
	forged.DecisionID = "dec-forged"
	forged.SessionID = "forged-session"
	forged.ArgsHash = "args-forged"
	forged.Signature = ""
	if err := forgedSigner.SignReceipt(&forged); err != nil {
		t.Fatalf("sign forged receipt: %v", err)
	}

	validBundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("trusted-session", []*contracts.Receipt{valid}, nil, &Services{ReceiptSigner: trustedSigner})
	if err != nil {
		t.Fatalf("build trusted bundle: %v", err)
	}
	forgedBundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("forged-session", []*contracts.Receipt{&forged}, nil, &Services{ReceiptSigner: forgedSigner})
	if err != nil {
		t.Fatalf("build forged bundle: %v", err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: trustedSigner})

	for _, endpoint := range []string{"/api/v1/evidence/verify", "/api/v1/replay/verify"} {
		t.Run(endpoint+" trusted", func(t *testing.T) {
			result := postEvidenceVerification(t, mux, endpoint, validBundle)
			if result["verdict"] != "PASS" {
				t.Fatalf("trusted bundle verification = %+v", result)
			}
		})
		t.Run(endpoint+" forged", func(t *testing.T) {
			result := postEvidenceVerification(t, mux, endpoint, forgedBundle)
			if result["verdict"] != "FAIL" {
				t.Fatalf("forged bundle verification = %+v", result)
			}
			if !resultErrorsContain(result, "trusted evidence bundle seal verification failed") {
				t.Fatalf("forged bundle did not fail trusted seal verification: %+v", result)
			}
		})
	}
}

func TestEvidenceAndReplayVerifyRejectTamperedUnsignedReceiptAttachments(t *testing.T) {
	svc, cleanup := newVerifiedEvidenceRouteTestServices(t)
	defer cleanup()
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "scope-unsigned",
		SubjectHash:         "sha256:subject-unsigned",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatalf("seed verification scope: %v", err)
	}
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), defaultRuntimeTenantID, "unsigned-fields-session", &contracts.Receipt{
		ReceiptID:    "rcpt-unsigned-fields",
		DecisionID:   "dec-unsigned-fields",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 2, 0, time.UTC),
		ExecutorID:   "agent.test",
		DecisionHash: "sha256:unsigned-fields-decision",
		ArgsHash:     "args-unsigned-fields",
		ScopeHash:    scope.ScopeHash,
		Evidence: map[string]string{
			"scope_ref": scope.ScopeHash,
		},
		Metadata: map[string]any{
			"risk_class": "T2",
			"scope_hash": scope.ScopeHash,
		},
	}, svc.ReceiptSigner)
	svc.BoundarySurfaces = registry

	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)
	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"unsigned-fields-session","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRec.Code, exportRec.Body.String())
	}

	tampered, err := tamperEvidenceReceiptFields(exportRec.Body.Bytes(), func(receipt *contracts.Receipt) {
		receipt.ScopeHash = "sha256:tampered-scope"
		if receipt.Evidence == nil {
			receipt.Evidence = map[string]string{}
		}
		receipt.Evidence["scope_ref"] = "sha256:tampered-scope"
		if receipt.Metadata == nil {
			receipt.Metadata = map[string]any{}
		}
		receipt.Metadata["scope_hash"] = "sha256:tampered-scope"
		receipt.Metadata["operator_note"] = "tampered after issuance"
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := readEvidenceBundle(tampered)
	if err != nil {
		t.Fatalf("read tampered bundle: %v", err)
	}
	var tamperedReceipt contracts.Receipt
	for name, data := range parsed.Files {
		if strings.HasPrefix(name, "receipts/") {
			if err := json.Unmarshal(data, &tamperedReceipt); err != nil {
				t.Fatalf("decode tampered receipt: %v", err)
			}
			break
		}
	}
	if err := verifyTrustedEvidenceReceipt(svc, &tamperedReceipt); err != nil {
		t.Fatalf("tampered unsigned fields unexpectedly broke receipt signature: %v", err)
	}

	for _, endpoint := range []string{"/api/v1/evidence/verify", "/api/v1/replay/verify"} {
		result := postEvidenceVerification(t, mux, endpoint, tampered)
		if result["verdict"] != "FAIL" {
			t.Fatalf("%s expected tampered unsigned fields to fail, got %+v", endpoint, result)
		}
		if !resultErrorsContain(result, "trusted evidence bundle seal verification failed") {
			t.Fatalf("%s expected trusted seal failure, got %+v", endpoint, result)
		}
	}
}

func TestTrustedEvidenceBundleSealSignerRejectsUnsupportedRuntimeProfiles(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	mldsaSigner, err := helmcrypto.NewMLDSASigner("mldsa-only")
	if err != nil {
		t.Fatalf("create mldsa signer: %v", err)
	}
	if _, _, err := trustedEvidenceBundleSealSigner(&Services{ReceiptSigner: mldsaSigner}); err == nil || !strings.Contains(err.Error(), "MLDSA-only") {
		t.Fatalf("expected MLDSA-only compatibility error, got %v", err)
	}

	keyring := helmcrypto.NewKeyRing()
	edSigner, err := helmcrypto.NewEd25519Signer("keyring-ed25519")
	if err != nil {
		t.Fatalf("create keyring signer: %v", err)
	}
	keyring.AddKey(edSigner)
	if _, _, err := trustedEvidenceBundleSealSigner(&Services{ReceiptSigner: keyring}); err == nil || !strings.Contains(err.Error(), "keyring") {
		t.Fatalf("expected keyring compatibility error, got %v", err)
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

func TestApprovalRouteDerivesActorAndRejectsStaleCeremony(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", strings.NewReader(`{"approval_id":"approval-raw-admin","subject":"mcp:srv","action":"mcp.approve","requested_by":"agent:test","quorum":1}`))
	authorizeTestRequest(createReq)
	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create approval status=%d body=%s", createRec.Code, createRec.Body.String())
	}
	var created contracts.ApprovalCeremony
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	transitionReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-raw-admin/approve", strings.NewReader(fmt.Sprintf(`{"actor":"user:attacker","expected_ceremony_hash":%q,"reason":"reviewed"}`, created.CeremonyHash)))
	authorizeTestRequest(transitionReq)
	// The raw admin path must ignore both body and tenant-header identities.
	transitionReq.Header.Set(principalHeader, "user:attacker")
	transitionRec := httptest.NewRecorder()
	mux.ServeHTTP(transitionRec, transitionReq)
	if transitionRec.Code != http.StatusOK {
		t.Fatalf("transition approval status=%d body=%s", transitionRec.Code, transitionRec.Body.String())
	}
	var approval contracts.ApprovalCeremony
	if err := json.Unmarshal(transitionRec.Body.Bytes(), &approval); err != nil {
		t.Fatal(err)
	}
	if approval.State != contracts.ApprovalCeremonyAllowed || len(approval.Approvers) != 1 || approval.Approvers[0] != "system-admin" {
		t.Fatalf("raw shared-admin transition trusted caller identity: %+v", approval)
	}

	staleReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-raw-admin/revoke", strings.NewReader(fmt.Sprintf(`{"expected_ceremony_hash":%q,"reason":"stale"}`, created.CeremonyHash)))
	authorizeTestRequest(staleReq)
	staleRec := httptest.NewRecorder()
	mux.ServeHTTP(staleRec, staleReq)
	if staleRec.Code != http.StatusConflict || !strings.Contains(staleRec.Body.String(), "refresh and review again") {
		t.Fatalf("stale transition status=%d body=%s", staleRec.Code, staleRec.Body.String())
	}

	missingHashReq := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-raw-admin/revoke", strings.NewReader(`{"reason":"missing hash"}`))
	authorizeTestRequest(missingHashReq)
	missingHashRec := httptest.NewRecorder()
	mux.ServeHTTP(missingHashRec, missingHashReq)
	if missingHashRec.Code != http.StatusBadRequest || !strings.Contains(missingHashRec.Body.String(), "expected_ceremony_hash") {
		t.Fatalf("missing-hash transition status=%d body=%s", missingHashRec.Code, missingHashRec.Body.String())
	}
}

func TestReplayVerifyDetectsReceiptChainBreakWithValidManifest(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("chain-test")
	if err != nil {
		t.Fatal(err)
	}
	good := &contracts.Receipt{
		ReceiptID:    "rcpt-good",
		DecisionID:   "dec-good",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-good",
		LamportClock: 1,
		ArgsHash:     "args-good",
	}
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
	if err := signer.SignReceipt(good); err != nil {
		t.Fatal(err)
	}
	if err := signer.SignReceipt(broken); err != nil {
		t.Fatal(err)
	}
	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("session-test", []*contracts.Receipt{good, broken}, nil, &Services{ReceiptSigner: signer})
	if err != nil {
		t.Fatalf("build valid-manifest bundle: %v", err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: signer})

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/replay/verify", bytes.NewReader(bundle))
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

func TestEvidenceVerifyScopesReceiptChainsBySession(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("session-chain-test")
	if err != nil {
		t.Fatal(err)
	}
	newReceipt := func(id, sessionID string, lamport uint64, prevHash string) *contracts.Receipt {
		return &contracts.Receipt{
			ReceiptID:    id,
			DecisionID:   "decision-" + id,
			EffectID:     "EXECUTE_TOOL",
			Status:       string(contracts.VerdictAllow),
			Timestamp:    time.Date(2026, 5, 5, 0, int(lamport), 0, 0, time.UTC),
			ExecutorID:   "agent.test",
			SessionID:    sessionID,
			PrevHash:     prevHash,
			LamportClock: lamport,
			ArgsHash:     "args-" + id,
		}
	}

	firstSessionGenesis := newReceipt("first-session-1", "session-first", 1, "")
	if err := signer.SignReceipt(firstSessionGenesis); err != nil {
		t.Fatal(err)
	}
	firstSessionHash, err := contracts.ReceiptChainHash(firstSessionGenesis)
	if err != nil {
		t.Fatal(err)
	}
	firstSessionNext := newReceipt("first-session-2", "session-first", 2, firstSessionHash)
	if err := signer.SignReceipt(firstSessionNext); err != nil {
		t.Fatal(err)
	}
	secondSessionGenesis := newReceipt("second-session-1", "session-second", 1, "")
	if err := signer.SignReceipt(secondSessionGenesis); err != nil {
		t.Fatal(err)
	}
	secondSessionHash, err := contracts.ReceiptChainHash(secondSessionGenesis)
	if err != nil {
		t.Fatal(err)
	}
	secondSessionNext := newReceipt("second-session-2", "session-second", 2, secondSessionHash)
	if err := signer.SignReceipt(secondSessionNext); err != nil {
		t.Fatal(err)
	}

	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("", []*contracts.Receipt{
		firstSessionNext,
		secondSessionNext,
		firstSessionGenesis,
		secondSessionGenesis,
	}, nil, &Services{ReceiptSigner: signer})
	if err != nil {
		t.Fatalf("build multi-session evidence bundle: %v", err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: signer})

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verify", bytes.NewReader(bundle))
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
		t.Fatalf("expected independent session chains to verify, got %+v", result)
	}
	checks, _ := result["checks"].(map[string]any)
	if checks["causal_chain"] != "PASS" {
		t.Fatalf("expected causal chain verification to pass, got %+v", result)
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

func TestWriteEvidenceBundlePackFilesRejectsUnsafeDerivedNames(t *testing.T) {
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "../../escaped-artifact",
		SubjectHash:         "sha256:subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatalf("seed verification scope: %v", err)
	}
	files, err := buildEvidenceBundleFilesWithSurfaceArtifacts("session-unsafe", []*contracts.Receipt{{
		ReceiptID:    "../../escaped-receipt",
		DecisionID:   "dec-unsafe",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-unsafe",
		ScopeHash:    scope.ScopeHash,
		LamportClock: 1,
		ArgsHash:     "args-unsafe",
		Metadata: map[string]any{
			"risk_class": "T2",
		},
	}}, registry)
	if err != nil {
		t.Fatalf("build unsafe bundle files: %v", err)
	}
	for _, name := range []string{
		"receipts/../../escaped-receipt.json",
		"verification_scopes/../../escaped-artifact.json",
	} {
		if _, ok := files[name]; !ok {
			t.Fatalf("expected derived file %q in bundle files: %v", name, files)
		}
	}

	root := t.TempDir()
	packDir := filepath.Join(root, "pack")
	if err := os.Mkdir(packDir, 0o700); err != nil {
		t.Fatalf("create pack dir: %v", err)
	}
	err = writeEvidenceBundlePackFiles(packDir, files)
	if err == nil || !strings.Contains(err.Error(), `unsafe archive path "receipts/../../escaped-receipt.json"`) && !strings.Contains(err.Error(), `unsafe archive path "verification_scopes/../../escaped-artifact.json"`) {
		t.Fatalf("expected unsafe path rejection, got %v", err)
	}
	for _, escaped := range []string{"escaped-receipt.json", "escaped-artifact.json"} {
		if _, statErr := os.Stat(filepath.Join(root, escaped)); !os.IsNotExist(statErr) {
			t.Fatalf("expected no escaped write for %q, stat err=%v", escaped, statErr)
		}
	}
}

func TestBuildTrustedEvidenceBundleWithSurfaceArtifactsAllowsSafeNames(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("safe-export")
	if err != nil {
		t.Fatal(err)
	}
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "scope-safe",
		SubjectHash:         "sha256:subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatalf("seed verification scope: %v", err)
	}
	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-safe",
		DecisionID:   "dec-safe",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-safe",
		ScopeHash:    scope.ScopeHash,
		LamportClock: 1,
		ArgsHash:     "args-safe",
		Metadata: map[string]any{
			"risk_class": "T2",
		},
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatal(err)
	}

	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("session-safe", []*contracts.Receipt{receipt}, registry, &Services{ReceiptSigner: signer})
	if err != nil {
		t.Fatalf("build trusted evidence bundle: %v", err)
	}
	parsed, err := readEvidenceBundle(bundle)
	if err != nil {
		t.Fatalf("read evidence bundle: %v", err)
	}
	for _, name := range []string{
		"receipts/rcpt-safe.json",
		"verification_scopes/scope-safe.json",
		evidenceBundleIndexPath,
		evidencepkg.EvidencePackSealPath,
	} {
		if _, ok := parsed.Files[name]; !ok {
			t.Fatalf("expected safe bundle file %q: %v", name, parsed.Files)
		}
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

func TestReceiptListUsesOpaqueTenantKeysetCursorAcrossSessions(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	second := &contracts.Receipt{
		ReceiptID:  "rcpt-next",
		DecisionID: "dec-next",
		EffectID:   "EXECUTE_TOOL",
		Status:     string(contracts.VerdictAllow),
		Timestamp:  time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID: "agent.peer",
		Signature:  "sig-next",
		ArgsHash:   "args-next",
	}
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), defaultRuntimeTenantID, "session-peer", second)

	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	firstPage := requestReceiptList(t, mux, "/api/v1/receipts?limit=1")
	firstCursor, _ := firstPage["next_cursor"].(string)
	if firstPage["count"] != float64(1) || firstPage["has_more"] != true || !strings.HasPrefix(firstCursor, tenantReceiptCursorVersionPrefix) {
		t.Fatalf("first page pagination metadata = %+v", firstPage)
	}
	secondPage := requestReceiptList(t, mux, "/api/v1/receipts?since="+url.QueryEscape(firstCursor)+"&limit=1")
	if secondPage["count"] != float64(1) || secondPage["has_more"] != false {
		t.Fatalf("second page pagination metadata = %+v", secondPage)
	}
	firstIDs := receiptIDsFromPage(t, firstPage)
	secondIDs := receiptIDsFromPage(t, secondPage)
	for receiptID := range secondIDs {
		if firstIDs[receiptID] {
			t.Fatalf("tenant keyset cursor duplicated receipt %q", receiptID)
		}
		firstIDs[receiptID] = true
	}
	if len(firstIDs) != 2 || !firstIDs["rcpt-test"] || !firstIDs["rcpt-next"] {
		t.Fatalf("tenant keyset cursor omitted tied-Lamport receipts: %+v", firstIDs)
	}

	legacyReq := httptest.NewRequest(http.MethodGet, "/api/v1/receipts?since=lamport:1&limit=1", nil)
	authorizeTestRequest(legacyReq)
	legacyRec := httptest.NewRecorder()
	mux.ServeHTTP(legacyRec, legacyReq)
	if legacyRec.Code != http.StatusBadRequest {
		t.Fatalf("tenant-wide scalar cursor status = %d body=%s", legacyRec.Code, legacyRec.Body.String())
	}
}

func receiptIDsFromPage(t *testing.T, page map[string]any) map[string]bool {
	t.Helper()
	encoded, err := json.Marshal(page["receipts"])
	if err != nil {
		t.Fatal(err)
	}
	var receipts []*contracts.Receipt
	if err := json.Unmarshal(encoded, &receipts); err != nil {
		t.Fatal(err)
	}
	return receiptIDSet(receipts)
}

func receiptIDSet(receipts []*contracts.Receipt) map[string]bool {
	ids := make(map[string]bool, len(receipts))
	for _, receipt := range receipts {
		if receipt != nil {
			ids[receipt.ReceiptID] = true
		}
	}
	return ids
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

func newVerifiedEvidenceRouteTestServices(t *testing.T) (*Services, func()) {
	t.Helper()
	t.Setenv("HELM_PRODUCTION", "")
	svc, cleanup := newContractRouteTestServices(t)
	signer, err := helmcrypto.NewEd25519Signer("evidence-route-test")
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	svc.ReceiptSigner = signer
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), defaultRuntimeTenantID, "verified-session", &contracts.Receipt{
		ReceiptID:    "rcpt-verified",
		DecisionID:   "dec-verified",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		DecisionHash: "sha256:verified-decision",
		ArgsHash:     "args-verified",
	}, signer)
	return svc, cleanup
}

func appendTenantScopedReceipt(t *testing.T, receiptStore *store.SQLiteReceiptStore, tenantID, sessionID string, receipt *contracts.Receipt, signers ...helmcrypto.Signer) {
	t.Helper()
	if len(signers) > 1 {
		t.Fatal("append tenant-scoped receipt accepts at most one signer")
	}
	if err := receiptStore.AppendCausalScoped(context.Background(), tenantID, sessionID, func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		copy := *receipt
		copy.SignatureVersion = contracts.ReceiptSignatureV5
		if strings.TrimSpace(copy.DecisionHash) == "" {
			copy.DecisionHash = "sha256:test-decision-" + copy.DecisionID
		}
		copy.SessionID = sessionID
		copy.LamportClock = lamport
		copy.PrevHash = prevHash
		if len(signers) == 1 {
			if err := signers[0].SignReceipt(&copy); err != nil {
				return nil, fmt.Errorf("sign tenant-scoped receipt: %w", err)
			}
		}
		return &copy, nil
	}); err != nil {
		t.Fatalf("append tenant-scoped receipt: %v", err)
	}
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
	req.Header.Set(tenantHeader, defaultRuntimeTenantID)
	req.Header.Set(principalHeader, "system-admin")
}

type overflowReceiptStore struct {
	captureReceiptStore
}

type exactLimitReceiptStore struct {
	overflowReceiptStore
}

func (s *exactLimitReceiptStore) ListByTenantSession(_ context.Context, _, sessionID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	if since >= maxEvidenceExportReceipts {
		return nil, nil
	}
	remaining := int(maxEvidenceExportReceipts - since)
	if limit > remaining {
		limit = remaining
	}
	return overflowReceipts(sessionID, since, limit), nil
}

func (s *overflowReceiptStore) ListByAgent(_ context.Context, agentID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	return overflowReceipts(agentID, since, limit), nil
}

func (s *overflowReceiptStore) ListSince(_ context.Context, since uint64, limit int) ([]*contracts.Receipt, error) {
	return overflowReceipts("agent.overflow", since, limit), nil
}

func (s *overflowReceiptStore) GetByReceiptIDForTenant(ctx context.Context, _ string, receiptID string) (*contracts.Receipt, error) {
	return s.GetByReceiptID(ctx, receiptID)
}

func (s *overflowReceiptStore) ListByTenant(_ context.Context, _ string, since uint64, limit int) ([]*contracts.Receipt, error) {
	return overflowReceipts("session.overflow", since, limit), nil
}

func (s *overflowReceiptStore) ListByTenantSession(_ context.Context, _, sessionID string, since uint64, limit int) ([]*contracts.Receipt, error) {
	return overflowReceipts(sessionID, since, limit), nil
}

func overflowReceipts(agentID string, since uint64, limit int) []*contracts.Receipt {
	receipts := make([]*contracts.Receipt, 0, limit)
	for i := 0; i < limit; i++ {
		lamport := since + uint64(i) + 1
		receipts = append(receipts, &contracts.Receipt{
			ReceiptID:        fmt.Sprintf("rcpt-overflow-%d", lamport),
			DecisionID:       fmt.Sprintf("dec-overflow-%d", lamport),
			EffectID:         "EXECUTE_TOOL",
			Status:           string(contracts.VerdictDeny),
			Timestamp:        time.Unix(int64(lamport), 0).UTC(),
			ExecutorID:       agentID,
			Signature:        "sig-overflow",
			DecisionHash:     fmt.Sprintf("sha256:overflow-decision-%d", lamport),
			LamportClock:     lamport,
			SignatureVersion: contracts.ReceiptSignatureV5,
			SessionID:        agentID,
		})
	}
	return receipts
}

func tamperEvidenceReceipt(bundle []byte) ([]byte, error) {
	return tamperEvidenceReceiptFields(bundle, func(receipt *contracts.Receipt) {
		receipt.Signature = strings.Repeat("0", len(receipt.Signature))
	})
}

func tamperEvidenceReceiptFields(bundle []byte, mutate func(*contracts.Receipt)) ([]byte, error) {
	files, err := readRawEvidenceBundleFiles(bundle)
	if err != nil {
		return nil, err
	}
	for name, data := range files {
		if strings.HasPrefix(name, "receipts/") {
			var receipt contracts.Receipt
			if err := json.Unmarshal(data, &receipt); err != nil {
				return nil, err
			}
			mutate(&receipt)
			updated, err := json.Marshal(&receipt)
			if err != nil {
				return nil, err
			}
			files[name] = updated
			return tarEvidenceBundleFiles(files)
		}
	}
	return nil, fmt.Errorf("evidence bundle has no receipt")
}

func readRawEvidenceBundleFiles(bundle []byte) (map[string][]byte, error) {
	if len(bundle) == 0 {
		return nil, fmt.Errorf("empty evidence bundle")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, err
		}
		files[header.Name] = data
	}
}

func resultErrorsContain(result map[string]any, want string) bool {
	values, _ := result["errors"].([]any)
	for _, value := range values {
		if text, ok := value.(string); ok && strings.Contains(text, want) {
			return true
		}
	}
	return false
}

func postEvidenceVerification(t *testing.T, mux *http.ServeMux, endpoint string, bundle []byte) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(bundle))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify %s status=%d body=%s", endpoint, rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
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
