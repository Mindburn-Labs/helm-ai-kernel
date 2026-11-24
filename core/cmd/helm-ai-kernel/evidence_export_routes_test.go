package main

// quantum_posture: These route tests use classical Ed25519 receipt signatures.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

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
	if result["outcome"] != "VERIFIED" {
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
		Evidence: map[string]string{
			"scope_ref": scope.ScopeHash,
		},
		Metadata: map[string]any{
			"risk_class":             "T2",
			"side_effectful":         true,
			"scope_hash":             scope.ScopeHash,
			"verification_scope_ref": scope.ScopeHash,
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
	if verifyRec.Code != http.StatusOK || result["outcome"] != "VERIFIED" {
		t.Fatalf("referenced evidence verification status=%d result=%+v", verifyRec.Code, result)
	}
}

func TestArtifactReceiptRefsRequireCanonicalTenantOwnership(t *testing.T) {
	svc, cleanup := newVerifiedEvidenceRouteTestServices(t)
	defer cleanup()
	bindingStore, cleanupBindings := newRouteAuthTestBindingStore(t)
	defer cleanupBindings()
	if _, err := bindingStore.Bind(context.Background(), store.PrincipalBinding{
		TenantID:    "tenant-b",
		PrincipalID: "operator-tenant-b",
	}, false); err != nil {
		t.Fatalf("seed tenant-b principal binding: %v", err)
	}
	SetPrincipalBindingStore(bindingStore)
	t.Cleanup(func() { SetPrincipalBindingStore(nil) })

	const sessionID = "artifact-ownership-session"
	const receiptID = "rcpt-artifact-owned"
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), defaultRuntimeTenantID, sessionID, &contracts.Receipt{
		ReceiptID:    receiptID,
		DecisionID:   "dec-artifact-owned",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 1, 0, time.UTC),
		ExecutorID:   "agent.test",
		DecisionHash: "sha256:artifact-owned-decision",
		ArgsHash:     "args-artifact-owned",
		Metadata: map[string]any{
			"risk_class": "T2",
		},
	}, svc.ReceiptSigner)

	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	svc.BoundarySurfaces = registry
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)
	postScope := func(tenantID, scopeID string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"verification_scope_id":%q,"receipt_refs":[%q],"subject_hash":"sha256:subject","risk_class":"T2","checks_performed":["hash"],"verifier_hash":"sha256:verifier","policy_hash":"sha256:policy"}`, scopeID, receiptID)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verification-scopes", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
		req.Header.Set(tenantHeader, tenantID)
		principalID := "operator-" + tenantID
		if tenantID == defaultRuntimeTenantID {
			principalID = "system-admin"
		}
		req.Header.Set(principalHeader, principalID)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// The registry has no tenant dimension, so another tenant is refused before
	// its receipt references are even checked (HELM-755 S-05).
	if rec := postScope("tenant-b", "scope-forged-by-tenant-b"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant artifact reference status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := registry.GetVerificationScope("scope-forged-by-tenant-b"); ok {
		t.Fatal("cross-tenant artifact reference reached the shared registry")
	}
	if rec := postScope(defaultRuntimeTenantID, "scope-owned-by-tenant-a"); rec.Code != http.StatusCreated {
		t.Fatalf("same-tenant artifact reference status=%d body=%s", rec.Code, rec.Body.String())
	}

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"`+sessionID+`","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("same-tenant evidence export status=%d body=%s", exportRec.Code, exportRec.Body.String())
	}
	bundle, err := readEvidenceBundle(exportRec.Body.Bytes())
	if err != nil {
		t.Fatalf("read evidence bundle: %v", err)
	}
	if _, ok := bundle.Files["verification_scopes/scope-forged-by-tenant-b.json"]; ok {
		t.Fatal("tenant evidence export included rejected cross-tenant artifact")
	}
	if _, ok := bundle.Files["verification_scopes/scope-owned-by-tenant-a.json"]; !ok {
		t.Fatal("tenant evidence export omitted authorized same-tenant artifact")
	}
}

func TestVerificationScopeArtifactRequiresExplicitReceiptEvidenceRef(t *testing.T) {
	scope := contracts.VerificationScope{
		VerificationScopeID: "rcpt-not-a-scope-reference",
		ScopeHash:           "sha256:scope-reference",
	}
	data, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &contracts.Receipt{
		ReceiptID:         scope.VerificationScopeID,
		ScopeHash:         scope.ScopeHash,
		Signature:         scope.ScopeHash,
		MerkleRoot:        scope.ScopeHash,
		EffectGraphNodeID: scope.ScopeHash,
		Metadata: map[string]any{
			"risk_class":            "T2",
			"verification_scope_id": scope.VerificationScopeID,
			"scope_hash":            scope.ScopeHash,
		},
	}
	if evidenceArtifactReferencesReceipt("verification_scopes/", data, receipt) {
		t.Fatal("intrinsic receipt fields or metadata must not reference a verification scope")
	}
	receipt.Evidence = map[string]string{"scope_ref": scope.ScopeHash}
	if !evidenceArtifactReferencesReceipt("verification_scopes/", data, receipt) {
		t.Fatal("explicit receipt evidence reference did not link the verification scope")
	}
}

func TestSealedSurfaceArtifactReceiptRefsLinkEvidence(t *testing.T) {
	receipt := &contracts.Receipt{ReceiptID: "rcpt-sealed-link"}
	cases := []struct {
		name     string
		prefix   string
		artifact any
		metadata map[string]any
	}{
		{
			name:     "verification scope",
			prefix:   "verification_scopes/",
			artifact: contracts.VerificationScope{ReceiptRefs: []string{receipt.ReceiptID}},
			metadata: map[string]any{
				"risk_class": "T2",
			},
		},
		{
			name:     "plan transaction",
			prefix:   "plan_transactions/",
			artifact: contracts.PlanTransaction{ReceiptRefs: []string{receipt.ReceiptID}},
			metadata: map[string]any{
				"requires_plan_transaction": true,
			},
		},
		{
			name:     "grounded action",
			prefix:   "grounded_action_refs/",
			artifact: contracts.GroundedActionRef{ReceiptRefs: []string{receipt.ReceiptID}},
			metadata: map[string]any{
				"requires_grounded_action_ref": true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.artifact)
			if err != nil {
				t.Fatal(err)
			}
			receipt.Metadata = tc.metadata
			if !evidenceArtifactReferencesReceipt(tc.prefix, data, receipt) {
				t.Fatal("sealed artifact receipt_refs did not link the receipt")
			}
		})
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

func TestBoundaryCheckpointUsesDurableReceiptCounter(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	svc.ReceiptStore = &checkpointCountingReceiptStore{count: 37}
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/boundary/checkpoints", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("checkpoint status=%d body=%s", rec.Code, rec.Body.String())
	}
	var checkpoint contracts.BoundaryCheckpoint
	if err := json.Unmarshal(rec.Body.Bytes(), &checkpoint); err != nil {
		t.Fatal(err)
	}
	if checkpoint.ReceiptCount != 37 {
		t.Fatalf("counter-backed checkpoint receipt_count=%d, want 37", checkpoint.ReceiptCount)
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

type overflowReceiptStore struct {
	captureReceiptStore
}

type exactLimitReceiptStore struct {
	overflowReceiptStore
}

type checkpointCountingReceiptStore struct {
	captureReceiptStore
	count int
}

func (s *checkpointCountingReceiptStore) CountReceipts(context.Context) (int, error) {
	return s.count, nil
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

func (s *overflowReceiptStore) GetCanonicalReceiptByIDForTenant(_ context.Context, _ string, receiptID string) (*contracts.Receipt, error) {
	return &contracts.Receipt{ReceiptID: receiptID}, nil
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
