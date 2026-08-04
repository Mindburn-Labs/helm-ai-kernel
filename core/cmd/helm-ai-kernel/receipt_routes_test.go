package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/agentruntime"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

type captureReceiptStore struct {
	last         *contracts.Receipt
	stored       *contracts.Receipt
	storeErr     error
	sessionID    string
	readTenantID string
}

type scopedCaptureReceiptStore struct {
	*captureReceiptStore
	tenantID       string
	externalID     string
	scopedAppended bool
}

func (s *scopedCaptureReceiptStore) AppendCausalScoped(ctx context.Context, tenantID, sessionID string, build store.CausalReceiptBuilder) error {
	s.tenantID = tenantID
	s.externalID = sessionID
	s.scopedAppended = true
	return s.captureReceiptStore.AppendCausal(ctx, sessionID, build)
}

func (s *scopedCaptureReceiptStore) NormalizeReceiptTimestamp(timestamp time.Time) time.Time {
	return timestamp.UTC().Truncate(time.Microsecond)
}

type recordingScopedStopReader struct {
	inner  kernel.ScopedStopReader
	calls  int
	scope  kernel.StopScope
	state  kernel.FenceState
	fenced bool
	err    error
}

func (r *recordingScopedStopReader) IsFenced(ctx context.Context, scope kernel.StopScope) (kernel.FenceState, bool, error) {
	r.calls++
	r.scope = scope
	r.state, r.fenced, r.err = r.inner.IsFenced(ctx, scope)
	return r.state, r.fenced, r.err
}

func (s *captureReceiptStore) Get(context.Context, string) (*contracts.Receipt, error) {
	if s.stored != nil {
		return s.stored, nil
	}
	return nil, errors.New("receipt not found")
}

func (s *captureReceiptStore) GetByReceiptID(_ context.Context, receiptID string) (*contracts.Receipt, error) {
	if s.stored != nil && s.stored.ReceiptID == receiptID {
		return s.stored, nil
	}
	return nil, errors.New("receipt not found")
}

func (s *captureReceiptStore) GetByReceiptIDForTenant(ctx context.Context, tenantID, receiptID string) (*contracts.Receipt, error) {
	s.readTenantID = tenantID
	return s.GetByReceiptID(ctx, receiptID)
}

func (s *captureReceiptStore) ListByTenant(context.Context, string, uint64, int) ([]*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) ListByTenantSession(context.Context, string, string, uint64, int) ([]*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) List(context.Context, int) ([]*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) ListSince(context.Context, uint64, int) ([]*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) ListByAgent(context.Context, string, uint64, int) ([]*contracts.Receipt, error) {
	return nil, errors.New("not implemented")
}

func (s *captureReceiptStore) Store(_ context.Context, receipt *contracts.Receipt) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.stored = receipt
	return nil
}

func (s *captureReceiptStore) AppendCausal(ctx context.Context, sessionID string, build store.CausalReceiptBuilder) error {
	s.sessionID = sessionID
	lamport := uint64(1)
	prevHash := ""
	if s.last != nil {
		lamport = s.last.LamportClock + 1
		hash, err := contracts.ReceiptChainHash(s.last)
		if err != nil {
			return err
		}
		prevHash = hash
	}
	receipt, err := build(s.last, lamport, prevHash)
	if err != nil {
		return err
	}
	return s.Store(ctx, receipt)
}

func (s *captureReceiptStore) GetLastForSession(context.Context, string) (*contracts.Receipt, error) {
	return s.last, nil
}

func TestPersistDecisionReceiptSignsAndStoresReceipt(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	store := &captureReceiptStore{}
	svc := &Services{ReceiptStore: store, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{
		ID:                 "dec-1",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictDeny),
		ReasonCode:         string(contracts.ReasonEmergencyStopFenced),
		PolicyContentHash:  "sha256:policy-content",
		PolicyDecisionHash: "sha256:pdp",
		InputContext:       map[string]any{"session_id": "session-route"},
		Timestamp:          time.Unix(1700000000, 0).UTC(),
	}

	err = persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "test"})
	if err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if store.stored == nil {
		t.Fatal("receipt was not stored")
	}
	if store.stored.Signature == "" {
		t.Fatal("receipt signature was not set")
	}
	if store.stored.ReasonCode != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("receipt reason_code = %q", store.stored.ReasonCode)
	}
	if store.stored.SignatureVersion != contracts.ReceiptSignatureV5 || store.stored.Verdict != decision.Verdict || store.stored.PolicyHash != decision.PolicyContentHash || store.stored.SessionID != "session-route" {
		t.Fatalf("receipt did not bind decision governance fields: %+v", store.stored)
	}
	valid, err := signer.VerifyReceipt(store.stored)
	if err != nil || !valid {
		t.Fatalf("receipt signature invalid: valid=%v err=%v receipt=%+v", valid, err, store.stored)
	}
	if store.stored.Timestamp != decision.Timestamp {
		t.Fatalf("timestamp = %s, want %s", store.stored.Timestamp, decision.Timestamp)
	}
}

func TestPersistDecisionReceiptUsesTenantScopedCausalStorageAndNormalizesBeforeSigning(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	base := &captureReceiptStore{}
	receiptStore := &scopedCaptureReceiptStore{captureReceiptStore: base}
	svc := &Services{ReceiptStore: receiptStore, ReceiptSigner: signer}
	timestamp := time.Date(2026, 8, 1, 12, 0, 0, 123456789, time.UTC)
	decision := &contracts.DecisionRecord{
		ID:                 "dec-scoped",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictAllow),
		PolicyDecisionHash: "sha256:pdp",
		InputContext: map[string]any{
			"tenant_id":  "tenant-trusted",
			"session_id": "external-session",
		},
		Timestamp: timestamp,
	}

	if err := persistDecisionReceiptForTenant(context.Background(), svc, decision, "agent.test", "tenant-trusted", []byte("body"), map[string]any{"source": "test"}); err != nil {
		t.Fatalf("persist scoped receipt: %v", err)
	}
	if !receiptStore.scopedAppended || receiptStore.tenantID != "tenant-trusted" || receiptStore.externalID != "external-session" {
		t.Fatalf("scoped append = %t tenant=%q external_session=%q", receiptStore.scopedAppended, receiptStore.tenantID, receiptStore.externalID)
	}
	if base.stored == nil || base.stored.SessionID != "external-session" {
		t.Fatalf("scoped append changed signed external session: %+v", base.stored)
	}
	if want := executor.ReceiptIDForDecision("tenant-trusted", decision.ID); base.stored.ReceiptID != want {
		t.Fatalf("scoped receipt id = %q, want %q", base.stored.ReceiptID, want)
	}
	wantTimestamp := timestamp.Truncate(time.Microsecond)
	if !base.stored.Timestamp.Equal(wantTimestamp) {
		t.Fatalf("signed timestamp = %s, want normalized %s", base.stored.Timestamp, wantTimestamp)
	}
	valid, err := signer.VerifyReceipt(base.stored)
	if err != nil || !valid {
		t.Fatalf("normalized receipt signature invalid: valid=%t err=%v", valid, err)
	}
}

func TestPersistDecisionReceiptLinksToCanonicalPreviousReceiptHash(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	previous := &contracts.Receipt{
		ReceiptID:    "rcpt-prev",
		DecisionID:   "dec-prev",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Unix(1699999999, 0).UTC(),
		ExecutorID:   "agent.test",
		Metadata:     map[string]any{"resource": "tool-a"},
		Signature:    "sig-prev",
		LamportClock: 7,
		ArgsHash:     "sha256:args-prev",
	}
	expectedPrevHash, err := contracts.ReceiptChainHash(previous)
	if err != nil {
		t.Fatal(err)
	}
	store := &captureReceiptStore{last: previous}
	svc := &Services{ReceiptStore: store, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{
		ID:                 "dec-next",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictAllow),
		PolicyDecisionHash: "sha256:pdp",
		Timestamp:          time.Unix(1700000000, 0).UTC(),
	}

	err = persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "test"})
	if err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if store.stored.PrevHash != expectedPrevHash {
		t.Fatalf("prev_hash = %q, want %q", store.stored.PrevHash, expectedPrevHash)
	}
	if store.stored.LamportClock != previous.LamportClock+1 {
		t.Fatalf("lamport = %d, want %d", store.stored.LamportClock, previous.LamportClock+1)
	}
}

type fakeTransparencyLog struct {
	appended  [][]byte
	appendErr error
	nextIndex uint64
}

func (l *fakeTransparencyLog) Append(leafInput []byte) (uint64, error) {
	if l.appendErr != nil {
		return 0, l.appendErr
	}
	l.appended = append(l.appended, append([]byte(nil), leafInput...))
	idx := l.nextIndex
	l.nextIndex++
	return idx, nil
}

func newTransparencyDecision() *contracts.DecisionRecord {
	return &contracts.DecisionRecord{
		ID:                 "dec-tl",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictAllow),
		PolicyDecisionHash: "sha256:pdp",
		Timestamp:          time.Unix(1700000000, 0).UTC(),
	}
}

func TestPersistDecisionReceiptAnchorsTransparencyLeaf(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	rcptStore := &captureReceiptStore{}
	tl := &fakeTransparencyLog{nextIndex: 5}
	svc := &Services{ReceiptStore: rcptStore, ReceiptSigner: signer, TranspLog: tl, TranspLogID: "log-abc"}

	if err := persistDecisionReceipt(context.Background(), svc, newTransparencyDecision(), "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "test"}); err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if rcptStore.stored == nil {
		t.Fatal("receipt was not stored")
	}
	if len(tl.appended) != 1 {
		t.Fatalf("expected exactly one transparency append, got %d", len(tl.appended))
	}
	if rcptStore.stored.LogID != "log-abc" {
		t.Fatalf("receipt log_id = %q, want log-abc", rcptStore.stored.LogID)
	}
	if rcptStore.stored.LeafIndex != 5 {
		t.Fatalf("receipt leaf_index = %d, want 5", rcptStore.stored.LeafIndex)
	}
	if rcptStore.stored.Transparency == nil || rcptStore.stored.Transparency.Deferred {
		t.Fatalf("expected non-deferred transparency anchor, got %+v", rcptStore.stored.Transparency)
	}
}

func TestPersistDecisionReceiptBlocksWhenTransparencyAppendFailsFailClosed(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	rcptStore := &captureReceiptStore{}
	appendErr := errors.New("transparency log unavailable")
	// Default posture: TranspLogDegrade is false (fail-closed).
	svc := &Services{ReceiptStore: rcptStore, ReceiptSigner: signer, TranspLog: &fakeTransparencyLog{appendErr: appendErr}, TranspLogID: "log-abc"}

	err = persistDecisionReceipt(context.Background(), svc, newTransparencyDecision(), "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "test"})
	if !errors.Is(err, appendErr) {
		t.Fatalf("expected transparency append error to block issuance, got %v", err)
	}
	if rcptStore.stored != nil {
		t.Fatalf("fail-closed issuance must not store a receipt, got %+v", rcptStore.stored)
	}
}

func TestPersistDecisionReceiptDegradesWhenExplicitlyAllowed(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	rcptStore := &captureReceiptStore{}
	svc := &Services{
		ReceiptStore:     rcptStore,
		ReceiptSigner:    signer,
		TranspLog:        &fakeTransparencyLog{appendErr: errors.New("transparency log unavailable")},
		TranspLogID:      "log-abc",
		TranspLogDegrade: true,
	}

	if err := persistDecisionReceipt(context.Background(), svc, newTransparencyDecision(), "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "test"}); err != nil {
		t.Fatalf("degrade mode must not block issuance: %v", err)
	}
	if rcptStore.stored == nil {
		t.Fatal("degrade mode should still store the receipt")
	}
	if rcptStore.stored.Transparency == nil || !rcptStore.stored.Transparency.Deferred {
		t.Fatalf("expected deferred transparency anchor under degrade, got %+v", rcptStore.stored.Transparency)
	}
	if rcptStore.stored.LeafIndex != 0 {
		t.Fatalf("deferred anchor must not claim a leaf index, got %d", rcptStore.stored.LeafIndex)
	}
}

func TestPersistDecisionReceiptReturnsStoreError(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	storeErr := errors.New("store down")
	svc := &Services{ReceiptStore: &captureReceiptStore{storeErr: storeErr}, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{ID: "dec-2", Verdict: string(contracts.VerdictDeny), Timestamp: time.Now().UTC()}

	err = persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("body"), nil)
	if !errors.Is(err, storeErr) {
		t.Fatalf("expected store error, got %v", err)
	}
}

func TestEvaluateRouteRequiresTenantAuthentication(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	svc, receipts := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader([]byte(`{"principal":"attacker","action":"EXECUTE_TOOL","resource":"local.echo"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	if receipts.stored != nil {
		t.Fatalf("unauthenticated evaluate persisted receipt: %+v", receipts.stored)
	}
}

func TestEvaluateRouteRejectsCallerSuppliedTaintedEgressOverride(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv("HELM_TAINT_TRACKING", "1")
	t.Setenv(runtimeTenantIDEnv, defaultRuntimeTenantID)
	t.Setenv(runtimePrincipalIDEnv, "principal-external")
	svc, _ := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	body := []byte(`{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"session_id":"session-external","security_context_trusted":true,"allow_tainted_egress":true,"destination":"https://external.example/upload","taint":["credential"]}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, defaultRuntimeTenantID)
	req.Header.Set(principalHeader, "principal-external")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	var decision contracts.DecisionRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != string(contracts.VerdictDeny) || decision.ReasonCode != string(contracts.ReasonTaintedEgressDeny) {
		t.Fatalf("caller-supplied taint override bypassed deny: %+v", decision)
	}
}

func TestEvaluateRouteBindsReceiptToAuthenticatedPrincipal(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	svc, receipts := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	body := []byte(`{"principal":"attacker","action":"EXECUTE_TOOL","resource":"local.echo","context":{"tenant_id":"tenant-attacker","principal_id":"attacker","session_id":"session-1"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	if receipts.stored == nil {
		t.Fatal("authenticated evaluate did not persist receipt")
	}
	if receipts.stored.SessionID != "session-1" {
		t.Fatalf("signed receipt session = %q, want session-1", receipts.stored.SessionID)
	}
	if receipts.stored.ExecutorID != "principal-trusted" {
		t.Fatalf("receipt executor = %q, want trusted principal", receipts.stored.ExecutorID)
	}
	if receipts.readTenantID != "tenant-trusted" {
		t.Fatalf("evaluate response receipt read tenant = %q, want authenticated tenant", receipts.readTenantID)
	}
	var response api.EvaluateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ReceiptID != receipts.stored.ReceiptID || response.DecisionID != receipts.stored.DecisionID || response.LamportClock != receipts.stored.LamportClock {
		t.Fatalf("legacy route response must use the canonical evaluate shape: %+v receipt=%+v", response, receipts.stored)
	}
}

func TestEvaluateRouteAcceptsCanonicalSDKContract(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	svc, receipts := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	body := []byte(`{"tool":"EXECUTE_TOOL","effect_level":"local.echo","args":{"message":"hello"},"agent_id":"attacker","session_id":" canonical-session ","context":{"session_id":"legacy-session","tenant_id":"tenant-attacker"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("canonical evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	if receipts.stored == nil {
		t.Fatal("canonical evaluate did not persist a receipt")
	}
	if receipts.stored.SessionID != "canonical-session" {
		t.Fatalf("top-level session must be trimmed and take precedence: receipt=%q", receipts.stored.SessionID)
	}
	if receipts.stored.ExecutorID != "principal-trusted" || receipts.stored.EffectID != "EXECUTE_TOOL" {
		t.Fatalf("canonical evaluate did not bind authenticated executor/action: %+v", receipts.stored)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"allow", "verdict", "receipt_id", "decision_id", "decision_hash", "reason_code", "policy_ref", "lamport_clock"} {
		if _, ok := raw[field]; !ok {
			t.Fatalf("canonical evaluate response omitted %q: %s", field, rec.Body.String())
		}
	}
	var response api.EvaluateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ReceiptID != receipts.stored.ReceiptID || response.DecisionID != receipts.stored.DecisionID || response.DecisionHash != receipts.stored.DecisionHash || response.LamportClock != receipts.stored.LamportClock {
		t.Fatalf("canonical response does not match persisted V5 receipt: response=%+v receipt=%+v", response, receipts.stored)
	}
}

func TestEvaluateRouteUsesCanonicalArgsHash(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	svc, receipts := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	args := []byte(`{"nested":{"beta":2,"alpha":1},"message":"<hello>"}`)
	wantHash, err := agentruntime.ComputeArgsHash(args)
	if err != nil {
		t.Fatalf("expected canonical args hash: %v", err)
	}
	body := []byte(`{"tool":"EXECUTE_TOOL","effect_level":"local.echo","args":{"nested":{"beta":2,"alpha":1},"message":"<hello>"},"session_id":"canonical-session"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("canonical args evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	if receipts.stored == nil {
		t.Fatal("canonical args evaluate did not persist a receipt")
	}
	if receipts.stored.ArgsHash != wantHash {
		t.Fatalf("receipt args_hash = %q, want canonical %q", receipts.stored.ArgsHash, wantHash)
	}
}

func TestEvaluateRouteRejectsIncompleteCanonicalContract(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	for name, body := range map[string]string{
		"session": `{"tool":"EXECUTE_TOOL","effect_level":"local.echo"}`,
		"tool":    `{"effect_level":"local.echo","session_id":"session-1"}`,
		"effect":  `{"tool":"EXECUTE_TOOL","session_id":"session-1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			svc, receipts := newEvaluateRouteTestServices(t)
			mux := http.NewServeMux()
			registerReceiptRoutes(mux, svc)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewBufferString(body))
			req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
			req.Header.Set(tenantHeader, "tenant-trusted")
			req.Header.Set(principalHeader, "principal-trusted")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("incomplete canonical request status = %d body=%s", rec.Code, rec.Body.String())
			}
			if receipts.stored != nil {
				t.Fatalf("rejected request persisted receipt: %+v", receipts.stored)
			}
		})
	}
}

func TestEvaluateRouteRejectsSessionIDWithPathSeparators(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	for name, body := range map[string]string{
		"forward slash": `{"tool":"EXECUTE_TOOL","effect_level":"local.echo","session_id":"bad/session"}`,
		"back slash":    `{"tool":"EXECUTE_TOOL","effect_level":"local.echo","context":{"session_id":"bad\\session"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			svc, receipts := newEvaluateRouteTestServices(t)
			mux := http.NewServeMux()
			registerReceiptRoutes(mux, svc)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewBufferString(body))
			req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
			req.Header.Set(tenantHeader, "tenant-trusted")
			req.Header.Set(principalHeader, "principal-trusted")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("invalid session status = %d body=%s", rec.Code, rec.Body.String())
			}
			if receipts.stored != nil {
				t.Fatalf("invalid session persisted receipt: %+v", receipts.stored)
			}
		})
	}
}

func TestReceiptRoutesRejectInvalidSessionQuery(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()

	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts?session_id=bad/session", nil)
	authorizeTestRequest(req)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid session query status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTenantReceiptTailUsesOpaqueKeysetCursorAcrossSessions(t *testing.T) {
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

	firstID, firstReceiptID := requestReceiptTailEvent(t, mux, "/api/v1/receipts/tail?limit=1", "")
	if !strings.HasPrefix(firstID, tenantReceiptCursorVersionPrefix) {
		t.Fatalf("tenant tail event id = %q, want opaque %q cursor", firstID, tenantReceiptCursorVersionPrefix)
	}
	secondID, secondReceiptID := requestReceiptTailEvent(t, mux, "/api/v1/receipts/tail?limit=1", firstID)
	if !strings.HasPrefix(secondID, tenantReceiptCursorVersionPrefix) || secondID == firstID {
		t.Fatalf("resumed tenant tail cursor = %q after %q, want distinct opaque keyset cursors", secondID, firstID)
	}
	if got := map[string]bool{firstReceiptID: true, secondReceiptID: true}; len(got) != 2 || !got["rcpt-test"] || !got["rcpt-next"] {
		t.Fatalf("tenant tail omitted or duplicated tied-Lamport receipts: first=%q second=%q", firstReceiptID, secondReceiptID)
	}
}

type cancelAfterFirstFlushRecorder struct {
	*httptest.ResponseRecorder
	cancel  context.CancelFunc
	flushed bool
}

func (r *cancelAfterFirstFlushRecorder) Flush() {
	r.ResponseRecorder.Flush()
	if !r.flushed {
		r.flushed = true
		r.cancel()
	}
}

func requestReceiptTailEvent(t *testing.T, mux *http.ServeMux, target, lastEventID string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
	authorizeTestRequest(req)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	rec := &cancelAfterFirstFlushRecorder{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("receipt tail status = %d body=%s", rec.Code, rec.Body.String())
	}
	var eventID string
	var receipt contracts.Receipt
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "id: "):
			eventID = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "data: "):
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &receipt); err != nil {
				t.Fatalf("decode receipt tail event: %v body=%s", err, rec.Body.String())
			}
		}
	}
	if eventID == "" || receipt.ReceiptID == "" {
		t.Fatalf("receipt tail did not emit a receipt event: %s", rec.Body.String())
	}
	return eventID, receipt.ReceiptID
}

func newEvaluateRouteTestServices(t *testing.T, guardianOpts ...guardian.GuardianOption) (*Services, *captureReceiptStore) {
	t.Helper()
	signer, err := helmcrypto.NewEd25519Signer("evaluate-route-test")
	if err != nil {
		t.Fatal(err)
	}
	graph := prg.NewGraph()
	if err := graph.AddRule("local.echo", prg.RequirementSet{
		ID:    "allow-local-echo",
		Logic: prg.AND,
		Requirements: []prg.Requirement{
			{ID: "allow", Expression: "true"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	receipts := &captureReceiptStore{}
	return &Services{
		Guardian:      guardian.NewGuardian(signer, graph, artifacts.NewRegistry(nil, nil), guardianOpts...),
		ReceiptStore:  receipts,
		ReceiptSigner: signer,
	}, receipts
}

func TestEvaluateRouteBindsWorkspaceFromVerifiedHeaderWhenScopedFenceEnabled(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-fenced")
	_, stopStore, _ := newEmergencyStopFenceRouteForTest(t)
	command := newEmergencyStopFenceCommand(time.Now().UTC())
	command.CommandID = "stop-command-evaluate-route"
	command.TenantID = "tenant-trusted"
	command.WorkspaceID = "workspace-fenced"
	if _, _, err := stopStore.Fence(context.Background(), command, emergencyStopAcknowledgementIdentityForTest()); err != nil {
		t.Fatal(err)
	}
	if state, fenced, err := stopStore.IsFenced(context.Background(), command.Scope()); err != nil || !fenced || state.CommandID != command.CommandID {
		t.Fatalf("test fence was not durable: state=%+v fenced=%t err=%v", state, fenced, err)
	}
	reader := &recordingScopedStopReader{inner: stopStore}
	svc, receipts := newEvaluateRouteTestServices(t, guardian.WithScopedStopReader(reader))
	svc.EmergencyStops = stopStore
	direct, err := svc.Guardian.EvaluateDecision(context.Background(), guardian.DecisionRequest{
		Principal: "principal-trusted",
		Action:    "EXECUTE_TOOL",
		Resource:  "local.echo",
		Context:   map[string]any{"tenant_id": "tenant-trusted", "workspace_id": "workspace-fenced"},
	})
	if err != nil || direct.ReasonCode != string(contracts.ReasonEmergencyStopFenced) || reader.calls != 1 || reader.scope != command.Scope() {
		t.Fatalf("configured guardian did not enforce durable fence: decision=%+v calls=%d scope=%+v state=%+v fenced=%t reader_err=%v err=%v", direct, reader.calls, reader.scope, reader.state, reader.fenced, reader.err, err)
	}
	reader.calls = 0
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	// The body attempts to select an unfenced workspace. The handler must use
	// the independently authenticated header binding instead.
	body := []byte(`{"action":"EXECUTE_TOOL","resource":"local.echo","session_id":"fenced-session","context":{"workspace_id":"workspace-unfenced"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	req.Header.Set(workspaceHeader, "workspace-fenced")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fenced evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response api.EvaluateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Verdict != string(contracts.VerdictDeny) || response.ReasonCode != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("fenced evaluate response = %+v", response)
	}
	if reader.calls != 1 || reader.scope != command.Scope() {
		t.Fatalf("evaluate route did not use the authenticated scope: calls=%d scope=%+v", reader.calls, reader.scope)
	}
	if receipts.stored == nil || receipts.stored.ReasonCode != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("fenced evaluate must persist a denial receipt, got %+v", receipts.stored)
	}
}

func TestEvaluateRouteRefusesMissingOrMismatchedWorkspaceBindingWhenFenceEnabled(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-trusted")
	_, stopStore, _ := newEmergencyStopFenceRouteForTest(t)
	svc, receipts := newEvaluateRouteTestServices(t, guardian.WithScopedStopReader(stopStore))
	svc.EmergencyStops = stopStore
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	for _, workspace := range []string{"", "workspace-spoofed"} {
		t.Run("workspace="+workspace, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader([]byte(`{"action":"EXECUTE_TOOL","resource":"local.echo"}`)))
			req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
			req.Header.Set(tenantHeader, "tenant-trusted")
			req.Header.Set(principalHeader, "principal-trusted")
			if workspace != "" {
				req.Header.Set(workspaceHeader, workspace)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("workspace binding status = %d body=%s", rec.Code, rec.Body.String())
			}
			if receipts.stored != nil {
				t.Fatalf("rejected workspace binding must not execute or persist a receipt: %+v", receipts.stored)
			}
		})
	}
}
