package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

type captureReceiptStore struct {
	last     *contracts.Receipt
	stored   *contracts.Receipt
	storeErr error
	agentID  string
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

func (s *captureReceiptStore) AppendCausal(ctx context.Context, agentID string, build store.CausalReceiptBuilder) error {
	s.agentID = agentID
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
		PolicyDecisionHash: "sha256:pdp",
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
	valid, err := signer.VerifyReceipt(store.stored)
	if err != nil || !valid {
		t.Fatalf("receipt signature invalid: valid=%v err=%v receipt=%+v", valid, err, store.stored)
	}
	if store.stored.Timestamp != decision.Timestamp {
		t.Fatalf("timestamp = %s, want %s", store.stored.Timestamp, decision.Timestamp)
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

func TestEvaluateRouteBindsReceiptToAuthenticatedPrincipal(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	svc, receipts := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	body := []byte(`{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"request_id":"request-1"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated evaluate status = %d body=%s", rec.Code, rec.Body.String())
	}
	if receipts.agentID != "principal-trusted" {
		t.Fatalf("causal chain agent = %q, want trusted principal", receipts.agentID)
	}
	if receipts.stored == nil {
		t.Fatal("authenticated evaluate did not persist receipt")
	}
	if receipts.stored.ExecutorID != "principal-trusted" {
		t.Fatalf("receipt executor = %q, want trusted principal", receipts.stored.ExecutorID)
	}
	var decision contracts.DecisionRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if decision.InputContext["tenant_id"] != "tenant-trusted" || decision.InputContext["principal_id"] != "principal-trusted" {
		t.Fatalf("decision context did not use trusted identity: %+v", decision.InputContext)
	}
	if decision.SubjectID != "principal-trusted" || decision.Action != "EXECUTE_TOOL" || decision.Resource != "local.echo" {
		t.Fatalf("signed decision did not bind the canonical request identity and effect: %+v", decision)
	}
	if decision.InputContext[guardian.ContextSecurityTrusted] != false ||
		decision.InputContext[guardian.ContextSourceChannel] != string(contracts.SourceChannelAPIRequest) ||
		decision.InputContext[guardian.ContextTrustLevel] != string(contracts.InputTrustExternalUntrusted) {
		t.Fatalf("decision context did not record the HTTP transport trust boundary: %+v", decision.InputContext)
	}
}

func TestEvaluateRouteRejectsAmbiguousOrCallerControlledPayloads(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")

	tests := []struct {
		name string
		body string
	}{
		{
			name: "body principal",
			body: `{"principal":"attacker","action":"EXECUTE_TOOL","resource":"local.echo"}`,
		},
		{
			name: "legacy payload",
			body: `{"tool":"local.echo","args":{},"agent_id":"attacker","effect_level":"EXECUTE_TOOL","session_id":"session-1"}`,
		},
		{
			name: "internal session history",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","session_history":[]}`,
		},
		{
			name: "caller principal context",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"principal_id":"attacker"}}`,
		},
		{
			name: "tenant scope alias",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"tenant":"tenant-attacker"}}`,
		},
		{
			name: "tenant snake case",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"tenant_id":"tenant-attacker"}}`,
		},
		{
			name: "tenant camel case",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"tenantId":"tenant-attacker"}}`,
		},
		{
			name: "workspace scope",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"workspace_id":"workspace-attacker"}}`,
		},
		{
			name: "workspace camel case",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"workspaceId":"workspace-attacker"}}`,
		},
		{
			name: "trusted security context",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"security_context_trusted":true}}`,
		},
		{
			name: "trusted credential context",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"credential_hash":"sha256:attacker"}}`,
		},
		{
			name: "trusted session context",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"session_id":"attacker-session"}}`,
		},
		{
			name: "trusted provenance context",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"source_channel":"internal"}}`,
		},
		{
			name: "trusted trust level context",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"trust_level":"trusted"}}`,
		},
		{
			name: "trusted destination context",
			body: `{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"destination":"trusted.example"}}`,
		},
		{
			name: "missing action",
			body: `{"resource":"local.echo"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, receipts := newEvaluateRouteTestServices(t)
			mux := http.NewServeMux()
			registerReceiptRoutes(mux, svc)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewBufferString(tt.body))
			req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
			req.Header.Set(tenantHeader, "tenant-trusted")
			req.Header.Set(principalHeader, "principal-trusted")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("evaluate status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if receipts.stored != nil || receipts.agentID != "" {
				t.Fatalf("rejected payload must not evaluate or persist a receipt: %+v", receipts.stored)
			}
		})
	}
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

	// Workspace scope comes only from the independently authenticated header.
	body := []byte(`{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"request_id":"fenced-request"}}`)
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
	var decision contracts.DecisionRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != string(contracts.VerdictDeny) || decision.ReasonCode != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("fenced evaluate decision = %+v", decision)
	}
	if reader.calls != 1 || reader.scope != command.Scope() {
		t.Fatalf("evaluate route did not use the authenticated scope: calls=%d scope=%+v", reader.calls, reader.scope)
	}
	if decision.InputContext["emergency_stop_command_id"] != command.CommandID || decision.InputContext["emergency_stop_scope_hash"] == "" {
		t.Fatalf("fenced evaluate missing signed stop provenance: %+v", decision.InputContext)
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
