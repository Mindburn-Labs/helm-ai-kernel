package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/agentruntime"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
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

type evaluateRouteCapturingPDP struct {
	request *pdp.DecisionRequest
}

func (p *evaluateRouteCapturingPDP) Evaluate(_ context.Context, req *pdp.DecisionRequest) (*pdp.DecisionResponse, error) {
	p.request = req
	return &pdp.DecisionResponse{Allow: true, PolicyRef: "evaluate-route-test", DecisionHash: "sha256:decision"}, nil
}

func (*evaluateRouteCapturingPDP) Backend() pdp.Backend { return pdp.BackendHELM }
func (*evaluateRouteCapturingPDP) PolicyHash() string   { return "sha256:policy" }

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

func TestPersistDecisionReceiptWritesPortableEvidencePack(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test")
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	store := &captureReceiptStore{}
	svc := &Services{DataDir: dataDir, ReceiptStore: store, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{
		ID:                 "dec-portable",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictDeny),
		ReasonCode:         string(contracts.ReasonEmergencyStopFenced),
		PolicyContentHash:  "sha256:policy-content",
		PolicyDecisionHash: "sha256:pdp",
		InputContext:       map[string]any{"session_id": "session-portable"},
		Timestamp:          time.Unix(1700000000, 0).UTC(),
	}

	if err := persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "api.evaluate"}); err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if store.stored == nil {
		t.Fatal("receipt was not stored")
	}
	receiptFile := portableEvaluateReceiptPath(dataDir, store.stored.ReceiptID)
	receiptRaw, err := os.ReadFile(receiptFile)
	if err != nil {
		t.Fatalf("portable receipt.v5 JSON missing: %v", err)
	}
	var fromFile contracts.Receipt
	if err := json.Unmarshal(receiptRaw, &fromFile); err != nil {
		t.Fatalf("decode portable receipt JSON: %v", err)
	}
	if fromFile.SignatureVersion != contracts.ReceiptSignatureV5 || fromFile.Verdict != string(contracts.VerdictDeny) {
		t.Fatalf("portable receipt JSON = %+v", fromFile)
	}
	path := portableEvaluateEvidencePackPath(dataDir, store.stored.ReceiptID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("portable evidence pack missing: %v", err)
	}
	offBox := filepath.Join(t.TempDir(), "evidence-pack.tar")
	if err := os.WriteFile(offBox, raw, 0o600); err != nil {
		t.Fatalf("copy portable evidence pack off-box: %v", err)
	}
	receiptName := "02_PROOFGRAPH/receipts/" + sanitizeReceiptFileName(store.stored.ReceiptID) + ".json"
	copiedRaw, err := readTarEntry(offBox, receiptName)
	if err != nil {
		t.Fatalf("read receipt from copied pack: %v", err)
	}
	var copied contracts.Receipt
	if err := json.Unmarshal(copiedRaw, &copied); err != nil {
		t.Fatalf("decode packed receipt: %v", err)
	}
	if copied.SignatureVersion != contracts.ReceiptSignatureV5 || copied.ReceiptID != store.stored.ReceiptID {
		t.Fatalf("packed receipt = %+v", copied)
	}
	if copied.Verdict != string(contracts.VerdictDeny) {
		t.Fatalf("hop pack verdict = %q, want DENY / no permit", copied.Verdict)
	}
	if copied.Metadata != nil {
		if _, ok := copied.Metadata["effect_permit_ref"]; ok {
			t.Fatal("DENY evaluate receipt carried permit material")
		}
	}
	valid, err := signer.VerifyReceipt(&copied)
	if err != nil || !valid {
		t.Fatalf("copied packed receipt signature invalid: valid=%v err=%v", valid, err)
	}
	scoreRaw, err := readTarEntry(offBox, "01_SCORE.json")
	if err != nil {
		t.Fatalf("read pack score: %v", err)
	}
	if !strings.Contains(string(scoreRaw), `"label": "DENY / no permit"`) {
		t.Fatalf("pack score missing DENY / no permit label: %s", scoreRaw)
	}
	if strings.Contains(strings.ToLower(string(scoreRaw)), "sent") || strings.Contains(string(scoreRaw), "ALLOW") {
		t.Fatalf("pack score looks like sent/ALLOW mail: %s", scoreRaw)
	}
	pubRaw, err := os.ReadFile(portableEvaluatePublicKeyPath(dataDir, store.stored.ReceiptID))
	if err != nil {
		t.Fatalf("portable public key missing: %v", err)
	}
	if strings.TrimSpace(string(pubRaw)) != signer.PublicKey() {
		t.Fatalf("portable public key = %q, want %q", strings.TrimSpace(string(pubRaw)), signer.PublicKey())
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

func TestEvaluateRouteStripsCallerSuppliedEgressSecurityContext(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv("HELM_TAINT_TRACKING", "1")
	t.Setenv(runtimeTenantIDEnv, defaultRuntimeTenantID)
	t.Setenv(runtimePrincipalIDEnv, "principal-external")
	svc, _ := newEvaluateRouteTestServices(t, guardian.WithEgressChecker(firewall.NewEgressChecker(nil)))
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	body := []byte(`{"action":"EXECUTE_TOOL","resource":"local.echo","context":{"session_id":"session-external","security_context_trusted":true,"allow_tainted_egress":true,"destination":"https://external.example/upload","egress_destination_required":true,"taint":["credential"]}}`)
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
	if decision.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("caller-supplied egress context changed local tool evaluation: %+v", decision)
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

	body := []byte(`{"tool":" EXECUTE_TOOL ","action":"EXECUTE_TOOL","effect_level":" local.echo ","resource":"local.echo","args":{"message":"hello"},"agent_id":"attacker","session_id":" canonical-session ","context":{"session_id":"canonical-session","tenant_id":"tenant-attacker"}}`)
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
		t.Fatalf("matching session aliases must be trimmed: receipt=%q", receipts.stored.SessionID)
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

func TestEvaluateRouteRejectsConflictingAliasesBeforeReceiptIssuance(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	for name, body := range map[string]string{
		"tool and action":             `{"tool":"EXECUTE_TOOL","action":"READ_FILE","effect_level":"local.echo","session_id":"session-tool"}`,
		"effect level and resource":   `{"tool":"EXECUTE_TOOL","effect_level":"local.echo","resource":"remote.http","session_id":"session-effect"}`,
		"session and context session": `{"tool":"EXECUTE_TOOL","effect_level":"local.echo","session_id":"session-current","context":{"session_id":"session-legacy"}}`,
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
				t.Fatalf("conflicting aliases status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if receipts.stored != nil {
				t.Fatalf("conflicting aliases persisted receipt: %+v", receipts.stored)
			}
		})
	}
}

func TestEvaluateRouteRebindsAuthorityContextBeforeGuardian(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")

	for _, tc := range []struct {
		name          string
		workspace     string
		wantWorkspace bool
	}{
		{name: "without authenticated workspace"},
		{name: "with authenticated workspace", workspace: "workspace-trusted", wantWorkspace: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capturing := &evaluateRouteCapturingPDP{}
			svc, receipts := newEvaluateRouteTestServices(t, guardian.WithPDP(capturing))
			mux := http.NewServeMux()
			registerReceiptRoutes(mux, svc)

			body := []byte(`{"tool":"EXECUTE_TOOL","effect_level":"local.echo","session_id":"authority-session","context":{"principal":"principal-attacker","principal_id":"principal-attacker","agent_id":"principal-attacker","tenant":"tenant-attacker","tenantId":"tenant-attacker","tenant_id":"tenant-attacker","workspace":"workspace-attacker","workspaceId":"workspace-attacker","workspace_id":"workspace-attacker","security_context_trusted":true,"credential_hash":"forged-hash","destination":"attacker.example","egress_destination_required":true,"effect_class":"E0","custom":"preserved"}}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
			req.Header.Set(tenantHeader, "tenant-trusted")
			req.Header.Set(principalHeader, "principal-trusted")
			if tc.workspace != "" {
				req.Header.Set(workspaceHeader, tc.workspace)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("evaluate status = %d body=%s", rec.Code, rec.Body.String())
			}
			if receipts.stored == nil {
				t.Fatal("evaluate did not persist a receipt")
			}
			if capturing.request == nil {
				t.Fatal("Guardian PDP did not receive the evaluate request")
			}
			if capturing.request.Principal != "principal-trusted" {
				t.Fatalf("Guardian principal = %q", capturing.request.Principal)
			}
			if got := capturing.request.Context["principal_id"]; got != "principal-trusted" {
				t.Fatalf("Guardian principal_id = %#v", got)
			}
			if got := capturing.request.Context["tenant_id"]; got != "tenant-trusted" {
				t.Fatalf("Guardian tenant_id = %#v", got)
			}
			if got := capturing.request.Context["custom"]; got != "preserved" {
				t.Fatalf("non-authority context changed: %#v", got)
			}
			expectedContext := helmauth.WithAuthenticatedCredential(context.Background(), testAdminAPIKey)
			expectedHash, ok := helmauth.AuthenticatedCredentialHash(expectedContext)
			if !ok || capturing.request.Context[guardian.ContextCredentialHash] != expectedHash {
				t.Fatalf("Guardian credential hash = %#v, want middleware digest", capturing.request.Context[guardian.ContextCredentialHash])
			}
			if capturing.request.Context[guardian.ContextSecurityTrusted] != true {
				t.Fatalf("Guardian security marker = %#v", capturing.request.Context[guardian.ContextSecurityTrusted])
			}
			if got := capturing.request.Context[guardian.ContextEffectClass]; got != "local.echo" {
				t.Fatalf("Guardian effect class = %#v, want adapter-bound local.echo", got)
			}
			if _, exists := capturing.request.Context[guardian.ContextDestination]; exists {
				t.Fatalf("caller destination reached Guardian: %#v", capturing.request.Context[guardian.ContextDestination])
			}
			if _, exists := capturing.request.Context[guardian.ContextEgressDestinationRequired]; exists {
				t.Fatalf("caller egress requirement reached Guardian: %#v", capturing.request.Context[guardian.ContextEgressDestinationRequired])
			}
			for _, key := range []string{"principal", "agent_id", "tenant", "tenantId", "workspace", "workspaceId"} {
				if value, exists := capturing.request.Context[key]; exists {
					t.Fatalf("caller authority alias %q reached Guardian: %#v", key, value)
				}
			}
			workspace, exists := capturing.request.Context["workspace_id"]
			if tc.wantWorkspace {
				if !exists || workspace != tc.workspace {
					t.Fatalf("Guardian workspace_id = %#v, exists=%t", workspace, exists)
				}
			} else if exists {
				t.Fatalf("caller workspace_id reached Guardian without an authenticated header: %#v", workspace)
			}
		})
	}
}

func TestEvaluateRouteRejectsMemoryWithoutWorkspaceAndNestedContextSpoof(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	t.Setenv(runtimeWorkspaceIDEnv, "")

	for _, tc := range []struct {
		name     string
		envelope bool
	}{
		{name: "without reserved envelope"},
		{name: "with empty reserved envelope", envelope: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capturing := &evaluateRouteCapturingPDP{}
			svc, receipts := newEvaluateRouteTestServices(t, guardian.WithPDP(capturing))
			mux := http.NewServeMux()
			registerReceiptRoutes(mux, svc)

			request := api.EvaluateRequest{
				Tool:        "memory.read",
				EffectLevel: "E1",
				SessionID:   "memory-workspace-spoof-session",
				Args: map[string]any{
					"budget": map[string]any{"decision": "ALLOW"},
				},
				Context: map[string]any{
					"zzz": map[string]any{"workspace_id": "workspace-spoofed"},
				},
			}
			if tc.envelope {
				request.Args[evaluateAuthorityArgsKey] = map[string]any{
					"tenant_id":    "tenant-trusted",
					"workspace_id": "",
					"principal_id": "principal-trusted",
					"session_id":   request.SessionID,
					"tool":         request.Tool,
					"effect_level": request.EffectLevel,
				}
			}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
			req.Header.Set(tenantHeader, "tenant-trusted")
			req.Header.Set(principalHeader, "principal-trusted")
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("evaluate status = %d, want 403: %s", recorder.Code, recorder.Body.String())
			}
			if capturing.request != nil {
				t.Fatalf("rejected request reached Guardian: %+v", capturing.request)
			}
			if receipts.stored != nil {
				t.Fatalf("rejected request persisted a receipt: %+v", receipts.stored)
			}
		})
	}
}

func TestEvaluateRouteRejectsNestedMemoryAuthorityContextSpoofWithWorkspace(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")

	capturing := &evaluateRouteCapturingPDP{}
	svc, receipts := newEvaluateRouteTestServices(t, guardian.WithPDP(capturing))
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)
	request := api.EvaluateRequest{
		Tool:        "memory.read",
		EffectLevel: "E1",
		SessionID:   "memory-nested-context-spoof-session",
		Args:        map[string]any{"budget": map[string]any{"decision": "ALLOW"}},
		Context: map[string]any{
			"zzz": map[string]any{"workspace_id": "workspace-spoofed"},
		},
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	req.Header.Set(workspaceHeader, "workspace-trusted")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("evaluate status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	if capturing.request != nil {
		t.Fatalf("rejected request reached Guardian: %+v", capturing.request)
	}
	if receipts.stored != nil {
		t.Fatalf("rejected request persisted a receipt: %+v", receipts.stored)
	}
}

func TestEvaluateAuthorityBindingRequiresWorkspaceAndKeepsProfileCompatibility(t *testing.T) {
	expected := evaluateAuthorityBinding{
		TenantID:    "tenant-trusted",
		PrincipalID: "principal-trusted",
		WorkspaceID: "workspace-trusted",
		SessionID:   "authority-session",
		Tool:        "record",
		EffectLevel: "E1",
	}
	base := map[string]any{
		"tenant_id":    expected.TenantID,
		"workspace_id": expected.WorkspaceID,
		"principal_id": expected.PrincipalID,
		"session_id":   expected.SessionID,
		"tool":         expected.Tool,
		"effect_level": expected.EffectLevel,
	}
	if err := validateEvaluateAuthorityBinding(base, expected); err != nil {
		t.Fatalf("six-field authority binding rejected: %v", err)
	}
	withProfile := make(map[string]any, len(base)+1)
	for key, value := range base {
		withProfile[key] = value
	}
	withProfile["execution_profile"] = "organization-runtime"
	if err := validateEvaluateAuthorityBinding(withProfile, expected); err != nil {
		t.Fatalf("organization-runtime authority binding rejected: %v", err)
	}

	missingWorkspace := evaluateAuthorityBinding{
		TenantID:    expected.TenantID,
		PrincipalID: expected.PrincipalID,
		SessionID:   expected.SessionID,
		Tool:        expected.Tool,
		EffectLevel: expected.EffectLevel,
	}
	if err := validateEvaluateAuthorityBinding(base, missingWorkspace); err == nil {
		t.Fatal("authority binding with an unauthenticated workspace was accepted")
	}
	memoryProfile := make(map[string]any, len(base)+1)
	for key, value := range base {
		memoryProfile[key] = value
	}
	memoryProfile["tool"] = "memory.read"
	memoryProfile["execution_profile"] = "organization-runtime"
	memoryExpected := expected
	memoryExpected.Tool = "memory.read"
	if err := validateEvaluateAuthorityBinding(memoryProfile, memoryExpected); err == nil {
		t.Fatal("organization-runtime profile was accepted for a memory authority binding")
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

func TestReceiptRoutesRequireConfiguredWorkspaceWhenScopedFenceEnabled(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, defaultRuntimeTenantID)
	t.Setenv(runtimePrincipalIDEnv, "system-admin")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-trusted")
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	_, stopStore, _ := newEmergencyStopFenceRouteForTest(t)
	svc.EmergencyStops = stopStore
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	for _, target := range []string{
		"/api/v1/receipts",
		"/api/v1/receipts/rcpt-test",
		"/api/v1/receipts/tail",
	} {
		for _, workspaceID := range []string{"", "workspace-foreign"} {
			t.Run(target+"/workspace="+workspaceID, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, target, nil)
				authorizeTestRequest(req)
				if workspaceID != "" {
					req.Header.Set(workspaceHeader, workspaceID)
				}
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("receipt workspace status = %d body=%s", rec.Code, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), "rcpt-test") {
					t.Fatalf("rejected workspace leaked receipt: %s", rec.Body.String())
				}
			})
		}
	}

	for _, target := range []string{"/api/v1/receipts", "/api/v1/receipts/rcpt-test"} {
		t.Run(target+"/workspace=workspace-trusted", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			authorizeTestRequest(req)
			req.Header.Set(workspaceHeader, "workspace-trusted")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("configured receipt workspace status = %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func receiptListIDs(t *testing.T, result map[string]any) []string {
	t.Helper()
	raw, ok := result["receipts"].([]any)
	if !ok {
		return nil
	}
	ids := make([]string, 0, len(raw))
	for _, item := range raw {
		obj, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("receipt entry is not an object: %T", item)
		}
		if id, ok := obj["receipt_id"].(string); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func TestReceiptListQueryFilters(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	receiptStore := svc.ReceiptStore.(*store.SQLiteReceiptStore)
	appendTenantScopedReceipt(t, receiptStore, defaultRuntimeTenantID, "session-allow", &contracts.Receipt{
		ReceiptID:    "rcpt-allow",
		DecisionID:   "dec-allow",
		EffectID:     "READ_FILE",
		Status:       string(contracts.VerdictAllow),
		Verdict:      string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.filtered",
		DecisionHash: "sha256:allow-decision",
		ArgsHash:     "args-allow",
	})
	appendTenantScopedReceipt(t, receiptStore, defaultRuntimeTenantID, "session-deny", &contracts.Receipt{
		ReceiptID:    "rcpt-deny",
		DecisionID:   "dec-deny",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictDeny),
		Verdict:      string(contracts.VerdictDeny),
		ReasonCode:   "policy.blocked",
		Timestamp:    time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.filtered",
		DecisionHash: "sha256:deny-decision",
		ArgsHash:     "args-deny",
	})
	appendTenantScopedReceipt(t, receiptStore, defaultRuntimeTenantID, "session-boundary", &contracts.Receipt{
		ReceiptID:    "rcpt-to-boundary",
		DecisionID:   "dec-to-boundary",
		EffectID:     "READ_FILE",
		Status:       string(contracts.VerdictEscalate),
		Verdict:      string(contracts.VerdictEscalate),
		Timestamp:    time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.filtered",
		DecisionHash: "sha256:boundary-decision",
		ArgsHash:     "args-boundary",
	})
	nanosecondBound := time.Date(2026, 5, 9, 0, 0, 0, 123456789, time.UTC)
	appendTenantScopedReceipt(t, receiptStore, defaultRuntimeTenantID, "session-nano-at", &contracts.Receipt{
		ReceiptID:    "rcpt-nano-at",
		DecisionID:   "dec-nano-at",
		EffectID:     "READ_FILE",
		Status:       string(contracts.VerdictEscalate),
		Verdict:      string(contracts.VerdictEscalate),
		Timestamp:    nanosecondBound,
		ExecutorID:   "agent.nanosecond",
		DecisionHash: "sha256:nano-at-decision",
		ArgsHash:     "args-nano-at",
	})
	appendTenantScopedReceipt(t, receiptStore, defaultRuntimeTenantID, "session-nano-next", &contracts.Receipt{
		ReceiptID:    "rcpt-nano-next",
		DecisionID:   "dec-nano-next",
		EffectID:     "READ_FILE",
		Status:       string(contracts.VerdictEscalate),
		Verdict:      string(contracts.VerdictEscalate),
		Timestamp:    nanosecondBound.Add(time.Nanosecond),
		ExecutorID:   "agent.nanosecond",
		DecisionHash: "sha256:nano-next-decision",
		ArgsHash:     "args-nano-next",
	})
	appendTenantScopedReceipt(t, receiptStore, "tenant-foreign", "session-deny", &contracts.Receipt{
		ReceiptID:    "rcpt-foreign",
		DecisionID:   "dec-foreign",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictDeny),
		Verdict:      string(contracts.VerdictDeny),
		ReasonCode:   "policy.blocked",
		Timestamp:    time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.filtered",
		DecisionHash: "sha256:foreign-decision",
		ArgsHash:     "args-foreign",
	})

	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	deny := receiptListIDs(t, requestReceiptList(t, mux, "/api/v1/receipts?verdict=DENY"))
	if len(deny) != 1 || deny[0] != "rcpt-deny" {
		t.Fatalf("verdict=DENY returned %v, want [rcpt-deny]", deny)
	}
	allow := receiptListIDs(t, requestReceiptList(t, mux, "/api/v1/receipts?verdict=ALLOW&reason_code="))
	if len(allow) != 1 || allow[0] != "rcpt-allow" {
		t.Fatalf("verdict=ALLOW returned %v, want [rcpt-allow]", allow)
	}
	denyReason := receiptListIDs(t, requestReceiptList(t, mux, "/api/v1/receipts?verdict=DENY&reason_code=policy.blocked"))
	if len(denyReason) != 1 || denyReason[0] != "rcpt-deny" {
		t.Fatalf("verdict=DENY&reason_code=policy.blocked returned %v, want [rcpt-deny]", denyReason)
	}

	for _, tc := range []struct {
		name  string
		query string
		want  []string
	}{
		{"principal overrides executor alias", "principal=agent.filtered&executor=other", []string{"rcpt-allow", "rcpt-deny", "rcpt-to-boundary"}},
		{"executor alias", "executor=agent.filtered", []string{"rcpt-allow", "rcpt-deny", "rcpt-to-boundary"}},
		{"effect overrides resource alias", "principal=agent.filtered&effect=READ_FILE&resource=EXECUTE_TOOL", []string{"rcpt-allow", "rcpt-to-boundary"}},
		{"resource alias", "principal=agent.filtered&resource=READ_FILE", []string{"rcpt-allow", "rcpt-to-boundary"}},
		{"all dimensions compose in one request", "verdict=DENY&reason_code=policy.blocked&principal=agent.filtered&resource=EXECUTE_TOOL&from=2026-05-07T00:00:00Z&to=2026-05-08T00:00:00Z", []string{"rcpt-deny"}},
		{"half-open time bounds", "principal=agent.filtered&from=2026-05-06T00:00:00Z&to=2026-05-08T00:00:00Z", []string{"rcpt-allow", "rcpt-deny"}},
		{"nanosecond half-open time bounds", "principal=agent.nanosecond&from=2026-05-09T00:00:00.123456789Z&to=2026-05-09T00:00:00.123456790Z", []string{"rcpt-nano-at"}},
		{"timezone offset represents the same nanosecond bounds", "principal=agent.nanosecond&from=2026-05-09T02:00:00.123456789%2B02:00&to=2026-05-09T02:00:00.123456790%2B02:00", []string{"rcpt-nano-at"}},
		{"session filter remains tenant scoped", "session_id=session-deny&executor=agent.filtered&resource=EXECUTE_TOOL", []string{"rcpt-deny"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := receiptListIDs(t, requestReceiptList(t, mux, "/api/v1/receipts?"+tc.query))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("query %q returned %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestReceiptListQueryFiltersPreserveOpaquePagination(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	receiptStore := svc.ReceiptStore.(*store.SQLiteReceiptStore)
	base := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	for _, receipt := range []*contracts.Receipt{
		{
			ReceiptID:    "rcpt-filter-page-1",
			DecisionID:   "dec-filter-page-1",
			EffectID:     "EXECUTE_TOOL",
			Status:       string(contracts.VerdictDeny),
			Verdict:      string(contracts.VerdictDeny),
			ReasonCode:   "policy.blocked",
			Timestamp:    base,
			ExecutorID:   "agent.pagination",
			DecisionHash: "sha256:filter-page-1",
			ArgsHash:     "args-filter-page-1",
		},
		{
			ReceiptID:    "rcpt-filter-page-decoy",
			DecisionID:   "dec-filter-page-decoy",
			EffectID:     "EXECUTE_TOOL",
			Status:       string(contracts.VerdictAllow),
			Verdict:      string(contracts.VerdictAllow),
			Timestamp:    base.Add(time.Second),
			ExecutorID:   "agent.pagination",
			DecisionHash: "sha256:filter-page-decoy",
			ArgsHash:     "args-filter-page-decoy",
		},
		{
			ReceiptID:    "rcpt-filter-page-2",
			DecisionID:   "dec-filter-page-2",
			EffectID:     "EXECUTE_TOOL",
			Status:       string(contracts.VerdictDeny),
			Verdict:      string(contracts.VerdictDeny),
			ReasonCode:   "policy.blocked",
			Timestamp:    base.Add(2 * time.Second),
			ExecutorID:   "agent.pagination",
			DecisionHash: "sha256:filter-page-2",
			ArgsHash:     "args-filter-page-2",
		},
	} {
		appendTenantScopedReceipt(t, receiptStore, defaultRuntimeTenantID, "session-"+receipt.ReceiptID, receipt)
	}

	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)
	filter := "verdict=DENY&reason_code=policy.blocked&principal=agent.pagination&effect=EXECUTE_TOOL"
	firstPage := requestReceiptList(t, mux, "/api/v1/receipts?"+filter+"&limit=1")
	firstCursor, _ := firstPage["next_cursor"].(string)
	if ids := receiptListIDs(t, firstPage); !reflect.DeepEqual(ids, []string{"rcpt-filter-page-1"}) || firstPage["has_more"] != true || !strings.HasPrefix(firstCursor, tenantReceiptCursorVersionPrefix) {
		t.Fatalf("first filtered page = ids %v cursor %q has_more %v", ids, firstCursor, firstPage["has_more"])
	}
	secondPage := requestReceiptList(t, mux, "/api/v1/receipts?"+filter+"&since="+url.QueryEscape(firstCursor)+"&limit=1")
	if ids := receiptListIDs(t, secondPage); !reflect.DeepEqual(ids, []string{"rcpt-filter-page-2"}) || secondPage["has_more"] != false {
		t.Fatalf("second filtered page = ids %v has_more %v", ids, secondPage["has_more"])
	}
}

func TestReceiptListRejectsInvalidTimeFilter(t *testing.T) {
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	for _, tc := range []struct {
		name string
		from string
	}{
		{"malformed", "not-a-timestamp"},
		{"comma fractional separator", "2026-05-09T00:00:00,1Z"},
		{"more than nine fractional digits", "2026-05-09T00:00:00.1234567890Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts?from="+tc.from, nil)
			authorizeTestRequest(req)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("invalid from filter status = %d body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "RFC3339Nano with at most 9 fractional digits") {
				t.Fatalf("invalid from filter body = %s", rec.Body.String())
			}
		})
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

func readTarEntry(packPath, name string) ([]byte, error) {
	file, err := os.Open(packPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	tr := tar.NewReader(file)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("tar entry %s not found", name)
		}
		if err != nil {
			return nil, err
		}
		if filepath.ToSlash(hdr.Name) == name {
			return io.ReadAll(tr)
		}
	}
}
