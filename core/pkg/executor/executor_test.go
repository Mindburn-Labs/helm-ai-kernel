package executor

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
)

// MockDriver implements ToolDriver
type MockDriver struct {
	Called bool
	Calls  int
}

func (m *MockDriver) Execute(ctx context.Context, toolName string, params map[string]any) (any, error) {
	m.Called = true
	m.Calls++
	return "result", nil
}

type staticDriver struct{}

func (staticDriver) Execute(context.Context, string, map[string]any) (any, error) {
	return "result", nil
}

// testDecisionAuthority makes test-created signed decisions explicit about
// their evaluated authority tuple. Runtime callers must supply their own
// actual tuple before a V4 signature can be issued.
func testDecisionAuthority(decision *contracts.DecisionRecord) *contracts.DecisionRecord {
	if decision == nil {
		return nil
	}
	if decision.SubjectID == "" {
		decision.SubjectID = "test:executor"
	}
	if decision.Action == "" {
		decision.Action = "EXECUTE_TOOL"
	}
	if decision.Resource == "" {
		decision.Resource = "test:executor-resource"
	}
	return decision
}

// MemoryReceiptStore for tests
type MemoryReceiptStore struct {
	receipts map[string]*contracts.Receipt
}

func NewMemoryReceiptStore() *MemoryReceiptStore {
	return &MemoryReceiptStore{
		receipts: make(map[string]*contracts.Receipt),
	}
}

func (s *MemoryReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	for _, r := range s.receipts {
		if r.DecisionID == decisionID {
			return r, nil
		}
	}
	return nil, nil // Not found
}

func (s *MemoryReceiptStore) Store(ctx context.Context, r *contracts.Receipt) error {
	s.receipts[r.ReceiptID] = r
	return nil
}

func (s *MemoryReceiptStore) GetLastForSession(ctx context.Context, sessionID string) (*contracts.Receipt, error) {
	var last *contracts.Receipt
	for _, receipt := range s.receipts {
		if receipt.SessionID != sessionID {
			continue
		}
		if last == nil || receipt.LamportClock > last.LamportClock {
			last = receipt
		}
	}
	return last, nil
}

type recordingOutboxStore struct {
	scheduleCalls int
	markDoneCalls int
}

func (s *recordingOutboxStore) Schedule(context.Context, *contracts.Effect, *contracts.AuthorizedExecutionIntent) error {
	s.scheduleCalls++
	return nil
}

func (s *recordingOutboxStore) GetPending(context.Context) ([]*OutboxRecord, error) {
	return nil, nil
}

func (s *recordingOutboxStore) MarkDone(context.Context, string) error {
	s.markDoneCalls++
	return nil
}

type tenantScopedReceiptStore struct {
	*MemoryReceiptStore
	tenantID             string
	sessionID            string
	appendCalls          int
	preflightCalls       int
	preflightErr         error
	legacyGetCalls       int
	idempotencyTenantIDs []string
	tenantReceipts       map[string]map[string]*contracts.Receipt
}

func (s *tenantScopedReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	s.legacyGetCalls++
	return s.MemoryReceiptStore.Get(ctx, decisionID)
}

func (s *tenantScopedReceiptStore) GetByDecisionIDForTenant(_ context.Context, tenantID, decisionID string) (*contracts.Receipt, error) {
	s.idempotencyTenantIDs = append(s.idempotencyTenantIDs, tenantID)
	return s.tenantReceipts[tenantID][decisionID], nil
}

func (s *tenantScopedReceiptStore) PreflightCausalAppendScoped(_ context.Context, tenantID, sessionID string) error {
	s.tenantID = tenantID
	s.sessionID = sessionID
	s.preflightCalls++
	return s.preflightErr
}

func (s *tenantScopedReceiptStore) AppendCausalScoped(ctx context.Context, tenantID, sessionID string, build func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error)) error {
	s.tenantID = tenantID
	s.sessionID = sessionID
	s.appendCalls++
	receipt, err := build(nil, 1, "")
	if err != nil {
		return err
	}
	if s.tenantReceipts == nil {
		s.tenantReceipts = make(map[string]map[string]*contracts.Receipt)
	}
	if s.tenantReceipts[tenantID] == nil {
		s.tenantReceipts[tenantID] = make(map[string]*contracts.Receipt)
	}
	s.tenantReceipts[tenantID][receipt.DecisionID] = receipt
	return s.Store(ctx, receipt)
}

// collisionCheckingTenantReceiptStore models the receipt_id primary key that
// durable stores enforce, rather than allowing a test map to overwrite it.
type collisionCheckingTenantReceiptStore struct {
	*tenantScopedReceiptStore
	persistCalls int
}

func (s *collisionCheckingTenantReceiptStore) AppendCausalScoped(ctx context.Context, tenantID, sessionID string, build func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error)) error {
	s.tenantID = tenantID
	s.sessionID = sessionID
	receipt, err := build(nil, 1, "")
	if err != nil {
		return err
	}
	if s.receipts[receipt.ReceiptID] != nil {
		return errors.New("global receipt id collision")
	}
	if s.tenantReceipts == nil {
		s.tenantReceipts = make(map[string]map[string]*contracts.Receipt)
	}
	if s.tenantReceipts[tenantID] == nil {
		s.tenantReceipts[tenantID] = make(map[string]*contracts.Receipt)
	}
	s.tenantReceipts[tenantID][receipt.DecisionID] = receipt
	s.persistCalls++
	return s.MemoryReceiptStore.Store(ctx, receipt)
}

// causalReceiptStore models the optional atomic append capability provided by
// the durable receipt stores. Its legacy read barrier makes the old
// GetLastForSession + Store sequence deterministically allocate the same
// position to two concurrent executions.
type causalReceiptStore struct {
	mu               sync.Mutex
	receipts         map[string]*contracts.Receipt
	appendCalls      int
	directStoreCalls int
	legacyReadCount  int
	legacyReadsReady chan struct{}
}

func newCausalReceiptStore() *causalReceiptStore {
	return &causalReceiptStore{
		receipts:         make(map[string]*contracts.Receipt),
		legacyReadsReady: make(chan struct{}),
	}
}

func (s *causalReceiptStore) Get(_ context.Context, decisionID string) (*contracts.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, receipt := range s.receipts {
		if receipt.DecisionID == decisionID {
			return receipt, nil
		}
	}
	return nil, nil
}

func (s *causalReceiptStore) Store(_ context.Context, receipt *contracts.Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.directStoreCalls++
	s.receipts[receipt.ReceiptID] = receipt
	return nil
}

func (s *causalReceiptStore) GetLastForSession(ctx context.Context, _ string) (*contracts.Receipt, error) {
	s.mu.Lock()
	s.legacyReadCount++
	if s.legacyReadCount == 2 {
		close(s.legacyReadsReady)
	}
	s.mu.Unlock()

	select {
	case <-s.legacyReadsReady:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *causalReceiptStore) AppendCausal(ctx context.Context, sessionID string, build func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var previous *contracts.Receipt
	for _, receipt := range s.receipts {
		if receipt.SessionID == sessionID && (previous == nil || receipt.LamportClock > previous.LamportClock) {
			previous = receipt
		}
	}
	lamport := uint64(1)
	prevHash := ""
	if previous != nil {
		lamport = previous.LamportClock + 1
		var err error
		prevHash, err = contracts.ReceiptChainHash(previous)
		if err != nil {
			return err
		}
	}
	receipt, err := build(previous, lamport, prevHash)
	if err != nil {
		return err
	}
	if receipt == nil {
		return context.Canceled
	}
	s.appendCalls++
	s.receipts[receipt.ReceiptID] = receipt
	return nil
}

func (s *causalReceiptStore) PreflightCausalAppend(context.Context, string) error {
	return nil
}

type safeDepGateFunc func(context.Context, safedep.GateRequest) (safedep.GateResult, error)

func (f safeDepGateFunc) Gate(ctx context.Context, req safedep.GateRequest) (safedep.GateResult, error) {
	return f(ctx, req)
}

func testEffectDigest(t *testing.T, effect *contracts.Effect) string {
	t.Helper()
	effectBytes, err := canonicalize.JCS(testEffectDigestEnvelopeFrom(effect))
	if err != nil {
		t.Fatalf("canonicalize effect: %v", err)
	}
	return canonicalize.HashBytes(effectBytes)
}

type testEffectDigestEnvelope struct {
	EffectType     string                    `json:"effect_type"`
	Params         map[string]any            `json:"params,omitempty"`
	IdempotencyKey string                    `json:"idempotency_key,omitempty"`
	Irreversible   bool                      `json:"irreversible,omitempty"`
	ArgsHash       string                    `json:"args_hash,omitempty"`
	OutputHash     string                    `json:"output_hash,omitempty"`
	Taint          []string                  `json:"taint,omitempty"`
	Compensation   *testEffectDigestEnvelope `json:"compensation,omitempty"`
}

func testEffectDigestEnvelopeFrom(effect *contracts.Effect) *testEffectDigestEnvelope {
	if effect == nil {
		return nil
	}
	return &testEffectDigestEnvelope{
		EffectType:     effect.EffectType,
		Params:         effect.Params,
		IdempotencyKey: effect.IdempotencyKey,
		Irreversible:   effect.Irreversible,
		ArgsHash:       effect.ArgsHash,
		OutputHash:     effect.OutputHash,
		Taint:          contracts.NormalizeTaintLabels(effect.Taint),
		Compensation:   testEffectDigestEnvelopeFrom(effect.Compensation),
	}
}

func TestSafeExecutor_Gating(t *testing.T) {
	// Setup
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil)

	effect := &contracts.Effect{
		EffectID: "eff-1",
		Params:   map[string]any{"tool_name": "ls"},
	}

	// 1. Valid Decision -> Execute
	validDec := &contracts.DecisionRecord{
		ID:                "dec-1",
		Verdict:           string(contracts.VerdictAllow),
		ReasonCode:        "ALLOW_BY_POLICY",
		PolicyContentHash: "sha256:policy-content",
		InputContext:      map[string]any{"session_id": "session-executor"},
		EffectDigest:      testEffectDigest(t, effect),
	}
	// Sign the decision so it passes signature validation
	if err := signer.SignDecision(testDecisionAuthority(validDec)); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}

	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:       "dec-1",
		EffectDigestHash: validDec.EffectDigest,
		ExpiresAt:        time.Now().Add(1 * time.Hour), // Set expiry in the future
	}
	// Sign the intent as well
	if err := signer.SignIntent(intent); err != nil {
		t.Fatalf("Failed to sign intent: %v", err)
	}

	receipt, artifact, err := executor.Execute(context.Background(), effect, validDec, intent)
	if err != nil {
		t.Fatalf("Valid execute failed: %v", err)
	}
	if !mockDriver.Called {
		t.Error("Driver not called")
	}
	if artifact == nil {
		t.Error("Artifact should not be nil")
	} else {
		if artifact.ContentType != "text/plain" {
			t.Errorf("Expected text/plain content type, got %s", artifact.ContentType)
		}
	}
	if receipt.OutputHash != artifact.Digest {
		t.Errorf("Receipt OutputHash %s does not match Artifact Digest %s", receipt.OutputHash, artifact.Digest)
	}
	if receipt.SignatureVersion != contracts.ReceiptSignatureV5 || receipt.Verdict != validDec.Verdict || receipt.ReasonCode != validDec.ReasonCode || receipt.PolicyHash != validDec.PolicyContentHash || receipt.SessionID != "session-executor" {
		t.Fatalf("receipt did not bind decision governance fields: %+v", receipt)
	}
	if valid, err := signer.VerifyReceipt(receipt); err != nil || !valid {
		t.Fatalf("V5 receipt signature invalid after issuance: valid=%v err=%v", valid, err)
	}

	// 2. Intent Mismatch -> Block
	// Create fresh executor to avoid idempotency cache hit from first test
	executor2 := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil)
	mockDriver.Called = false
	mismatchIntent := &contracts.AuthorizedExecutionIntent{DecisionID: "dec-other"}

	if _, _, err := executor2.Execute(context.Background(), effect, validDec, mismatchIntent); err == nil {
		t.Error("Executor allowed mismatch intent")
	}
	if mockDriver.Called {
		t.Error("Driver called despite mismatch")
	}
}

func TestSafeExecutorRejectsLegacyDecisionAuthorityAfterVerification(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("legacy-authority")
	if err != nil {
		t.Fatal(err)
	}
	driver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, driver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil)
	effect := &contracts.Effect{
		EffectID:   "effect-legacy-authority",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "github.create_issue"},
	}
	legacy := &contracts.DecisionRecord{
		ID:               "decision-legacy-authority",
		Verdict:          string(contracts.VerdictAllow),
		Reason:           "historical allow",
		EffectDigest:     testEffectDigest(t, effect),
		SignatureVersion: contracts.DecisionRecordSignatureV2,
		SignatureType:    crypto.SigPrefixEd25519 + crypto.SigSeparator + "legacy-authority",
	}
	payload, err := crypto.CanonicalizeDecisionV2(legacy.ID, legacy.Verdict, legacy.Reason, legacy.ReasonCode, legacy.PhenotypeHash, legacy.PolicyContentHash, legacy.EffectDigest)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Signature, err = signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := signer.VerifyDecision(legacy); err != nil || !valid {
		t.Fatalf("legacy decision no longer verifies: valid=%t err=%v", valid, err)
	}

	intent := &contracts.AuthorizedExecutionIntent{
		ID:               "intent-legacy-authority",
		DecisionID:       legacy.ID,
		EffectDigestHash: legacy.EffectDigest,
		ExpiresAt:        time.Now().Add(time.Hour),
		AllowedTool:      "github.create_issue",
	}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}

	if _, _, err := executor.Execute(context.Background(), effect, legacy, intent); err == nil || !strings.Contains(err.Error(), contracts.DecisionRecordSignatureV4) {
		t.Fatalf("legacy decision crossed execution boundary: %v", err)
	}
	if driver.Called {
		t.Fatal("legacy decision dispatched an effect")
	}
}

func TestSafeExecutorScopesTenantFromAuthenticatedContext(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("tenant-scope-key")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1700000000, 0).UTC()
	driver := &MockDriver{}
	store := &tenantScopedReceiptStore{MemoryReceiptStore: NewMemoryReceiptStore()}
	outbox := &recordingOutboxStore{}
	executor := NewSafeExecutor(signer, signer, driver, store, nil, outbox, "", nil, nil, nil, func() time.Time { return clock })
	effect := &contracts.Effect{
		EffectID:   "effect-tenant-scope",
		EffectType: "EXECUTE_TOOL",
		ArgsHash:   "sha256:tenant-scope",
		Params:     map[string]any{"tool_name": "ls"},
	}
	decision := &contracts.DecisionRecord{
		ID:                "decision-tenant-scope",
		Verdict:           string(contracts.VerdictAllow),
		ReasonCode:        "ALLOW_BY_POLICY",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      testEffectDigest(t, effect),
		InputContext: map[string]any{
			"session_id": "tenant-scope-session",
			"tenant_id":  "tenant-before-mutation",
		},
	}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
		t.Fatal(err)
	}
	// InputContext falls outside the decision signature, so this mutation must
	// not be able to redirect the durable tenant scope.
	decision.InputContext["tenant_id"] = "tenant-after-mutation"
	if valid, err := signer.VerifyDecision(decision); err != nil || !valid {
		t.Fatalf("InputContext mutation unexpectedly changed decision verification: valid=%v err=%v", valid, err)
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

	if _, _, err := executor.Execute(context.Background(), effect, decision, intent); err == nil || !strings.Contains(err.Error(), "authenticated tenant required") {
		t.Fatalf("tenant-scoped store accepted an unbound tenant: %v", err)
	}
	if driver.Called || store.appendCalls != 0 || store.preflightCalls != 0 {
		t.Fatalf("tenant-scoped store dispatched before authenticated tenant binding: driver=%v appends=%d preflights=%d", driver.Called, store.appendCalls, store.preflightCalls)
	}

	ctx := helmauth.WithPrincipal(context.Background(), &helmauth.BasePrincipal{ID: "operator-a", TenantID: "tenant-authorized"})
	receipt, _, err := executor.Execute(ctx, effect, decision, intent)
	if err != nil {
		t.Fatalf("execute with authenticated tenant: %v", err)
	}
	if store.tenantID != "tenant-authorized" || store.sessionID != "tenant-scope-session" {
		t.Fatalf("durable scope = tenant=%q session=%q, want authenticated tenant and requested session", store.tenantID, store.sessionID)
	}
	if valid, err := signer.VerifyReceipt(receipt); err != nil || !valid {
		t.Fatalf("receipt signature invalid after authenticated tenant scope: valid=%v err=%v", valid, err)
	}
	if store.preflightCalls != 1 {
		t.Fatalf("expected one causal preflight, got %d", store.preflightCalls)
	}

	store.preflightErr = errors.New("predecessor has no persisted chain hash")
	driver.Called = false
	appendsBefore := store.appendCalls
	schedulesBefore := outbox.scheduleCalls
	blockedDecision := &contracts.DecisionRecord{
		ID:                "decision-legacy-chain",
		Verdict:           string(contracts.VerdictAllow),
		ReasonCode:        "ALLOW_BY_POLICY",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      testEffectDigest(t, effect),
		InputContext:      map[string]any{"session_id": "tenant-scope-session"},
	}
	if err := signer.SignDecision(testDecisionAuthority(blockedDecision)); err != nil {
		t.Fatal(err)
	}
	blockedIntent := &contracts.AuthorizedExecutionIntent{
		DecisionID:       blockedDecision.ID,
		EffectDigestHash: blockedDecision.EffectDigest,
		AllowedTool:      "ls",
		ExpiresAt:        clock.Add(time.Hour),
	}
	if err := signer.SignIntent(blockedIntent); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executor.Execute(ctx, effect, blockedDecision, blockedIntent); err == nil || !strings.Contains(err.Error(), "causal append preflight failed") {
		t.Fatalf("expected causal append preflight denial, got %v", err)
	}
	if driver.Called || store.appendCalls != appendsBefore || outbox.scheduleCalls != schedulesBefore {
		t.Fatalf("preflight failure dispatched, scheduled, or appended: driver=%v schedules=%d appends=%d", driver.Called, outbox.scheduleCalls, store.appendCalls)
	}
}

func TestSafeExecutorScopesIdempotencyToAuthenticatedTenant(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("tenant-idempotency-key")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1700000000, 0).UTC()
	decisionID := "decision-tenant-idempotency"
	cachedReceipt := &contracts.Receipt{
		ReceiptID:  "rcpt-tenant-a",
		DecisionID: decisionID,
		OutputHash: "sha256:tenant-a-output",
	}
	store := &tenantScopedReceiptStore{
		MemoryReceiptStore: NewMemoryReceiptStore(),
		preflightErr:       errors.New("tenant-b append preflight"),
		tenantReceipts: map[string]map[string]*contracts.Receipt{
			"tenant-a": {decisionID: cachedReceipt},
		},
	}
	store.receipts[cachedReceipt.ReceiptID] = cachedReceipt // A global lookup would leak this receipt to tenant-b.
	driver := &MockDriver{}
	outbox := &recordingOutboxStore{}
	executor := NewSafeExecutor(signer, signer, driver, store, nil, outbox, "", nil, nil, nil, func() time.Time { return clock })
	effect := &contracts.Effect{
		EffectID:   "effect-tenant-idempotency",
		EffectType: "EXECUTE_TOOL",
		ArgsHash:   "sha256:tenant-idempotency",
		Params:     map[string]any{"tool_name": "ls"},
	}
	decision := &contracts.DecisionRecord{
		ID:                decisionID,
		Verdict:           string(contracts.VerdictAllow),
		ReasonCode:        "ALLOW_BY_POLICY",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      testEffectDigest(t, effect),
		InputContext:      map[string]any{"session_id": "tenant-idempotency-session"},
	}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
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

	tenantA := helmauth.WithPrincipal(context.Background(), &helmauth.BasePrincipal{ID: "operator-a", TenantID: "tenant-a"})
	got, artifact, err := executor.Execute(tenantA, effect, decision, intent)
	if err != nil {
		t.Fatalf("tenant-a idempotency hit: %v", err)
	}
	if got != cachedReceipt || artifact == nil || driver.Called || outbox.scheduleCalls != 0 || store.preflightCalls != 0 {
		t.Fatalf("tenant-a cache hit mutated execution state: receipt=%p artifact=%v driver=%v schedules=%d preflights=%d", got, artifact != nil, driver.Called, outbox.scheduleCalls, store.preflightCalls)
	}

	tenantB := helmauth.WithPrincipal(context.Background(), &helmauth.BasePrincipal{ID: "operator-b", TenantID: "tenant-b"})
	got, artifact, err = executor.Execute(tenantB, effect, decision, intent)
	if err == nil || !strings.Contains(err.Error(), "tenant-b append preflight") {
		t.Fatalf("tenant-b must not receive tenant-a receipt; got receipt=%+v artifact=%+v err=%v", got, artifact, err)
	}
	if driver.Called || outbox.scheduleCalls != 0 || store.legacyGetCalls != 0 {
		t.Fatalf("cross-tenant idempotency lookup dispatched, scheduled, or used global receipt lookup: driver=%v schedules=%d legacy_gets=%d", driver.Called, outbox.scheduleCalls, store.legacyGetCalls)
	}
	if got := strings.Join(store.idempotencyTenantIDs, ","); got != "tenant-a,tenant-b" {
		t.Fatalf("idempotency tenant scopes = %q, want tenant-a,tenant-b", got)
	}
}

func TestSafeExecutorTenantQualifiedReceiptIdentityAvoidsCollisionAndRetriesIdempotently(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("tenant-receipt-id-key")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1700000000, 0).UTC()
	store := &collisionCheckingTenantReceiptStore{tenantScopedReceiptStore: &tenantScopedReceiptStore{MemoryReceiptStore: NewMemoryReceiptStore()}}
	driver := &MockDriver{}
	outbox := &recordingOutboxStore{}
	executor := NewSafeExecutor(signer, signer, driver, store, nil, outbox, "", nil, nil, nil, func() time.Time { return clock })
	effect := &contracts.Effect{
		EffectID:   "effect-shared-decision",
		EffectType: "EXECUTE_TOOL",
		ArgsHash:   "sha256:shared-decision",
		Params:     map[string]any{"tool_name": "ls"},
	}
	decision := &contracts.DecisionRecord{
		ID:                "decision-shared-across-tenants",
		Verdict:           string(contracts.VerdictAllow),
		ReasonCode:        "ALLOW_BY_POLICY",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      testEffectDigest(t, effect),
		InputContext:      map[string]any{"session_id": "shared-session"},
	}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
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
	execute := func(tenantID string) *contracts.Receipt {
		t.Helper()
		ctx := helmauth.WithPrincipal(context.Background(), &helmauth.BasePrincipal{ID: "operator-" + tenantID, TenantID: tenantID})
		receipt, _, err := executor.Execute(ctx, effect, decision, intent)
		if err != nil {
			t.Fatalf("execute for %s: %v", tenantID, err)
		}
		return receipt
	}

	tenantA := execute("tenant-a")
	tenantB := execute("tenant-b")
	if tenantA.ReceiptID == tenantB.ReceiptID || len(store.receipts) != 2 {
		t.Fatalf("tenant-scoped receipts collided: a=%q b=%q stored=%d", tenantA.ReceiptID, tenantB.ReceiptID, len(store.receipts))
	}
	if driver.Calls != 2 || store.persistCalls != 2 || outbox.scheduleCalls != 2 {
		t.Fatalf("distinct tenant executions = driver:%d persist:%d schedule:%d, want 2 each", driver.Calls, store.persistCalls, outbox.scheduleCalls)
	}

	retry := execute("tenant-b")
	if retry != tenantB || driver.Calls != 2 || store.persistCalls != 2 || outbox.scheduleCalls != 2 {
		t.Fatalf("tenant-b retry dispatched or persisted: receipt=%p want=%p driver=%d persist=%d schedule=%d", retry, tenantB, driver.Calls, store.persistCalls, outbox.scheduleCalls)
	}
}

func TestSafeExecutorRejectsAuthenticatedUnscopedCausalStoreBeforeDispatch(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("unscoped-causal-store-key")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1700000000, 0).UTC()
	driver := &MockDriver{}
	store := newCausalReceiptStore()
	executor := NewSafeExecutor(signer, signer, driver, store, nil, nil, "", nil, nil, nil, func() time.Time { return clock })
	effect := &contracts.Effect{
		EffectID:   "effect-unscoped-causal-store",
		EffectType: "EXECUTE_TOOL",
		ArgsHash:   "sha256:unscoped-causal-store",
		Params:     map[string]any{"tool_name": "ls"},
	}
	decision := &contracts.DecisionRecord{
		ID:                "decision-unscoped-causal-store",
		Verdict:           string(contracts.VerdictAllow),
		ReasonCode:        "ALLOW_BY_POLICY",
		PolicyContentHash: "sha256:policy",
		EffectDigest:      testEffectDigest(t, effect),
		InputContext:      map[string]any{"session_id": "unscoped-causal-session"},
	}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
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
	ctx := helmauth.WithPrincipal(context.Background(), &helmauth.BasePrincipal{ID: "operator-a", TenantID: "tenant-authorized"})
	if _, _, err := executor.Execute(ctx, effect, decision, intent); err == nil || !strings.Contains(err.Error(), "lacks tenant-scoped idempotency lookup") {
		t.Fatalf("expected unscoped causal store denial, got %v", err)
	}
	if driver.Called || store.appendCalls != 0 {
		t.Fatalf("unscoped causal store dispatched or appended: driver=%v appends=%d", driver.Called, store.appendCalls)
	}
}

func TestSafeExecutorChainsReceiptsBySignedSessionID(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("receipt-chain-key")
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryReceiptStore()
	executor := NewSafeExecutor(signer, signer, &MockDriver{}, store, nil, nil, "", nil, nil, nil, func() time.Time {
		return time.Unix(1700000000, 0).UTC()
	})
	const sessionID = "signed-session"

	execute := func(decisionID, effectID, argsHash string) *contracts.Receipt {
		t.Helper()
		effect := &contracts.Effect{
			EffectID:   effectID,
			EffectType: "EXECUTE_TOOL",
			ArgsHash:   argsHash,
			Params:     map[string]any{"tool_name": "ls"},
		}
		decision := &contracts.DecisionRecord{
			ID:                decisionID,
			Verdict:           string(contracts.VerdictAllow),
			ReasonCode:        "ALLOW_BY_POLICY",
			PolicyContentHash: "sha256:policy",
			InputContext:      map[string]any{"session_id": sessionID},
			EffectDigest:      testEffectDigest(t, effect),
		}
		if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
			t.Fatalf("sign decision %s: %v", decisionID, err)
		}
		intent := &contracts.AuthorizedExecutionIntent{
			DecisionID:       decisionID,
			EffectDigestHash: decision.EffectDigest,
			AllowedTool:      "ls",
			ExpiresAt:        time.Unix(1700003600, 0).UTC(),
		}
		if err := signer.SignIntent(intent); err != nil {
			t.Fatalf("sign intent %s: %v", decisionID, err)
		}
		receipt, _, err := executor.Execute(context.Background(), effect, decision, intent)
		if err != nil {
			t.Fatalf("execute %s: %v", decisionID, err)
		}
		return receipt
	}

	first := execute("decision-1", "effect-1", "sha256:args-1")
	second := execute("decision-2", "effect-2", "sha256:args-2")

	if first.ExecutorID != "" || second.ExecutorID != "" {
		t.Fatalf("SafeExecutor must chain on signed session_id, not an executor fallback: first=%+v second=%+v", first, second)
	}
	if first.SessionID != sessionID || second.SessionID != sessionID {
		t.Fatalf("receipts did not preserve signed session_id: first=%q second=%q", first.SessionID, second.SessionID)
	}
	if first.PrevHash != "" {
		t.Fatalf("genesis prev_hash = %q, want empty", first.PrevHash)
	}
	firstHash, err := contracts.ReceiptChainHash(first)
	if err != nil {
		t.Fatalf("hash first receipt: %v", err)
	}
	if first.LamportClock != 1 || second.LamportClock != 2 || second.PrevHash != firstHash {
		t.Fatalf("session chain = first(lamport=%d) second(lamport=%d prev=%q), want 1, 2, %q", first.LamportClock, second.LamportClock, second.PrevHash, firstHash)
	}
	for _, receipt := range []*contracts.Receipt{first, second} {
		if valid, verifyErr := signer.VerifyReceipt(receipt); verifyErr != nil || !valid {
			t.Fatalf("signed session-chain receipt did not verify: valid=%v err=%v receipt=%+v", valid, verifyErr, receipt)
		}
	}
}

func TestSafeExecutorAllocatesConcurrentReceiptChainsAtomically(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("atomic-receipt-chain-key")
	if err != nil {
		t.Fatal(err)
	}
	store := newCausalReceiptStore()
	executor := NewSafeExecutor(signer, signer, staticDriver{}, store, nil, nil, "", nil, nil, nil, time.Now)
	const sessionID = "atomic-session"

	type executionInput struct {
		effect   *contracts.Effect
		decision *contracts.DecisionRecord
		intent   *contracts.AuthorizedExecutionIntent
	}
	inputs := make([]executionInput, 0, 2)
	for _, id := range []string{"one", "two"} {
		effect := &contracts.Effect{
			EffectID:   "effect-" + id,
			EffectType: "EXECUTE_TOOL",
			ArgsHash:   "sha256:args-" + id,
			Params:     map[string]any{"tool_name": "ls", "effect": id},
		}
		decision := &contracts.DecisionRecord{
			ID:                "decision-" + id,
			Verdict:           string(contracts.VerdictAllow),
			ReasonCode:        "ALLOW_BY_POLICY",
			PolicyContentHash: "sha256:policy",
			InputContext:      map[string]any{"session_id": sessionID},
			EffectDigest:      testEffectDigest(t, effect),
		}
		if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
			t.Fatalf("sign decision %s: %v", id, err)
		}
		intent := &contracts.AuthorizedExecutionIntent{
			DecisionID:       decision.ID,
			EffectDigestHash: decision.EffectDigest,
			AllowedTool:      "ls",
			ExpiresAt:        time.Now().Add(time.Hour),
		}
		if err := signer.SignIntent(intent); err != nil {
			t.Fatalf("sign intent %s: %v", id, err)
		}
		inputs = append(inputs, executionInput{effect: effect, decision: decision, intent: intent})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan *contracts.Receipt, len(inputs))
	errs := make(chan error, len(inputs))
	var wg sync.WaitGroup
	for _, input := range inputs {
		input := input
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			receipt, _, err := executor.Execute(ctx, input.effect, input.decision, input.intent)
			if err != nil {
				errs <- err
				return
			}
			results <- receipt
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent execution failed: %v", err)
	}

	if store.appendCalls != len(inputs) || store.directStoreCalls != 0 || store.legacyReadCount != 0 {
		t.Fatalf("receipt allocation bypassed AppendCausal: append=%d direct_store=%d legacy_reads=%d", store.appendCalls, store.directStoreCalls, store.legacyReadCount)
	}
	receipts := make([]*contracts.Receipt, 0, len(inputs))
	for receipt := range results {
		receipts = append(receipts, receipt)
	}
	if len(receipts) != len(inputs) {
		t.Fatalf("got %d receipts, want %d", len(receipts), len(inputs))
	}
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].LamportClock < receipts[j].LamportClock })
	if receipts[0].LamportClock != 1 || receipts[0].PrevHash != "" || receipts[1].LamportClock != 2 {
		t.Fatalf("unexpected atomic chain positions: first=%+v second=%+v", receipts[0], receipts[1])
	}
	firstHash, err := contracts.ReceiptChainHash(receipts[0])
	if err != nil {
		t.Fatal(err)
	}
	if receipts[1].PrevHash != firstHash {
		t.Fatalf("second receipt prev_hash = %q, want %q", receipts[1].PrevHash, firstHash)
	}
	for _, receipt := range receipts {
		if receipt.SignatureVersion != contracts.ReceiptSignatureV5 {
			t.Fatalf("atomic receipt signature version = %q, want %q", receipt.SignatureVersion, contracts.ReceiptSignatureV5)
		}
		if valid, verifyErr := signer.VerifyReceipt(receipt); verifyErr != nil || !valid {
			t.Fatalf("receipt signature invalid after atomic append: valid=%v err=%v receipt=%+v", valid, verifyErr, receipt)
		}
	}
}

func TestSafeExecutorRejectsRuntimeEffectDigestMismatch(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil)

	approvedEffect := &contracts.Effect{
		EffectID:   "eff-approved",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "deploy", "target": "staging"},
	}
	decision := &contracts.DecisionRecord{
		ID:           "dec-approved",
		Verdict:      string(contracts.VerdictAllow),
		EffectDigest: testEffectDigest(t, approvedEffect),
	}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:       decision.ID,
		EffectDigestHash: decision.EffectDigest,
		ExpiresAt:        time.Now().Add(time.Hour),
		AllowedTool:      "deploy",
	}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}

	substitutedEffect := &contracts.Effect{
		EffectID:   "eff-substituted",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "deploy", "target": "production"},
	}
	_, _, err := executor.Execute(context.Background(), substitutedEffect, decision, intent)
	if err == nil {
		t.Fatal("expected runtime effect digest mismatch")
	}
	if mockDriver.Called {
		t.Fatal("driver dispatched after runtime effect digest mismatch")
	}
}

func TestSafeExecutorSafeDepGateBlocksBeforeOutboxAndDispatch(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil).
		WithSafeDepGate(safeDepGateFunc(func(context.Context, safedep.GateRequest) (safedep.GateResult, error) {
			return safedep.GateResult{
				DispatchAllowed: false,
				ReasonCode:      contracts.ReasonSafeDepTerminalFreeze,
				Classification: contracts.HazardClassification{
					HazardCode: contracts.HazardDeadManExpired,
					State:      contracts.SafeDepTerminalFreeze,
				},
			}, nil
		}))
	decision := &contracts.DecisionRecord{ID: "dec-safedep-block", Verdict: string(contracts.VerdictAllow)}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{DecisionID: decision.ID, ExpiresAt: time.Now().Add(time.Hour)}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
	effect := &contracts.Effect{EffectID: "eff-safedep-block", Params: map[string]any{"tool_name": "ls"}}
	if _, _, err := executor.Execute(context.Background(), effect, decision, intent); err == nil {
		t.Fatal("expected SafeDep gate denial")
	}
	if mockDriver.Called {
		t.Fatal("driver dispatched before SafeDep gate allowed execution")
	}
}

func TestSafeExecutorSafeDepGateRequired(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil).
		WithSafeDepGate(nil)
	decision := &contracts.DecisionRecord{
		ID:      "dec-safedep-gate-required",
		Verdict: string(contracts.VerdictAllow),
	}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{DecisionID: decision.ID, ExpiresAt: time.Now().Add(time.Hour)}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
	effect := &contracts.Effect{EffectID: "eff-safedep-gate-required", Params: map[string]any{"tool_name": "ls"}}
	if _, _, err := executor.Execute(context.Background(), effect, decision, intent); err == nil {
		t.Fatal("expected missing SafeDep gate to fail closed")
	}
	if mockDriver.Called {
		t.Fatal("driver dispatched without SafeDep gate")
	}
}

func TestSafeExecutorBindsVerifiedEmergencyAuthorityToReceipt(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	var gateIntent *contracts.AuthorizedExecutionIntent
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil).
		WithSafeDepGate(safeDepGateFunc(func(_ context.Context, req safedep.GateRequest) (safedep.GateResult, error) {
			gateIntent = req.Intent
			// A gate implementation cannot alter the verified snapshot retained by
			// the executor, even if it attempts to rewrite its own copy.
			req.Intent.EmergencyActivationID = "act-attacker"
			req.Intent.EmergencyDelegationSessionID = "session-attacker"
			req.Intent.EmergencyScopeHash = "sha256:attacker"
			return safedep.GateResult{
				DispatchAllowed:    true,
				ReasonCode:         contracts.ReasonSafeDepDegradedNarrowing,
				EmergencyScopeHash: "sha256:scope",
				ActivationReceipt: &contracts.ActivationReceipt{
					ActivationID:        "act-1",
					DelegationSessionID: "session-1",
				},
				Classification: contracts.HazardClassification{
					HazardCode: contracts.HazardCredentialExpired,
					State:      contracts.SafeDepDegradedNarrowing,
				},
			}, nil
		}))
	effect := &contracts.Effect{EffectID: "eff-safedep-allow", Params: map[string]any{"tool_name": "ls"}}
	decision := &contracts.DecisionRecord{ID: "dec-safedep-allow", Verdict: string(contracts.VerdictAllow), EffectDigest: testEffectDigest(t, effect)}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:                   decision.ID,
		EffectDigestHash:             decision.EffectDigest,
		ExpiresAt:                    time.Now().Add(time.Hour),
		EmergencyActivationID:        "act-1",
		EmergencyDelegationSessionID: "session-1",
		EmergencyScopeHash:           "sha256:scope",
	}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
	receipt, _, err := executor.Execute(context.Background(), effect, decision, intent)
	if err != nil {
		t.Fatal(err)
	}
	if gateIntent == intent {
		t.Fatal("SafeDep gate received the executor's verified intent pointer")
	}
	if valid, verifyErr := signer.VerifyIntent(intent); verifyErr != nil || !valid {
		t.Fatalf("SafeDep changed the signed intent: valid=%v err=%v", valid, verifyErr)
	}
	if receipt.EmergencyActivationID != "act-1" || receipt.EmergencyDelegationSessionID != "session-1" || receipt.EmergencyScopeHash != "sha256:scope" {
		t.Fatalf("receipt missing emergency authority fields: %+v", receipt)
	}
	if receipt.SafeDepState != string(contracts.SafeDepDegradedNarrowing) || receipt.SafeDepReasonCode != string(contracts.ReasonSafeDepDegradedNarrowing) {
		t.Fatalf("receipt missing SafeDep state: %+v", receipt)
	}
}

func TestSafeExecutorRejectsSafeDepActivationBindingMismatch(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	outbox := &recordingOutboxStore{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, outbox, "", nil, nil, nil, nil).
		WithSafeDepGate(safeDepGateFunc(func(_ context.Context, req safedep.GateRequest) (safedep.GateResult, error) {
			req.Intent.EmergencyActivationID = "act-attacker"
			req.Intent.EmergencyDelegationSessionID = "session-attacker"
			req.Intent.EmergencyScopeHash = "sha256:attacker"
			return safedep.GateResult{
				DispatchAllowed:    true,
				ReasonCode:         contracts.ReasonSafeDepDegradedNarrowing,
				EmergencyScopeHash: "sha256:attacker",
				ActivationReceipt: &contracts.ActivationReceipt{
					ActivationID:        "act-attacker",
					DelegationSessionID: "session-attacker",
				},
				Classification: contracts.HazardClassification{
					HazardCode: contracts.HazardCredentialExpired,
					State:      contracts.SafeDepDegradedNarrowing,
				},
			}, nil
		}))
	effect := &contracts.Effect{EffectID: "eff-safedep-mismatch", Params: map[string]any{"tool_name": "ls"}}
	decision := &contracts.DecisionRecord{ID: "dec-safedep-mismatch", Verdict: string(contracts.VerdictAllow), EffectDigest: testEffectDigest(t, effect)}
	if err := signer.SignDecision(testDecisionAuthority(decision)); err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:                   decision.ID,
		EffectDigestHash:             decision.EffectDigest,
		ExpiresAt:                    time.Now().Add(time.Hour),
		EmergencyActivationID:        "act-signed",
		EmergencyDelegationSessionID: "session-signed",
		EmergencyScopeHash:           "sha256:signed",
	}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}

	if _, _, err := executor.Execute(context.Background(), effect, decision, intent); err == nil || !strings.Contains(err.Error(), "safe dep activation") {
		t.Fatalf("expected SafeDep binding mismatch denial, got %v", err)
	}
	if mockDriver.Called || outbox.scheduleCalls != 0 {
		t.Fatalf("SafeDep mismatch crossed an execution boundary: driver=%v outbox=%d", mockDriver.Called, outbox.scheduleCalls)
	}
	if intent.EmergencyActivationID != "act-signed" || intent.EmergencyDelegationSessionID != "session-signed" || intent.EmergencyScopeHash != "sha256:signed" {
		t.Fatalf("SafeDep mutated original signed intent: %+v", intent)
	}
	if valid, verifyErr := signer.VerifyIntent(intent); verifyErr != nil || !valid {
		t.Fatalf("original intent no longer verifies: valid=%v err=%v", valid, verifyErr)
	}
}

func TestSafeExecutor_WithClock(t *testing.T) {
	// Verify that WithClock injects a deterministic clock
	fixedTime := time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC)
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil).
		WithClock(func() time.Time { return fixedTime })

	effect := &contracts.Effect{
		EffectID: "eff-clock",
		Params:   map[string]any{"tool_name": "ls"},
	}
	dec := &contracts.DecisionRecord{
		ID:           "dec-clock",
		Verdict:      string(contracts.VerdictAllow),
		EffectDigest: testEffectDigest(t, effect),
	}
	if err := signer.SignDecision(testDecisionAuthority(dec)); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:       "dec-clock",
		EffectDigestHash: dec.EffectDigest,
		ExpiresAt:        fixedTime.Add(1 * time.Hour),
	}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatalf("Failed to sign intent: %v", err)
	}

	receipt, _, err := executor.Execute(context.Background(), effect, dec, intent)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if !receipt.Timestamp.Equal(fixedTime) {
		t.Errorf("Receipt timestamp %v != injected clock %v", receipt.Timestamp, fixedTime)
	}
}

func TestSafeExecutor_ExpiredIntent(t *testing.T) {
	// Use a clock that returns a time AFTER the intent's expiry
	futureTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil).
		WithClock(func() time.Time { return futureTime })

	effect := &contracts.Effect{
		EffectID: "eff-expired",
		Params:   map[string]any{"tool_name": "ls"},
	}
	dec := &contracts.DecisionRecord{
		ID:           "dec-expired",
		Verdict:      string(contracts.VerdictAllow),
		EffectDigest: testEffectDigest(t, effect),
	}
	if err := signer.SignDecision(testDecisionAuthority(dec)); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID:       "dec-expired",
		EffectDigestHash: dec.EffectDigest,
		ExpiresAt:        time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), // Expired relative to futureTime
	}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatalf("Failed to sign intent: %v", err)
	}

	_, _, err := executor.Execute(context.Background(), effect, dec, intent)
	if err == nil {
		t.Fatal("Expected error for expired intent, got nil")
	}
	if !mockDriver.Called {
		// Good — driver should NOT have been called
	} else {
		t.Error("Driver was called despite expired intent")
	}
}
