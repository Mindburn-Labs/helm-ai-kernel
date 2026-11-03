package executor

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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
