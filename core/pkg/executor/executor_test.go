package executor

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
)

// MockDriver implements ToolDriver
type MockDriver struct {
	Called bool
}

func (m *MockDriver) Execute(ctx context.Context, toolName string, params map[string]any) (any, error) {
	m.Called = true
	return "result", nil
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
	return nil, nil // Test mock: no causal chain
}

type safeDepGateFunc func(context.Context, safedep.GateRequest) (safedep.GateResult, error)

func (f safeDepGateFunc) Gate(ctx context.Context, req safedep.GateRequest) (safedep.GateResult, error) {
	return f(ctx, req)
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
		ID:      "dec-1",
		Verdict: string(contracts.VerdictAllow),
	}
	// Sign the decision so it passes signature validation
	if err := signer.SignDecision(validDec); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}

	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID: "dec-1",
		ExpiresAt:  time.Now().Add(1 * time.Hour), // Set expiry in the future
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
	if err := signer.SignDecision(decision); err != nil {
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
	if err := signer.SignDecision(decision); err != nil {
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

func TestSafeExecutorCopiesEmergencyAuthorityToReceipt(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil).
		WithSafeDepGate(safeDepGateFunc(func(_ context.Context, req safedep.GateRequest) (safedep.GateResult, error) {
			req.Intent.EmergencyActivationID = "act-1"
			req.Intent.EmergencyDelegationSessionID = "session-1"
			req.Intent.EmergencyScopeHash = "sha256:scope"
			return safedep.GateResult{
				DispatchAllowed: true,
				ReasonCode:      contracts.ReasonSafeDepDegradedNarrowing,
				Classification: contracts.HazardClassification{
					HazardCode: contracts.HazardCredentialExpired,
					State:      contracts.SafeDepDegradedNarrowing,
				},
			}, nil
		}))
	decision := &contracts.DecisionRecord{ID: "dec-safedep-allow", Verdict: string(contracts.VerdictAllow)}
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{DecisionID: decision.ID, ExpiresAt: time.Now().Add(time.Hour)}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
	effect := &contracts.Effect{EffectID: "eff-safedep-allow", Params: map[string]any{"tool_name": "ls"}}
	receipt, _, err := executor.Execute(context.Background(), effect, decision, intent)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.EmergencyActivationID != "act-1" || receipt.EmergencyDelegationSessionID != "session-1" || receipt.EmergencyScopeHash != "sha256:scope" {
		t.Fatalf("receipt missing emergency authority fields: %+v", receipt)
	}
	if receipt.SafeDepState != string(contracts.SafeDepDegradedNarrowing) || receipt.SafeDepReasonCode != string(contracts.ReasonSafeDepDegradedNarrowing) {
		t.Fatalf("receipt missing SafeDep state: %+v", receipt)
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
		ID:      "dec-clock",
		Verdict: string(contracts.VerdictAllow),
	}
	if err := signer.SignDecision(dec); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID: "dec-clock",
		ExpiresAt:  fixedTime.Add(1 * time.Hour),
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
		ID:      "dec-expired",
		Verdict: string(contracts.VerdictAllow),
	}
	if err := signer.SignDecision(dec); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		DecisionID: "dec-expired",
		ExpiresAt:  time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), // Expired relative to futureTime
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
