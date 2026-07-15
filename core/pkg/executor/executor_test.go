package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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

type reverifyingOutbox struct {
	verifier  crypto.Verifier
	scheduled bool
}

func (o *reverifyingOutbox) Schedule(_ context.Context, _ *contracts.Effect, intent *contracts.AuthorizedExecutionIntent) error {
	valid, err := o.verifier.VerifyIntent(intent)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid intent signature")
	}
	o.scheduled = true
	return nil
}

func (o *reverifyingOutbox) GetPending(context.Context) ([]*OutboxRecord, error) {
	return nil, nil
}

func (o *reverifyingOutbox) MarkDone(context.Context, string) error {
	return nil
}

func TestValidateSafeDepIntentBindingRejectsMismatchedSignedAuthority(t *testing.T) {
	result := safedep.GateResult{
		ActivationReceipt: &contracts.ActivationReceipt{
			ActivationID:        "actual-activation",
			DelegationSessionID: "actual-session",
		},
		EmergencyScopeHash: "sha256:actual-scope",
	}
	tests := []struct {
		name   string
		intent contracts.AuthorizedExecutionIntent
	}{
		{name: "activation", intent: contracts.AuthorizedExecutionIntent{EmergencyActivationID: "signed-activation"}},
		{name: "delegation session", intent: contracts.AuthorizedExecutionIntent{EmergencyDelegationSessionID: "signed-session"}},
		{name: "scope", intent: contracts.AuthorizedExecutionIntent{EmergencyScopeHash: "sha256:signed-scope"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSafeDepIntentBinding(&tt.intent, result); err == nil {
				t.Fatal("expected signed emergency authority mismatch to fail closed")
			}
		})
	}
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
		ID:           "dec-1",
		Verdict:      string(contracts.VerdictAllow),
		EffectDigest: testEffectDigest(t, effect),
	}
	// Sign the decision so it passes signature validation
	if err := signer.SignDecision(validDec); err != nil {
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
	if err := signer.SignDecision(decision); err != nil {
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

func TestSafeExecutorPreservesSignedIntentThroughSafeDepOutboxReverification(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	outbox := &reverifyingOutbox{verifier: signer}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, outbox, "", nil, nil, nil, nil).
		WithSafeDepGate(safeDepGateFunc(func(_ context.Context, req safedep.GateRequest) (safedep.GateResult, error) {
			// Exercise the former shared-pointer bug: even a mutating gate must not
			// invalidate the verified intent later passed to the outbox.
			req.Intent.EmergencyActivationID = "mutated-act"
			req.Intent.EmergencyDelegationSessionID = "mutated-session"
			req.Intent.EmergencyScopeHash = "sha256:mutated"
			return safedep.GateResult{
				DispatchAllowed: true,
				ReasonCode:      contracts.ReasonSafeDepDegradedNarrowing,
				ActivationReceipt: &contracts.ActivationReceipt{
					ActivationID:        "act-1",
					DelegationSessionID: "session-1",
				},
				EmergencyScopeHash: "sha256:scope",
				Classification: contracts.HazardClassification{
					HazardCode: contracts.HazardCredentialExpired,
					State:      contracts.SafeDepDegradedNarrowing,
				},
			}, nil
		}))
	effect := &contracts.Effect{EffectID: "eff-safedep-allow", Params: map[string]any{"tool_name": "ls"}}
	decision := &contracts.DecisionRecord{ID: "dec-safedep-allow", Verdict: string(contracts.VerdictAllow), EffectDigest: testEffectDigest(t, effect)}
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	intent := &contracts.AuthorizedExecutionIntent{DecisionID: decision.ID, EffectDigestHash: decision.EffectDigest, ExpiresAt: time.Now().Add(time.Hour)}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
	receipt, _, err := executor.Execute(context.Background(), effect, decision, intent)
	if err != nil {
		t.Fatal(err)
	}
	if !outbox.scheduled {
		t.Fatal("outbox did not reverify and schedule the signed intent")
	}
	if intent.EmergencyActivationID != "" || intent.EmergencyDelegationSessionID != "" || intent.EmergencyScopeHash != "" {
		t.Fatalf("SafeDep gate mutated original signed intent: %+v", intent)
	}
	if valid, verifyErr := signer.VerifyIntent(intent); verifyErr != nil || !valid {
		t.Fatalf("intent failed post-gate reverification: valid=%v err=%v", valid, verifyErr)
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
		ID:           "dec-clock",
		Verdict:      string(contracts.VerdictAllow),
		EffectDigest: testEffectDigest(t, effect),
	}
	if err := signer.SignDecision(dec); err != nil {
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
	if err := signer.SignDecision(dec); err != nil {
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
