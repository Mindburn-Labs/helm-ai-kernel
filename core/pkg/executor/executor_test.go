package executor

import (
	"context"
	"fmt"
	"strings"
	"sync"
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

type blockingDriver struct {
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (d *blockingDriver) Execute(context.Context, string, map[string]any) (any, error) {
	d.mu.Lock()
	d.calls++
	if d.calls == 1 {
		close(d.entered)
	}
	d.mu.Unlock()
	<-d.release
	return "result", nil
}

func (d *blockingDriver) Calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// MemoryReceiptStore for tests
type MemoryReceiptStore struct {
	mu            sync.Mutex
	receipts      map[string]*contracts.Receipt
	lastBySession map[string]*contracts.Receipt
}

func NewMemoryReceiptStore() *MemoryReceiptStore {
	return &MemoryReceiptStore{
		receipts:      make(map[string]*contracts.Receipt),
		lastBySession: make(map[string]*contracts.Receipt),
	}
}

func (s *MemoryReceiptStore) Get(ctx context.Context, decisionID string) (*contracts.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.receipts {
		if r.DecisionID == decisionID {
			return r, nil
		}
	}
	return nil, nil // Not found
}

func (s *MemoryReceiptStore) GetByReceiptID(ctx context.Context, receiptID string) (*contracts.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receipts[receiptID], nil
}

func (s *MemoryReceiptStore) Store(ctx context.Context, r *contracts.Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts[r.ReceiptID] = r
	if r.SessionID != "" && (s.lastBySession[r.SessionID] == nil || r.LamportClock >= s.lastBySession[r.SessionID].LamportClock) {
		s.lastBySession[r.SessionID] = r
	}
	return nil
}

func (s *MemoryReceiptStore) AppendCausal(_ context.Context, sessionID string, build func(*contracts.Receipt, uint64, string) (*contracts.Receipt, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sessionID == "" {
		return fmt.Errorf("session id is required")
	}
	previous := s.lastBySession[sessionID]
	lamport := uint64(1)
	prevHash := ""
	if previous != nil {
		var err error
		prevHash, err = contracts.ReceiptChainHash(previous)
		if err != nil {
			return err
		}
		lamport = previous.LamportClock + 1
	}
	receipt, err := build(previous, lamport, prevHash)
	if err != nil {
		return err
	}
	if receipt == nil || receipt.SessionID != sessionID || receipt.ExecutorID == "" || receipt.LamportClock != lamport || receipt.PrevHash != prevHash {
		return fmt.Errorf("invalid causal receipt returned by test store")
	}
	if _, exists := s.receipts[receipt.ReceiptID]; exists {
		return fmt.Errorf("receipt %q already exists", receipt.ReceiptID)
	}
	s.receipts[receipt.ReceiptID] = receipt
	s.lastBySession[sessionID] = receipt
	return nil
}

type memoryOutboxStore struct {
	mu     sync.Mutex
	states map[string]OutboxClaimState
}

func newMemoryOutboxStore() *memoryOutboxStore {
	return &memoryOutboxStore{states: map[string]OutboxClaimState{}}
}

func (s *memoryOutboxStore) Claim(_ context.Context, _ *contracts.Effect, intent *contracts.AuthorizedExecutionIntent) (OutboxClaimResult, error) {
	if intent == nil || intent.ID == "" {
		return OutboxClaimResult{}, fmt.Errorf("intent id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.states[intent.ID] {
	case "":
		s.states[intent.ID] = OutboxClaimed
		return OutboxClaimResult{State: OutboxClaimed}, nil
	case OutboxClaimed:
		return OutboxClaimResult{State: OutboxInProgress}, nil
	case OutboxCompleted:
		return OutboxClaimResult{State: OutboxCompleted}, nil
	default:
		return OutboxClaimResult{State: OutboxInProgress}, nil
	}
}

func (s *memoryOutboxStore) GetPending(context.Context) ([]*OutboxRecord, error) {
	return nil, nil
}

func (s *memoryOutboxStore) MarkDone(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[id] != OutboxClaimed {
		return fmt.Errorf("outbox %q not claimed", id)
	}
	s.states[id] = OutboxCompleted
	return nil
}

type safeDepGateFunc func(context.Context, safedep.GateRequest) (safedep.GateResult, error)

func (f safeDepGateFunc) Gate(ctx context.Context, req safedep.GateRequest) (safedep.GateResult, error) {
	return f(ctx, req)
}

func noHazardSafeDepResolver(context.Context, safedep.AuthorityRequest) (safedep.GateRequest, error) {
	return safedep.GateRequest{}, nil
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

func executableTestDecision(id, effectDigest string) *contracts.DecisionRecord {
	return &contracts.DecisionRecord{
		ID:           id,
		SessionID:    "session-" + id,
		SubjectID:    "principal:executor-test",
		Action:       "EXECUTE_TOOL",
		Resource:     "tool:executor-test",
		Verdict:      string(contracts.VerdictAllow),
		EffectDigest: effectDigest,
	}
}

func executableTestIntent(decision *contracts.DecisionRecord, effect *contracts.Effect, issuedAt time.Time) *contracts.AuthorizedExecutionIntent {
	toolName, _ := effect.Params["tool_name"].(string)
	if toolName == "" {
		toolName = effect.EffectType
	}
	return &contracts.AuthorizedExecutionIntent{
		ID:               "intent-" + decision.ID,
		DecisionID:       decision.ID,
		EffectDigestHash: decision.EffectDigest,
		IssuedAt:         issuedAt,
		ExpiresAt:        issuedAt.Add(time.Hour),
		AllowedTool:      toolName,
	}
}

func TestSafeExecutor_Gating(t *testing.T) {
	// Setup
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, newMemoryOutboxStore(), "", nil, nil, nil, nil).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))

	effect := &contracts.Effect{
		EffectID: "eff-1",
		Params:   map[string]any{"tool_name": "ls"},
	}

	// 1. Valid Decision -> Execute
	validDec := executableTestDecision("dec-1", testEffectDigest(t, effect))
	// Sign the decision so it passes signature validation
	if err := signer.SignDecision(validDec); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}

	intent := executableTestIntent(validDec, effect, time.Now())
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
	executor2 := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, nil, "", nil, nil, nil, nil).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))
	mockDriver.Called = false
	mismatchIntent := &contracts.AuthorizedExecutionIntent{DecisionID: "dec-other"}

	if _, _, err := executor2.Execute(context.Background(), effect, validDec, mismatchIntent); err == nil {
		t.Error("Executor allowed mismatch intent")
	}
	if mockDriver.Called {
		t.Error("Driver called despite mismatch")
	}
}

func TestSafeExecutorAtomicallyClaimsIntentBeforeDispatch(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("claim-test-key")
	if err != nil {
		t.Fatal(err)
	}
	driver := &blockingDriver{entered: make(chan struct{}), release: make(chan struct{})}
	receipts := NewMemoryReceiptStore()
	outbox := newMemoryOutboxStore()
	first := NewSafeExecutor(signer, signer, driver, receipts, nil, outbox, "", nil, nil, nil, nil).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))
	second := NewSafeExecutor(signer, signer, driver, receipts, nil, outbox, "", nil, nil, nil, nil).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))

	effect := &contracts.Effect{EffectID: "eff-claim", EffectType: "EXECUTE_TOOL", Params: map[string]any{"tool_name": "deploy"}}
	decision := executableTestDecision("dec-claim", testEffectDigest(t, effect))
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Now().UTC()
	intent := executableTestIntent(decision, effect, issuedAt)
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, _, executeErr := first.Execute(context.Background(), effect, decision, intent)
		firstDone <- executeErr
	}()
	select {
	case <-driver.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first executor never reached the driver")
	}

	if _, _, err := second.Execute(context.Background(), effect, decision, intent); err == nil {
		t.Fatal("second executor dispatched despite an active durable claim")
	}
	if got := driver.Calls(); got != 1 {
		t.Fatalf("driver calls during active claim = %d, want 1", got)
	}

	close(driver.release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first executor failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first executor did not complete")
	}
	if got := driver.Calls(); got != 1 {
		t.Fatalf("driver calls after completion = %d, want 1", got)
	}
	if receipt, ok := receipts.receipts[executionReceiptID(intent.ID)]; !ok || receipt.ExternalReferenceID != intent.ID {
		t.Fatalf("missing idempotent execution receipt: %+v", receipt)
	}
}

func TestSafeExecutorRequiresCausalReceiptPrerequisitesBeforeDispatch(t *testing.T) {
	cases := []struct {
		name            string
		receiptStore    ReceiptStore
		clearSessionID  bool
		wantErrorSubstr string
	}{
		{
			name:            "missing receipt store",
			receiptStore:    nil,
			wantErrorSubstr: "receipt store unavailable",
		},
		{
			name:            "missing signed session",
			receiptStore:    NewMemoryReceiptStore(),
			clearSessionID:  true,
			wantErrorSubstr: "signed decision session_id is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := crypto.NewEd25519Signer("causal-prereq-" + tc.name)
			if err != nil {
				t.Fatal(err)
			}
			driver := &MockDriver{}
			effect := &contracts.Effect{
				EffectID:   "effect-causal-prereq",
				EffectType: "EXECUTE_TOOL",
				Params:     map[string]any{"tool_name": "deploy"},
			}
			decision := executableTestDecision("decision-causal-prereq", testEffectDigest(t, effect))
			if tc.clearSessionID {
				decision.SessionID = ""
			}
			if err := signer.SignDecision(decision); err != nil {
				t.Fatalf("SignDecision: %v", err)
			}
			intent := executableTestIntent(decision, effect, time.Now().UTC())
			if err := signer.SignIntent(intent); err != nil {
				t.Fatalf("SignIntent: %v", err)
			}

			executor := NewSafeExecutor(signer, signer, driver, tc.receiptStore, nil, newMemoryOutboxStore(), "", nil, nil, nil, nil).
				WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))
			_, _, err = executor.Execute(context.Background(), effect, decision, intent)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrorSubstr) {
				t.Fatalf("Execute error = %v, want %q", err, tc.wantErrorSubstr)
			}
			if driver.Called {
				t.Fatal("driver dispatched despite missing causal receipt prerequisite")
			}
		})
	}
}

func TestSafeExecutorRejectsMissingVerifierOrDriverBeforeClaim(t *testing.T) {
	for _, missing := range []string{"verifier", "driver"} {
		t.Run(missing, func(t *testing.T) {
			signer, err := crypto.NewEd25519Signer("composition-" + missing)
			if err != nil {
				t.Fatal(err)
			}
			effect := &contracts.Effect{
				EffectID:   "effect-composition-" + missing,
				EffectType: "EXECUTE_TOOL",
				Params:     map[string]any{"tool_name": "deploy"},
			}
			decision := executableTestDecision("decision-composition-"+missing, testEffectDigest(t, effect))
			if err := signer.SignDecision(decision); err != nil {
				t.Fatalf("SignDecision: %v", err)
			}
			intent := executableTestIntent(decision, effect, time.Now().UTC())
			if err := signer.SignIntent(intent); err != nil {
				t.Fatalf("SignIntent: %v", err)
			}

			var verifier crypto.Verifier = signer
			var driver ToolDriver = &MockDriver{}
			if missing == "verifier" {
				verifier = nil
			} else {
				driver = nil
			}
			outbox := newMemoryOutboxStore()
			executor := NewSafeExecutor(verifier, signer, driver, NewMemoryReceiptStore(), nil, outbox, "", nil, nil, nil, nil).
				WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))

			_, _, err = executor.Execute(context.Background(), effect, decision, intent)
			if err == nil || !strings.Contains(err.Error(), missing+" unavailable") {
				t.Fatalf("Execute error = %v, want missing %s failure", err, missing)
			}
			if state := outbox.states[intent.ID]; state != "" {
				t.Fatalf("outbox claim = %q, want no reservation before composition preflight", state)
			}
		})
	}
}

func TestSafeExecutorRejectsRuntimeEffectDigestMismatch(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("test-key")
	mockDriver := &MockDriver{}
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, newMemoryOutboxStore(), "", nil, nil, nil, nil).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))

	approvedEffect := &contracts.Effect{
		EffectID:   "eff-approved",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "deploy", "target": "staging"},
	}
	decision := executableTestDecision("dec-approved", testEffectDigest(t, approvedEffect))
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	intent := executableTestIntent(decision, approvedEffect, time.Now())
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
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, newMemoryOutboxStore(), "", nil, nil, nil, nil).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver)).
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
	effect := &contracts.Effect{EffectID: "eff-safedep-block", Params: map[string]any{"tool_name": "ls"}}
	decision := executableTestDecision("dec-safedep-block", testEffectDigest(t, effect))
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	intent := executableTestIntent(decision, effect, time.Now())
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
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
	effect := &contracts.Effect{EffectID: "eff-safedep-gate-required", Params: map[string]any{"tool_name": "ls"}}
	decision := executableTestDecision("dec-safedep-gate-required", testEffectDigest(t, effect))
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	intent := executableTestIntent(decision, effect, time.Now())
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
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
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, newMemoryOutboxStore(), "", nil, nil, nil, nil).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver)).
		WithSafeDepGate(safeDepGateFunc(func(_ context.Context, req safedep.GateRequest) (safedep.GateResult, error) {
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
	decision := executableTestDecision("dec-safedep-allow", testEffectDigest(t, effect))
	if err := signer.SignDecision(decision); err != nil {
		t.Fatal(err)
	}
	intent := executableTestIntent(decision, effect, time.Now())
	if err := signer.SignIntent(intent); err != nil {
		t.Fatal(err)
	}
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
	executor := NewSafeExecutor(signer, signer, mockDriver, NewMemoryReceiptStore(), nil, newMemoryOutboxStore(), "", nil, nil, nil, nil).
		WithClock(func() time.Time { return fixedTime }).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))

	effect := &contracts.Effect{
		EffectID: "eff-clock",
		Params:   map[string]any{"tool_name": "ls"},
	}
	dec := executableTestDecision("dec-clock", testEffectDigest(t, effect))
	if err := signer.SignDecision(dec); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}
	intent := executableTestIntent(dec, effect, fixedTime)
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
		WithClock(func() time.Time { return futureTime }).
		WithSafeDepAuthorityResolver(safedep.AuthorityResolverFunc(noHazardSafeDepResolver))

	effect := &contracts.Effect{
		EffectID: "eff-expired",
		Params:   map[string]any{"tool_name": "ls"},
	}
	dec := executableTestDecision("dec-expired", testEffectDigest(t, effect))
	if err := signer.SignDecision(dec); err != nil {
		t.Fatalf("Failed to sign decision: %v", err)
	}
	intent := executableTestIntent(dec, effect, futureTime.Add(-2*time.Hour))
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
