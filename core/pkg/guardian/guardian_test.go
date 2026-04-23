package guardian

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBudgetTracker implements BudgetGate for tests.
type mockBudgetTracker struct {
	mu       sync.Mutex
	limit    int64
	consumed int64
}

func newMockBudgetTracker(limit int64) *mockBudgetTracker {
	return &mockBudgetTracker{limit: limit}
}

func (m *mockBudgetTracker) Check(_ string, cost BudgetCost) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.consumed+cost.Requests <= m.limit, nil
}

func (m *mockBudgetTracker) Consume(_ string, cost BudgetCost) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.consumed+cost.Requests > m.limit {
		return errors.New("budget exceeded")
	}
	m.consumed += cost.Requests
	return nil
}

// --- Mocks ---

type MockSigner struct {
	FailSign bool
}

func (m *MockSigner) Sign(data []byte) (string, error) {
	if m.FailSign {
		return "", errors.New("signer broken")
	}
	return "mock_sig", nil
}

func (m *MockSigner) PublicKey() string { return "mock_key" }

func (m *MockSigner) PublicKeyBytes() []byte { return []byte("mock_key") }

func (m *MockSigner) SignDecision(d *contracts.DecisionRecord) error {
	if m.FailSign {
		return errors.New("signer broken")
	}
	d.Signature = "mock_decision_sig"
	return nil
}

func (m *MockSigner) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	if m.FailSign {
		return errors.New("signer broken")
	}
	i.Signature = "mock_intent_sig"
	return nil
}

func (m *MockSigner) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	return true, nil
}

func (m *MockSigner) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	return true, nil
}

func (m *MockSigner) SignReceipt(r *contracts.Receipt) error {
	if m.FailSign {
		return errors.New("signer broken")
	}
	r.Signature = "mock_receipt_sig"
	return nil
}

func (m *MockSigner) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	return true, nil
}

type MockStore struct {
	Data map[string][]byte
}

func NewMockStore() *MockStore {
	return &MockStore{Data: make(map[string][]byte)}
}

func (m *MockStore) Store(ctx context.Context, data []byte) (string, error) {
	hash := fmt.Sprintf("sha256:%d", len(data)) // simple mock hash
	m.Data[hash] = data
	return hash, nil
}

func (m *MockStore) Get(ctx context.Context, hash string) ([]byte, error) {
	data, ok := m.Data[hash]
	if !ok {
		return nil, errors.New("not found")
	}
	return data, nil
}

func (m *MockStore) Exists(ctx context.Context, hash string) (bool, error) {
	_, ok := m.Data[hash]
	return ok, nil
}

func (m *MockStore) Delete(ctx context.Context, hash string) error {
	delete(m.Data, hash)
	return nil
}

// --- Tests ---

func TestGuardian_SignDecision(t *testing.T) {
	// 1. Setup Dependencies
	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	signer := &MockSigner{}
	ruleGraph := prg.NewGraph()

	// 2. Setup PRG Rules
	// Rule: "safe_tool" requires an artifact of type "audit_report"
	rule := prg.RequirementSet{
		ID:    "req-1",
		Logic: prg.AND,
		Requirements: []prg.Requirement{
			{ID: "must-have-audit", ArtifactType: "audit_report"},
		},
	}
	_ = ruleGraph.AddRule("safe_tool", rule)

	// 3. Setup Artifacts
	ctx := context.Background()
	validArt := &pkg_artifact.ArtifactEnvelope{
		Type:      "audit_report",
		Payload:   []byte("{}"),
		Signature: "sig",
	}
	// Manually store to get hash
	validHash, err := registry.PutArtifact(ctx, validArt)
	require.NoError(t, err)

	invalidArt := &pkg_artifact.ArtifactEnvelope{
		Type:      "random_log",
		Payload:   []byte("{}"),
		Signature: "sig",
	}
	invalidHash, err := registry.PutArtifact(ctx, invalidArt)
	require.NoError(t, err)

	subject := NewGuardian(signer, ruleGraph, registry)

	t.Run("Success Path", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-1"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-1",
			Params:     map[string]any{"tool_name": "safe_tool"},
		}
		evidence := []string{validHash}

		err := subject.SignDecision(ctx, decision, effect, evidence, nil)
		require.NoError(t, err)

		assert.Equal(t, "ALLOW", decision.Verdict)
		assert.Equal(t, "mock_decision_sig", decision.Signature)
		assert.NotEmpty(t, decision.RequirementSetHash)
		assert.WithinDuration(t, time.Now(), decision.Timestamp, 1*time.Second)
	})

	t.Run("Fail: Missing Evidence (Artifact not found)", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-2"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-2",
			Params:     map[string]any{"tool_name": "safe_tool"},
		}
		evidence := []string{"missing_hash"}

		err := subject.SignDecision(ctx, decision, effect, evidence, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve evidence")
	})

	t.Run("Fail: PRG Violation (Wrong Artifact Type) -> Fail Closed", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-3"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-3",
			Params:     map[string]any{"tool_name": "safe_tool"},
		}
		evidence := []string{invalidHash}

		err := subject.SignDecision(ctx, decision, effect, evidence, nil)
		require.NoError(t, err) // Should NOT return error, but sign a FAIL verdict

		assert.Equal(t, "DENY", decision.Verdict)
		assert.Equal(t, "mock_decision_sig", decision.Signature) // Must be signed
		assert.Contains(t, decision.Reason, "MISSING_REQUIREMENT")
	})

	t.Run("Fail: Unknown Action (No Policy) -> Fail Closed", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-4"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-4",
			Params:     map[string]any{"tool_name": "rogue_tool"},
		}
		evidence := []string{validHash}

		err := subject.SignDecision(ctx, decision, effect, evidence, nil)
		require.NoError(t, err)

		assert.Equal(t, "DENY", decision.Verdict)
		assert.Equal(t, "mock_decision_sig", decision.Signature)
		assert.Contains(t, decision.Reason, "no policy defined")
	})

	t.Run("Success: CEL Expression", func(t *testing.T) {
		// Rule: "cel_tool" requires a budget_id parameter in the effect
		rule := prg.RequirementSet{
			ID:    "req-cel",
			Logic: prg.AND,
			Requirements: []prg.Requirement{
				{
					ID:         "check-budget",
					Expression: `input.effect.params.budget_id != ""`,
				},
			},
		}
		_ = ruleGraph.AddRule("cel_tool", rule)

		decision := &contracts.DecisionRecord{ID: "dec-cel-1"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-cel-1",
			Params: map[string]any{
				"tool_name": "cel_tool",
				"budget_id": "test-budget",
			},
		}

		err := subject.SignDecision(ctx, decision, effect, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "ALLOW", decision.Verdict)
	})

	t.Run("Fail: CEL Expression Violation", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-cel-2"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-cel-2",
			Params: map[string]any{
				"tool_name": "cel_tool",
				"budget_id": "", // Violation
			},
		}

		err := subject.SignDecision(ctx, decision, effect, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "DENY", decision.Verdict)
		assert.Equal(t, string(contracts.ReasonMissingRequirement), decision.Reason)
	})

	t.Run("Fail: Signer Error", func(t *testing.T) {
		brokenSigner := &MockSigner{FailSign: true}
		brokenSubject := NewGuardian(brokenSigner, ruleGraph, registry)

		decision := &contracts.DecisionRecord{ID: "dec-5"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-5",
			Params:     map[string]any{"tool_name": "safe_tool"},
		}
		evidence := []string{validHash}

		err := brokenSubject.SignDecision(ctx, decision, effect, evidence, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signer broken")
	})
}

func TestGuardian_BudgetEnforcement(t *testing.T) {
	// 1. Setup Dependencies
	mockStore := NewMockStore()
	registry := pkg_artifact.NewRegistry(mockStore, nil)
	signer := &MockSigner{}
	ruleGraph := prg.NewGraph()
	// Allow safe_tool via PRG (so we don't fail on PRG)
	_ = ruleGraph.AddRule("safe_tool", prg.RequirementSet{
		ID:           "allow-all",
		Requirements: []prg.Requirement{}, // Empty = always pass
	})

	// 2. Setup Budget
	tracker := newMockBudgetTracker(1) // limit of 1 request

	// 3. Setup Guardian with Tracker
	subject := NewGuardian(signer, ruleGraph, registry)
	subject.SetBudgetTracker(tracker)

	ctx := context.Background()

	t.Run("Pass: Within Budget", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-budget-1"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-b1",
			Params: map[string]any{
				"tool_name": "safe_tool",
				"budget_id": "tiny-budget",
			},
		}

		err := subject.SignDecision(ctx, decision, effect, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "ALLOW", decision.Verdict)
	})

	t.Run("Fail: Budget Exceeded", func(t *testing.T) {
		// Budget had limit 1, consumed 1 in previous step.
		// Next request (cost 1) -> Total 2 > Limit 1.
		decision := &contracts.DecisionRecord{ID: "dec-budget-2"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-b2",
			Params: map[string]any{
				"tool_name": "safe_tool",
				"budget_id": "tiny-budget",
			},
		}

		err := subject.SignDecision(ctx, decision, effect, nil, nil)
		// It might return error or sign fail depending on impl.
		// My impl signs fail for "Budget Exceeded" but returns Signed decision (nil error).
		require.NoError(t, err)
		assert.Equal(t, "DENY", decision.Verdict)
		assert.Contains(t, decision.Reason, "BUDGET_EXCEEDED")
	})

	t.Run("Pass: No Budget ID (Bypass Check)", func(t *testing.T) {
		decision := &contracts.DecisionRecord{ID: "dec-budget-3"}
		effect := &contracts.Effect{
			EffectType: "tool_call",
			EffectID:   "eff-b3",
			Params: map[string]any{
				"tool_name": "safe_tool",
				// No budget_id
			},
		}

		err := subject.SignDecision(ctx, decision, effect, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, "ALLOW", decision.Verdict)
	})
}
