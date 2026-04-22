package context

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/ledger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type MockLedger struct {
	Data map[string]ledger.Obligation
}

func (m *MockLedger) Get(ctx context.Context, id string) (ledger.Obligation, error) {
	if obl, ok := m.Data[id]; ok {
		return obl, nil
	}
	return ledger.Obligation{}, errors.New("not found")
}

// Unused methods
func (m *MockLedger) Create(ctx context.Context, obl ledger.Obligation) error { return nil }
func (m *MockLedger) AcquireLease(ctx context.Context, id, workerID string, duration time.Duration) (ledger.Obligation, error) {
	return ledger.Obligation{}, nil
}
func (m *MockLedger) UpdateState(ctx context.Context, id string, newState ledger.State, details map[string]any) error {
	return nil
}
func (m *MockLedger) ListPending(ctx context.Context) ([]ledger.Obligation, error) { return nil, nil }
func (m *MockLedger) ListAll(ctx context.Context) ([]ledger.Obligation, error)     { return nil, nil }

type MockVectorStore struct {
	Results []store.SearchResult
}

func (m *MockVectorStore) Search(ctx context.Context, vector store.Embedding, limit int) ([]store.SearchResult, error) {
	return m.Results, nil
}
func (m *MockVectorStore) Store(ctx context.Context, id string, text string, vector store.Embedding, metadata map[string]string) error {
	return nil
}

type MockEmbedder struct{}

func (m *MockEmbedder) Embed(ctx context.Context, text string) (store.Embedding, error) {
	return make(store.Embedding, 10), nil
}

// --- Tests ---

func TestAssembler_Assemble(t *testing.T) {
	// Setup
	mockLedger := &MockLedger{Data: make(map[string]ledger.Obligation)}
	mockVector := &MockVectorStore{}
	mockEmbedder := &MockEmbedder{}

	assembler := NewAssembler(mockLedger, mockVector, mockEmbedder)
	ctx := context.Background()

	t.Run("Full Context Generation", func(t *testing.T) {
		// Data
		oblID := "obl-1"
		mockLedger.Data[oblID] = ledger.Obligation{
			ID:     oblID,
			Intent: "Fix the server",
			State:  ledger.StatePending,
		}
		mockVector.Results = []store.SearchResult{
			{Text: "Past fix 1"},
		}

		// Execute
		prompt, err := assembler.Assemble(ctx, oblID)
		require.NoError(t, err)

		// Verify
		assert.Contains(t, prompt, "You are the HELM Kernel")
		assert.Contains(t, prompt, "ACTIVE OBLIGATION: Fix the server")
		assert.Contains(t, prompt, "RELEVANT EXPERIENCE:")
		assert.Contains(t, prompt, "- Past fix 1")
		assert.Contains(t, prompt, "RULES:")
	})

	t.Run("No Active Obligation", func(t *testing.T) {
		prompt, err := assembler.Assemble(ctx, "")
		require.NoError(t, err)

		assert.Contains(t, prompt, "You are the HELM Kernel")
		assert.NotContains(t, prompt, "ACTIVE OBLIGATION")
		assert.Contains(t, prompt, "RULES:")
	})

	t.Run("Obligation Not Found (Graceful)", func(t *testing.T) {
		prompt, err := assembler.Assemble(ctx, "missing-id")
		require.NoError(t, err)

		assert.Contains(t, prompt, "You are the HELM Kernel")
		assert.NotContains(t, prompt, "ACTIVE OBLIGATION")
	})
}
