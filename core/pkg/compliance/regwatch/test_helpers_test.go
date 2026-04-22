package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// TestAdapter is a configurable adapter for integration tests.
// It implements SourceAdapter with injectable responses for verifying
// swarm pipeline behavior without requiring network access.
type TestAdapter struct {
	BaseAdapter
	changes    []*RegChange
	fetchError error
}

// NewTestAdapter creates a configurable test adapter.
func NewTestAdapter(sourceType SourceType, jurisdiction jkg.JurisdictionCode) *TestAdapter {
	return &TestAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   sourceType,
			jurisdiction: jurisdiction,
			healthy:      true,
		},
		changes: make([]*RegChange, 0),
	}
}

// SetChanges configures the changes to return from FetchChanges.
func (m *TestAdapter) SetChanges(changes []*RegChange) {
	m.changes = changes
}

// SetFetchError configures FetchChanges to return an error.
func (m *TestAdapter) SetFetchError(err error) {
	m.fetchError = err
}

// FetchChanges returns configured changes or error.
func (m *TestAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	if m.fetchError != nil {
		return nil, m.fetchError
	}
	return m.changes, nil
}

// IsHealthy returns configured health status.
func (m *TestAdapter) IsHealthy(ctx context.Context) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy
}

// SetHealthy sets health status for testing.
func (m *TestAdapter) SetHealthy(healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = healthy
}
