package governance

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/require"
)

// MockSigner implementation for testing
type MockSigner struct{}

func (m *MockSigner) Sign(data []byte) (string, error) { return "sig", nil }
func (m *MockSigner) PublicKey() string                { return "key" }
func (m *MockSigner) PublicKeyBytes() []byte           { return []byte("key") }
func (m *MockSigner) SignDecision(d *contracts.DecisionRecord) error {
	d.Signature = "sig"
	return nil
}
func (m *MockSigner) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	i.Signature = "sig"
	return nil
}
func (m *MockSigner) SignReceipt(r *contracts.Receipt) error {
	r.Signature = "sig"
	return nil
}
func (m *MockSigner) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	return true, nil
}
func (m *MockSigner) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	return true, nil
}
func (m *MockSigner) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	return true, nil
}

func decodeSignalPayload(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	require.NoError(t, json.Unmarshal(raw, &payload))
	return payload
}
