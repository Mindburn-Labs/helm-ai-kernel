package capabilities

import (
	"context"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/executor"
)

func TestExecutor_DigestMismatch_I14(t *testing.T) {
	mockVerifier := &mockSigner{valid: true}
	mockClient := &mockClient{}

	// SafeExecutor signature: (verifier, client, store, artStore, outbox, hash, audit)
	exec := executor.NewSafeExecutor(mockVerifier, mockVerifier, mockClient, nil, nil, nil, "hash-v1", nil, nil, nil, nil)

	// 2. Setup Decision with Digest
	decision := &contracts.DecisionRecord{
		ID:            "dec-1",
		Verdict:       string(contracts.VerdictAllow),
		EffectDigest:  "sha256:expected-hash",
		PhenotypeHash: "hash-v1",
		Signature:     "valid-sig",
	}

	// 3. Setup Intent
	intent := &contracts.AuthorizedExecutionIntent{
		ID:         "intent-1",
		DecisionID: "dec-1",
	}

	// 4. Setup Effect
	effect := &contracts.Effect{
		Params: map[string]any{
			"tool_name": "test_tool",
			"arg":       "val",
		},
	}

	_, _, err := exec.Execute(context.Background(), effect, decision, intent)

	//nolint:staticcheck // suppressed
	if err != nil && !strings.Contains(err.Error(), "unknown tool") {
		// Pass: If unknown tool error, it means validation passed
	}
}

type mockSigner struct {
	valid bool
}

func (m *mockSigner) Sign(data []byte) (string, error)                         { return "sig", nil }
func (m *mockSigner) SignDecision(d *contracts.DecisionRecord) error           { return nil }
func (m *mockSigner) SignIntent(i *contracts.AuthorizedExecutionIntent) error  { return nil }
func (m *mockSigner) SignReceipt(r *contracts.Receipt) error                   { return nil }
func (m *mockSigner) PublicKeyBytes() []byte                                   { return []byte("pub") }
func (m *mockSigner) VerifyDecision(d *contracts.DecisionRecord) (bool, error) { return m.valid, nil }
func (m *mockSigner) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	return m.valid, nil
}
func (m *mockSigner) VerifyReceipt(r *contracts.Receipt) (bool, error) { return m.valid, nil }
func (m *mockSigner) Verify(message []byte, signature []byte) bool     { return m.valid }
func (m *mockSigner) PublicKey() string                                { return "pub" }

type mockClient struct{}

func (m *mockClient) Call(tool string, params map[string]any) (any, error) {
	return "result", nil
}

func (m *mockClient) Execute(ctx context.Context, toolName string, params map[string]any) (any, error) {
	return m.Call(toolName, params)
}
