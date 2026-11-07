// quantum_posture: these tests exercise existing classical Ed25519 receipt
// verification; privacy-boundary coverage adds no post-quantum assurance.
package gateway

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

func newOpenAICompatibleServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
	})
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", version)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "test-model"}}})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "ok"}}},
		})
	})
	return httptest.NewServer(mux)
}

func gatewayAllowSpendDecision() *economic.SpendAuthorityDecision {
	return gatewaySpendDecision(economic.BudgetVerdictAllow, economic.SpendReasonOKWithinEnvelope)
}

func gatewaySpendDecision(verdict economic.BudgetVerdict, reason economic.SpendReasonCode) *economic.SpendAuthorityDecision {
	decision := &economic.SpendAuthorityDecision{
		Verdict:        verdict,
		ReasonCode:     reason,
		Reason:         "test spend decision",
		RemainingCents: 1000,
		EnvelopeHash:   "sha256:envelope",
	}
	decision.ContentHash = decision.CanonicalContentHash()
	return decision
}

func gatewayTamperedAllowSpendDecision() *economic.SpendAuthorityDecision {
	decision := gatewayAllowSpendDecision()
	decision.ContentHash = "sha256:tampered"
	return decision
}

var (
	gatewayReceiptPrivateKey          = ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	gatewayUntrustedReceiptPrivateKey = ed25519.NewKeyFromSeed([]byte("fedcba9876543210fedcba9876543210"))
)

func gatewayExecContext(provider ProviderType, model string, decision *economic.SpendAuthorityDecision, req ExecContext) ExecContext {
	req.SpendDecision = decision
	req.SpendReceipt = gatewaySpendReceipt(provider, model, decision)
	return req
}

func gatewaySpendReceipt(provider ProviderType, model string, decision *economic.SpendAuthorityDecision) *economic.BudgetVerdictReceipt {
	receipt := gatewayUnsignedSpendReceipt(provider, model, decision)
	sealGatewayReceipt(receipt)
	return receipt
}

func gatewayDispatchPermit() budgetVerdictDispatchPermit {
	decision := gatewayAllowSpendDecision()
	receipt := gatewaySpendReceipt(ProviderVLLM, "model", decision)
	return budgetVerdictDispatchPermit{decisionHash: decision.ContentHash, receiptHash: receipt.ContentHash}
}

func gatewayUnsignedSpendReceipt(provider ProviderType, model string, decision *economic.SpendAuthorityDecision) *economic.BudgetVerdictReceipt {
	if decision == nil {
		return nil
	}
	return economic.NewBudgetVerdictReceipt(
		"verdict-1",
		"tenant-1",
		"spend-1",
		"env-1",
		"agent-1",
		string(provider),
		model,
		100,
		200,
		"USD",
		"sha256:price",
		"sha256:route-policy",
		"evidence://pack-1",
		*decision,
	)
}

func sealGatewayReceipt(receipt *economic.BudgetVerdictReceipt) {
	sealGatewayReceiptWithKey(receipt, "gateway-test-key", gatewayReceiptPrivateKey)
}

func sealGatewayReceiptWithKey(receipt *economic.BudgetVerdictReceipt, keyID string, key ed25519.PrivateKey) {
	if receipt == nil {
		return
	}
	if err := receipt.Seal(keyID, key); err != nil {
		panic(err)
	}
}
