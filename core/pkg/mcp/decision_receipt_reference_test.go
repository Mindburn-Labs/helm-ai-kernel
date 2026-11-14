package mcp

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
)

func TestDecisionReceiptReferenceSurvivesExecutionReceipt(t *testing.T) {
	catalog := privacyCatalog(t)
	tool, _ := catalog.Lookup("privacy-tool")
	argsHash, err := ValidateToolArguments(tool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	firewall := NewGovernanceFirewall(&privacyRecordingEvaluator{verdict: "ALLOW"}, catalog,
		WithDecisionReceiptID(func(context.Context, *contracts.DecisionRecord) string { return "persisted-admission-receipt" }))
	response, err := firewall.WrapToolHandler(func(context.Context, ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "done", ExecutionReceipt: &contracts.Receipt{ReceiptID: "persisted-execution-receipt", ArgsHash: argsHash}}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "review-session", Arguments: map[string]any{}})
	if err != nil || response.IsError {
		t.Fatalf("unexpected denial: response=%+v error=%v", response, err)
	}
	if response.ReceiptID != "persisted-admission-receipt" {
		t.Fatalf("response receipt_id must reference a persisted receipt: got %q", response.ReceiptID)
	}
	if response.ExecutionReceipt == nil || response.ExecutionReceipt.ReceiptID != "persisted-execution-receipt" {
		t.Fatal("execution evidence was replaced")
	}
}

func TestDecisionReceiptReferenceSurvivesEgressDenial(t *testing.T) {
	catalog := privacyCatalog(t)
	tool, _ := catalog.Lookup("privacy-tool")
	argsHash, err := ValidateToolArguments(tool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	firewall := NewGovernanceFirewall(&privacyRecordingEvaluator{verdict: "ALLOW"}, catalog,
		WithDecisionReceiptID(func(context.Context, *contracts.DecisionRecord) string { return "persisted-admission-receipt" }))
	response, err := firewall.WrapToolHandler(func(context.Context, ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "4111 1111 1111 1111", ExecutionReceipt: &contracts.Receipt{ReceiptID: "persisted-execution-receipt", ArgsHash: argsHash}}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "review-session", Arguments: map[string]any{}})
	if err != nil || !response.IsError {
		t.Fatalf("expected egress refusal: response=%+v error=%v", response, err)
	}
	if response.ReceiptID != "persisted-admission-receipt" {
		t.Fatalf("governed response must retain documented portable decision receipt reference after egress refusal: got %q", response.ReceiptID)
	}
}

// A cryptographic digest can contain digits that happen to pass the privacy
// manager's payment-card heuristic. The receipt writer still persists the
// original rcpt-<sha256> identity, which the public response must resolve.
func TestGeneratedDecisionReceiptReferenceIsPreserved(t *testing.T) {
	const tenant, decisionID = "final-review-tenant", "decision-152"
	want := executor.ReceiptIDForDecision(tenant, decisionID)
	t.Logf("generated receipt reference: %s", want)
	catalog := privacyCatalog(t)
	firewall := NewGovernanceFirewall(&privacyRecordingEvaluator{verdict: "ALLOW"}, catalog,
		WithDecisionReceiptID(func(context.Context, *contracts.DecisionRecord) string { return want }))
	response, err := firewall.WrapToolHandler(func(context.Context, ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "done"}, nil
	})(context.Background(), ToolExecutionRequest{ToolName: "privacy-tool", SessionID: "final-review", Arguments: map[string]any{}})
	if err != nil || response.IsError {
		t.Fatalf("unexpected denial: response=%+v error=%v", response, err)
	}
	if response.ReceiptID != want {
		t.Fatalf("public reference does not resolve the writer's receipt: got %q, want %q", response.ReceiptID, want)
	}
}
