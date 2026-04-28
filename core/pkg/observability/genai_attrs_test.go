package observability_test

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/observability"
)

// TestGenAIKeyStability pins the OTel GenAI semconv attribute keys helm-oss
// emits. Renaming any of these constants is a backwards-incompatible change:
// downstream SIEM exporters, the OTel collector pipeline, and any user-built
// dashboards index spans by these exact strings.
func TestGenAIKeyStability(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"GenAISystem", observability.GenAISystem, "gen_ai.system"},
		{"GenAIRequestModel", observability.GenAIRequestModel, "gen_ai.request.model"},
		{"GenAIOperationName", observability.GenAIOperationName, "gen_ai.operation.name"},
		{"GenAIToolName", observability.GenAIToolName, "gen_ai.tool.name"},
		{"GenAIToolCallID", observability.GenAIToolCallID, "gen_ai.tool.call.id"},
		{"GenAIUsageInputTokens", observability.GenAIUsageInputTokens, "gen_ai.usage.input_tokens"},
		{"GenAIUsageOutputTokens", observability.GenAIUsageOutputTokens, "gen_ai.usage.output_tokens"},
		{"GenAIResponseFinishReason", observability.GenAIResponseFinishReason, "gen_ai.response.finish_reason"},
		{"GenAIResponseModel", observability.GenAIResponseModel, "gen_ai.response.model"},
		{"GenAIResponseID", observability.GenAIResponseID, "gen_ai.response.id"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q (renaming this constant breaks SIEM exporters)", tc.name, tc.got, tc.want)
		}
	}
}

// TestHelmKeyStability pins the helm.* governance attribute keys.
func TestHelmKeyStability(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"HelmVerdict", observability.HelmVerdict, "helm.verdict"},
		{"HelmPolicyID", observability.HelmPolicyID, "helm.policy_id"},
		{"HelmProofNodeID", observability.HelmProofNodeID, "helm.proof_node_id"},
		{"HelmReasonCode", observability.HelmReasonCode, "helm.reason_code"},
		{"HelmCorrelationID", observability.HelmCorrelationID, "helm.correlation_id"},
		{"HelmReceiptID", observability.HelmReceiptID, "helm.receipt_id"},
		{"HelmReceiptHash", observability.HelmReceiptHash, "helm.receipt.hash"},
		{"HelmLamport", observability.HelmLamport, "helm.lamport"},
		{"HelmTenantID", observability.HelmTenantID, "helm.tenant_id"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// TestNamespaceDiscipline asserts the gen_ai.* keys live under the OTel namespace
// and the helm.* keys live under the helm-specific namespace. Mixing namespaces
// would prevent OTel collectors from filtering by attribute prefix.
func TestNamespaceDiscipline(t *testing.T) {
	genAI := []string{
		observability.GenAISystem,
		observability.GenAIRequestModel,
		observability.GenAIOperationName,
		observability.GenAIToolName,
		observability.GenAIToolCallID,
		observability.GenAIUsageInputTokens,
		observability.GenAIUsageOutputTokens,
		observability.GenAIResponseFinishReason,
		observability.GenAIResponseModel,
		observability.GenAIResponseID,
	}
	for _, k := range genAI {
		if !strings.HasPrefix(k, "gen_ai.") {
			t.Errorf("expected gen_ai. prefix on %q", k)
		}
	}

	helm := []string{
		observability.HelmVerdict,
		observability.HelmPolicyID,
		observability.HelmProofNodeID,
		observability.HelmReasonCode,
		observability.HelmCorrelationID,
		observability.HelmReceiptID,
		observability.HelmReceiptHash,
		observability.HelmLamport,
		observability.HelmTenantID,
	}
	for _, k := range helm {
		if !strings.HasPrefix(k, "helm.") {
			t.Errorf("expected helm. prefix on %q", k)
		}
	}
}

// TestOperationValuesStability pins the GenAI operation enum values.
func TestOperationValuesStability(t *testing.T) {
	if observability.GenAIOperationChat != "chat" {
		t.Errorf("GenAIOperationChat = %q, want %q", observability.GenAIOperationChat, "chat")
	}
	if observability.GenAIOperationCompletion != "completion" {
		t.Errorf("GenAIOperationCompletion = %q, want %q", observability.GenAIOperationCompletion, "completion")
	}
	if observability.GenAIOperationEmbedding != "embedding" {
		t.Errorf("GenAIOperationEmbedding = %q, want %q", observability.GenAIOperationEmbedding, "embedding")
	}
	if observability.GenAIOperationToolCall != "tool_call" {
		t.Errorf("GenAIOperationToolCall = %q, want %q", observability.GenAIOperationToolCall, "tool_call")
	}
}

// TestSystemValuesStability pins the GenAI system enum values.
func TestSystemValuesStability(t *testing.T) {
	if observability.GenAISystemOpenAI != "openai" {
		t.Errorf("GenAISystemOpenAI = %q, want %q", observability.GenAISystemOpenAI, "openai")
	}
	if observability.GenAISystemAnthropic != "anthropic" {
		t.Errorf("GenAISystemAnthropic = %q, want %q", observability.GenAISystemAnthropic, "anthropic")
	}
	if observability.GenAISystemBedrock != "aws.bedrock" {
		t.Errorf("GenAISystemBedrock = %q, want %q", observability.GenAISystemBedrock, "aws.bedrock")
	}
}
