// Package observability — OpenTelemetry GenAI semantic convention attribute keys.
//
// This file is the single source of truth for the OTel GenAI semconv attribute
// keys helm-ai-kernel emits. Stable keys defined here MUST NOT be renamed without a
// major version bump; the SIEM exporter packs in core/pkg/connectors/siem and
// the OTel collector contract documented in docs/architecture/otel-genai.md
// rely on these names.
//
// Reference: OpenTelemetry Semantic Conventions for Generative AI
// https://github.com/open-telemetry/semantic-conventions/tree/main/docs/gen-ai
package observability

// ── OTel GenAI stable keys ───────────────────────────────────
//
// These keys mirror the upstream OTel GenAI semantic convention. helm-ai-kernel
// emits them on every governed model call so the trace is portable across any
// OTel-compatible backend.

const (
	// GenAISystem identifies the upstream model provider.
	// Values: "openai", "anthropic", "aws.bedrock", "azure.openai", "google.gemini".
	GenAISystem = "gen_ai.system"

	// GenAIRequestModel is the requested model identifier.
	// Examples: "gpt-4o", "claude-3-5-sonnet", "anthropic.claude-3-5-sonnet-20241022".
	GenAIRequestModel = "gen_ai.request.model"

	// GenAIOperationName is the GenAI operation kind.
	// Values: "chat", "completion", "embedding", "tool_call".
	GenAIOperationName = "gen_ai.operation.name"

	// GenAIToolName is the name of the tool the model invoked.
	GenAIToolName = "gen_ai.tool.name"

	// GenAIToolCallID is the upstream provider's tool call identifier.
	// helm-ai-kernel sets this to the helm correlation_id so traces and receipts
	// cross-reference 1:1.
	GenAIToolCallID = "gen_ai.tool.call.id"

	// GenAIUsageInputTokens is the number of input/prompt tokens consumed.
	GenAIUsageInputTokens = "gen_ai.usage.input_tokens"

	// GenAIUsageOutputTokens is the number of output/completion tokens produced.
	GenAIUsageOutputTokens = "gen_ai.usage.output_tokens"

	// GenAIResponseFinishReason captures the upstream finish reason.
	// Values: "stop", "length", "tool_calls", "content_filter".
	GenAIResponseFinishReason = "gen_ai.response.finish_reason"

	// GenAIResponseModel is the model returned by the provider (may differ from
	// the requested model after routing).
	GenAIResponseModel = "gen_ai.response.model"

	// GenAIResponseID is the upstream response identifier.
	GenAIResponseID = "gen_ai.response.id"
)

// ── helm.* governance keys ───────────────────────────────────
//
// These keys are helm-specific governance attributes. They live alongside the
// gen_ai.* keys on the same span so a single trace describes both the model
// invocation and the governance decision over it.

const (
	// HelmVerdict is the governance verdict: "ALLOW" | "DENY" | "ESCALATE".
	HelmVerdict = "helm.verdict"

	// HelmPolicyID is the policy bundle identifier that produced the verdict.
	HelmPolicyID = "helm.policy_id"

	// HelmProofNodeID is the ProofGraph node identifier the decision is bound to.
	HelmProofNodeID = "helm.proof_node_id"

	// HelmReasonCode is the structured reason code for the verdict.
	HelmReasonCode = "helm.reason_code"

	// HelmCorrelationID is the helm correlation_id for the governed call.
	// Mirrors gen_ai.tool.call.id so SIEM queries can join either way.
	HelmCorrelationID = "helm.correlation_id"

	// HelmReceiptID is the receipt identifier produced for this call.
	HelmReceiptID = "helm.receipt_id"

	// HelmReceiptHash is the SHA-256 hash of the receipt JSON.
	HelmReceiptHash = "helm.receipt.hash"

	// HelmLamport is the Lamport clock value at the time of the decision.
	HelmLamport = "helm.lamport"

	// HelmTenantID is the tenant the call was governed under.
	HelmTenantID = "helm.tenant_id"
)

// ── GenAI operation values ───────────────────────────────────

const (
	GenAIOperationChat       = "chat"
	GenAIOperationCompletion = "completion"
	GenAIOperationEmbedding  = "embedding"
	GenAIOperationToolCall   = "tool_call"
)

// ── GenAI system values ──────────────────────────────────────

const (
	GenAISystemOpenAI      = "openai"
	GenAISystemAnthropic   = "anthropic"
	GenAISystemBedrock     = "aws.bedrock"
	GenAISystemAzureOpenAI = "azure.openai"
	GenAISystemGemini      = "google.gemini"
)
