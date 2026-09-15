// Package observability — OpenTelemetry GenAI semantic convention attribute keys.
//
// This file is the single source of truth for the OTel GenAI semconv attribute
// keys helm-ai-kernel emits. Stable keys defined here MUST NOT be renamed without a
// major version bump; the SIEM exporter packs in core/pkg/connectors/siem and
// the OTel collector contract documented in docs/architecture/otel-genai.md
// rely on these names.
//
// Reference: OpenTelemetry Semantic Conventions for Generative AI
// https://github.com/open-telemetry/semantic-conventions-genai/tree/main/docs/gen-ai
// (moved out of the main semantic-conventions repository in its v1.42.0
// release; status is still "Development", not Stable).
//
// Known drift from upstream as of 2026-09-12, kept deliberately until a major
// version bump: upstream replaced gen_ai.system with gen_ai.provider.name and
// its well-known value "azure.openai" with "azure.ai.openai"; upstream names
// the tool operation "execute_tool" (span "execute_tool {gen_ai.tool.name}")
// rather than "tool_call". The SIEM exporters and dashboards join on the keys
// below, so the rename must ship as one coordinated change with them.
package observability

// ── OTel GenAI stable keys ───────────────────────────────────
//
// These keys mirror the upstream OTel GenAI semantic convention. helm-ai-kernel
// emits them on every governed model call so the trace is portable across any
// OTel-compatible backend.

const (
	// GenAISystem identifies the upstream model provider.
	// Values: "openai", "anthropic", "aws.bedrock", "azure.openai", "google.gemini".
	//
	// Legacy. Upstream replaced this key with GenAIProviderName and gen_ai.system
	// does not appear in the current conventions. helm-ai-kernel emits both for one
	// major version so existing SIEM joins and dashboards keep working; see
	// docs/architecture/otel-genai.md for the removal decision, which is still open.
	// Never set this key alone: anything that sets it must also set
	// GenAIProviderName via GenAIProviderNameFor.
	GenAISystem = "gen_ai.system"

	// GenAIProviderName identifies the upstream model provider using the current
	// upstream key, which marks it Required on inference and execute_tool spans.
	// Values: the GenAIProvider* constants below.
	GenAIProviderName = "gen_ai.provider.name"

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

	// GenAIOperationToolCall is the legacy value helm-ai-kernel used for tool
	// invocations. Upstream names this operation execute_tool. Callers may still
	// pass it; the tracer maps it to GenAIOperationExecuteTool on emission.
	GenAIOperationToolCall = "tool_call"

	// GenAIOperationExecuteTool is the upstream operation name for a tool
	// invocation. Upstream names such a span "{operation} {tool name}".
	GenAIOperationExecuteTool = "execute_tool"
)

// ── GenAI system values ──────────────────────────────────────

const (
	GenAISystemOpenAI      = "openai"
	GenAISystemAnthropic   = "anthropic"
	GenAISystemBedrock     = "aws.bedrock"
	GenAISystemAzureOpenAI = "azure.openai"
	GenAISystemGemini      = "google.gemini"
)

// ── GenAI provider names ─────────────────────────────────────
//
// The well-known values of gen_ai.provider.name. Two of the legacy gen_ai.system
// values above are not upstream spellings and are mapped: "azure.openai" becomes
// "azure.ai.openai", "google.gemini" becomes "gcp.gemini". The other three are
// already spelled the upstream way.

const (
	GenAIProviderOpenAI      = "openai"
	GenAIProviderAnthropic   = "anthropic"
	GenAIProviderBedrock     = "aws.bedrock"
	GenAIProviderAzureOpenAI = "azure.ai.openai"
	GenAIProviderGemini      = "gcp.gemini"
)

// genAIProviderNameBySystem maps every legacy gen_ai.system value this kernel
// can emit onto its upstream gen_ai.provider.name spelling.
var genAIProviderNameBySystem = map[string]string{
	GenAISystemOpenAI:      GenAIProviderOpenAI,
	GenAISystemAnthropic:   GenAIProviderAnthropic,
	GenAISystemBedrock:     GenAIProviderBedrock,
	GenAISystemAzureOpenAI: GenAIProviderAzureOpenAI,
	GenAISystemGemini:      GenAIProviderGemini,
}

// GenAIProviderNameFor returns the gen_ai.provider.name value for a legacy
// gen_ai.system value. An unrecognised system is returned unchanged rather than
// dropped: a provider this kernel does not know about is still a provider, and
// the operator's own spelling is more useful than an absent Required attribute.
func GenAIProviderNameFor(system string) string {
	if mapped, ok := genAIProviderNameBySystem[system]; ok {
		return mapped
	}
	return system
}

// GenAIOperationNameFor returns the upstream operation name for the value a
// caller supplied, mapping the legacy tool_call onto execute_tool so callers do
// not each have to be changed.
func GenAIOperationNameFor(operation string) string {
	if operation == GenAIOperationToolCall {
		return GenAIOperationExecuteTool
	}
	return operation
}
