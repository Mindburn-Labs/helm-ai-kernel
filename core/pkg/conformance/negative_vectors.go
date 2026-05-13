package conformance

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// NegativeBoundaryVector is a clean-room conformance vector for fail-closed
// execution boundaries. These vectors describe HELM-required behavior, not a
// competitor's test fixture or implementation.
type NegativeBoundaryVector struct {
	ID                 string               `json:"id"`
	Category           string               `json:"category"`
	Trigger            string               `json:"trigger"`
	ExpectedVerdict    contracts.Verdict    `json:"expected_verdict"`
	ExpectedReasonCode contracts.ReasonCode `json:"expected_reason_code"`
	MustEmitReceipt    bool                 `json:"must_emit_receipt"`
	MustNotDispatch    bool                 `json:"must_not_dispatch"`
	MustBindEvidence   []string             `json:"must_bind_evidence,omitempty"`
}

// DefaultNegativeBoundaryVectors returns the P0/P1 negative gates identified by
// the May 2026 competitive implementation plan.
func DefaultNegativeBoundaryVectors() []NegativeBoundaryVector {
	return []NegativeBoundaryVector{
		{
			ID:                 "policy-not-ready",
			Category:           "policy",
			Trigger:            "policy bundle absent or not initialized at the PEP",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonNoPolicy,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"policy_epoch", "receipt_id"},
		},
		{
			ID:                 "stale-policy-bundle",
			Category:           "policy",
			Trigger:            "policy bundle epoch is older than the configured freshness window",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonPDPError,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"policy_epoch", "bundle_hash"},
		},
		{
			ID:                 "stale-rebac-tuples",
			Category:           "authorization",
			Trigger:            "relationship snapshot token is stale or cannot be proven current",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonPDPError,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"authz_snapshot_hash"},
		},
		{
			ID:                 "mcp-tool-list-call-mismatch",
			Category:           "mcp",
			Trigger:            "tools/call references a tool not present in the filtered tools/list view",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonSchemaViolation,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"mcp_server_id", "tool_scope_hash"},
		},
		{
			ID:                 "direct-upstream-bypass",
			Category:           "boundary",
			Trigger:            "a client attempts direct upstream dispatch without a HELM boundary record",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonProvenance,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"direct_dispatch_seen"},
		},
		{
			ID:                 "pdp-outage",
			Category:           "policy",
			Trigger:            "PDP or policy-engine dependency cannot answer the decision",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonPDPError,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"policy_epoch", "receipt_id"},
		},
		{
			ID:                 "missing-credentials",
			Category:           "identity",
			Trigger:            "tool call requires credentials that are missing or unavailable to the current identity",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonIdentityIsolationViolation,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"actor_id", "credential_ref"},
		},
		{
			ID:                 "malformed-tool-args",
			Category:           "schema",
			Trigger:            "tool arguments fail canonical schema validation before execution",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonSchemaViolation,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"args_hash", "schema_hash"},
		},
		{
			ID:                 "schema-drift",
			Category:           "schema",
			Trigger:            "registered connector/tool contract hash differs from the pinned contract",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonSchemaViolation,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"schema_hash", "pinned_schema_hash"},
		},
		{
			ID:                 "sandbox-overgrant",
			Category:           "sandbox",
			Trigger:            "requested sandbox filesystem, environment, or network grant exceeds policy",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonSandboxViolation,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"sandbox_grant_hash"},
		},
		{
			ID:                 "blocked-egress",
			Category:           "sandbox",
			Trigger:            "execution attempts network egress outside declared grants",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonDataEgressBlocked,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"sandbox_grant_hash", "network_log_ref"},
		},
		{
			ID:                 "deny-receipt-emission",
			Category:           "receipt",
			Trigger:            "a denied decision path fails to produce an offline-verifiable receipt",
			ExpectedVerdict:    contracts.VerdictDeny,
			ExpectedReasonCode: contracts.ReasonVerification,
			MustEmitReceipt:    true,
			MustNotDispatch:    true,
			MustBindEvidence:   []string{"receipt_id", "record_hash"},
		},
	}
}
