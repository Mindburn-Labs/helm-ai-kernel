// Package contracts — Canonical Verdict and Reason Code Registry.
//
// Per HELM Standard v1.2 §1.2 — every governance decision MUST use these
// canonical verdict values. No other verdict strings are valid.
//
// This file is the SINGLE SOURCE OF TRUTH for verdict vocabulary.
// All kernel components (Guardian, Executor, PDP, SDK) import from here.
package contracts

// Verdict is the canonical verdict type for all HELM governance decisions.
// Wire format: JSON string field "verdict" in DecisionRecord and Receipt.
type Verdict string

const (
	// VerdictAllow indicates the effect is permitted. Decision is signed, Intent is issued.
	VerdictAllow Verdict = "ALLOW"

	// VerdictDeny indicates the effect is refused. A DenialReceipt is emitted.
	VerdictDeny Verdict = "DENY"

	// VerdictEscalate indicates the effect requires human/ceremony approval.
	VerdictEscalate Verdict = "ESCALATE"
)

// IsTerminal returns true if the verdict is a final state (not pending escalation).
func (v Verdict) IsTerminal() bool {
	return v == VerdictAllow || v == VerdictDeny
}

// ReasonCode is a typed, machine-readable reason for DENY/ESCALATE verdicts.
// These codes form a canonical registry analogous to HTTP status codes.
// Wire format: JSON string field "reason_code" in DecisionRecord.
type ReasonCode string

const (
	// ── Policy Reasons ─────────────────────────────────────
	ReasonPolicyViolation    ReasonCode = "POLICY_VIOLATION"
	ReasonNoPolicy           ReasonCode = "NO_POLICY_DEFINED"
	ReasonPRGEvalError       ReasonCode = "PRG_EVALUATION_ERROR"
	ReasonMissingRequirement ReasonCode = "MISSING_REQUIREMENT"

	// ── PDP Reasons ────────────────────────────────────────
	ReasonPDPDeny  ReasonCode = "PDP_DENY"
	ReasonPDPError ReasonCode = "PDP_ERROR"

	// ── Resource Reasons ───────────────────────────────────
	ReasonBudgetExceeded ReasonCode = "BUDGET_EXCEEDED"
	ReasonBudgetError    ReasonCode = "BUDGET_ERROR"

	// ── Envelope / Schema Reasons ──────────────────────────
	ReasonEnvelopeInvalid ReasonCode = "ENVELOPE_INVALID"
	ReasonSchemaViolation ReasonCode = "SCHEMA_VIOLATION"

	// ── Temporal Reasons ───────────────────────────────────
	ReasonTemporalIntervene ReasonCode = "TEMPORAL_INTERVENTION"
	ReasonTemporalThrottle  ReasonCode = "TEMPORAL_THROTTLE"
	ReasonSessionRiskDeny   ReasonCode = "SESSION_RISK_MEMORY_DENY"

	// ── Security Reasons ───────────────────────────────────
	ReasonSandboxViolation ReasonCode = "SANDBOX_VIOLATION"
	ReasonProvenance       ReasonCode = "PROVENANCE_FAILURE"
	ReasonVerification     ReasonCode = "VERIFICATION_FAILURE"

	// ── Tenancy / Jurisdiction Reasons ─────────────────────
	ReasonTenantIsolation ReasonCode = "TENANT_ISOLATION"
	ReasonJurisdiction    ReasonCode = "JURISDICTION_VIOLATION"

	// ── Operations / Environment / Approval Reasons ────────
	ReasonSystemFrozen               ReasonCode = "SYSTEM_FROZEN"
	ReasonContextMismatch            ReasonCode = "CONTEXT_MISMATCH"
	ReasonDataEgressBlocked          ReasonCode = "DATA_EGRESS_BLOCKED"
	ReasonIdentityIsolationViolation ReasonCode = "IDENTITY_ISOLATION_VIOLATION"
	ReasonApprovalRequired           ReasonCode = "APPROVAL_REQUIRED"
	ReasonApprovalTimeout            ReasonCode = "APPROVAL_TIMEOUT"

	// ── Delegation Reasons (v1.3) ───────────────────────────
	ReasonDelegationInvalid        ReasonCode = "DELEGATION_INVALID"
	ReasonDelegationScopeViolation ReasonCode = "DELEGATION_SCOPE_VIOLATION"

	// ── Privilege Tier Reasons ──────────────
	ReasonInsufficientPrivilege ReasonCode = "INSUFFICIENT_PRIVILEGE"

	// ── Agent Lifecycle Reasons ────────────────────────────
	ReasonAgentKilled ReasonCode = "AGENT_KILLED"

	// ── Threat Signal Reasons (v1.2) ───────────────────────
	ReasonTaintedInputDeny           ReasonCode = "TAINTED_INPUT_HIGH_RISK_DENY"
	ReasonPromptInjectionDetected    ReasonCode = "PROMPT_INJECTION_DETECTED"
	ReasonUnicodeObfuscationDetected ReasonCode = "UNICODE_OBFUSCATION_DETECTED"
	ReasonTaintedCredentialDeny      ReasonCode = "TAINTED_CREDENTIAL_ACCESS_DENY"
	ReasonTaintedPublishDeny         ReasonCode = "TAINTED_SOFTWARE_PUBLISH_DENY"
	ReasonTaintedInvokeDeny          ReasonCode = "TAINTED_PRIVILEGED_INVOKE_DENY"
	ReasonTaintedEgressDeny          ReasonCode = "TAINTED_DATA_EGRESS_DENY"
	ReasonTaintedEscalate            ReasonCode = "TAINTED_HIGH_RISK_ESCALATE"
)

// CanonicalVerdicts returns the full normative verdict vocabulary.
func CanonicalVerdicts() []Verdict {
	return []Verdict{
		VerdictAllow,
		VerdictDeny,
		VerdictEscalate,
	}
}

// CoreReasonCodes returns the full normative core reason-code registry.
func CoreReasonCodes() []ReasonCode {
	return []ReasonCode{
		ReasonPolicyViolation,
		ReasonNoPolicy,
		ReasonPRGEvalError,
		ReasonMissingRequirement,
		ReasonPDPDeny,
		ReasonPDPError,
		ReasonBudgetExceeded,
		ReasonBudgetError,
		ReasonEnvelopeInvalid,
		ReasonSchemaViolation,
		ReasonTemporalIntervene,
		ReasonTemporalThrottle,
		ReasonSessionRiskDeny,
		ReasonSandboxViolation,
		ReasonProvenance,
		ReasonVerification,
		ReasonTenantIsolation,
		ReasonJurisdiction,
		ReasonSystemFrozen,
		ReasonContextMismatch,
		ReasonDataEgressBlocked,
		ReasonIdentityIsolationViolation,
		ReasonApprovalRequired,
		ReasonApprovalTimeout,
		ReasonDelegationInvalid,
		ReasonDelegationScopeViolation,
		ReasonInsufficientPrivilege,
		ReasonAgentKilled,
		ReasonTaintedInputDeny,
		ReasonPromptInjectionDetected,
		ReasonUnicodeObfuscationDetected,
		ReasonTaintedCredentialDeny,
		ReasonTaintedPublishDeny,
		ReasonTaintedInvokeDeny,
		ReasonTaintedEgressDeny,
		ReasonTaintedEscalate,
	}
}

// IsCanonicalVerdict reports whether v is a normative verdict string.
func IsCanonicalVerdict(v string) bool {
	for _, verdict := range CanonicalVerdicts() {
		if string(verdict) == v {
			return true
		}
	}
	return false
}

// IsCanonicalReasonCode reports whether code is part of the core registry.
func IsCanonicalReasonCode(code string) bool {
	for _, reason := range CoreReasonCodes() {
		if string(reason) == code {
			return true
		}
	}
	return false
}
