package conform

// Reason codes are stable identifiers per §6.2.
// They MUST NOT change between releases.
const (
	// --- Build & Identity ---
	ReasonBuildIdentityMissing = "BUILD_IDENTITY_MISSING"
	ReasonTrustRootsMissing    = "TRUST_ROOTS_MISSING" // G0: signing keys not verifiable

	// --- Receipt chain ---
	ReasonReceiptChainBroken        = "RECEIPT_CHAIN_BROKEN"
	ReasonReceiptDAGBroken          = "RECEIPT_DAG_BROKEN" // DAG parent hash unresolvable
	ReasonSignatureInvalid          = "SIGNATURE_INVALID"
	ReasonPayloadCommitmentMismatch = "PAYLOAD_COMMITMENT_MISMATCH"

	// --- Receipt emission ---
	ReasonReceiptEmissionPanic = "RECEIPT_EMISSION_PANIC" // kernel panic: receipts cannot be emitted

	// --- Replay ---
	ReasonReplayHashDivergence = "REPLAY_HASH_DIVERGENCE"
	ReasonReplayTapeMiss       = "REPLAY_TAPE_MISS"

	// --- Tape ---
	ReasonTapeResidencyViolation = "TAPE_RESIDENCY_VIOLATION" // taped payload violates jurisdiction/data handling

	// --- Policy ---
	ReasonPolicyDecisionMissing  = "POLICY_DECISION_MISSING"
	ReasonSchemaValidationFailed = "SCHEMA_VALIDATION_FAILED"

	// --- Budget ---
	ReasonBudgetExhausted = "BUDGET_EXHAUSTED"

	// --- Containment ---
	ReasonContainmentNotTriggered = "CONTAINMENT_NOT_TRIGGERED"

	// --- Taint ---
	ReasonTaintFlowViolation = "TAINT_FLOW_VIOLATION"

	// --- Tenant Isolation ---
	ReasonTenantIsolationViolation = "TENANT_ISOLATION_VIOLATION" // cross-tenant access detected
	ReasonTenantIDMissing          = "TENANT_ID_MISSING"          // receipt/evidence lacks tenant_id

	// --- Envelope Binding ---
	ReasonEnvelopeNotBound        = "ENVELOPE_NOT_BOUND"         // effect without active envelope
	ReasonEnvelopeNotEnforced     = "ENVELOPE_NOT_ENFORCED"      // envelope constraints not checked
	ReasonEnvelopeDenialNoReceipt = "ENVELOPE_DENIAL_NO_RECEIPT" // denial without receipt

	// --- Proxy Governance ---
	ReasonProxyToolAllowed     = "PROXY_TOOL_ALLOWED"     // tool call passed governance
	ReasonProxyToolDenied      = "PROXY_TOOL_DENIED"      // tool call failed governance
	ReasonProxyBudgetExhausted = "PROXY_BUDGET_EXHAUSTED" // budget limit hit via proxy
	ReasonProxyIterationLimit  = "PROXY_ITERATION_LIMIT"  // max iterations reached
	ReasonProxyWallclockLimit  = "PROXY_WALLCLOCK_LIMIT"  // session wallclock exceeded

	// --- Operations (v1.1.0) ---
	ReasonSystemFrozen = "SYSTEM_FROZEN" // global freeze active

	// --- Environment (v1.1.0) ---
	ReasonContextMismatch = "CONTEXT_MISMATCH" // env fingerprint mismatch

	// --- Network (v1.1.0) ---
	ReasonDataEgressBlocked = "DATA_EGRESS_BLOCKED" // egress to unauthorized destination

	// --- Identity (v1.1.0) ---
	ReasonIdentityIsolationViolation = "IDENTITY_ISOLATION_VIOLATION" // agent credential reuse

	// --- Approval (v1.1.0) ---
	ReasonApprovalRequired = "APPROVAL_REQUIRED" // effect requires human approval
	ReasonApprovalTimeout  = "APPROVAL_TIMEOUT"  // approval not received in time

	// --- Delegation (v1.3.0) ---
	ReasonDelegationInvalid        = "DELEGATION_INVALID"         // invalid/expired delegation session
	ReasonDelegationScopeViolation = "DELEGATION_SCOPE_VIOLATION" // delegate exceeded session scope

	// --- Threat Signal (v1.2.0) ---
	ReasonTaintedInputDeny           = "TAINTED_INPUT_HIGH_RISK_DENY"   // high-risk effect from tainted source
	ReasonPromptInjectionDetected    = "PROMPT_INJECTION_DETECTED"      // prompt injection pattern found
	ReasonUnicodeObfuscationDetected = "UNICODE_OBFUSCATION_DETECTED"   // Unicode obfuscation detected
	ReasonTaintedCredentialDeny      = "TAINTED_CREDENTIAL_ACCESS_DENY" // credential access from tainted source
	ReasonTaintedPublishDeny         = "TAINTED_SOFTWARE_PUBLISH_DENY"  // software publish from tainted source
	ReasonTaintedInvokeDeny          = "TAINTED_PRIVILEGED_INVOKE_DENY" // privileged invoke from tainted source
	ReasonTaintedEgressDeny          = "TAINTED_DATA_EGRESS_DENY"       // data egress from tainted source
	ReasonTaintedEscalate            = "TAINTED_HIGH_RISK_ESCALATE"     // high-risk effect requires approval

	// --- L3 Conformance (v1.4.0) ---
	ReasonSignedEvidencePackInvalid    = "SIGNED_EVIDENCE_PACK_INVALID"     // evidence pack signature invalid or missing
	ReasonSignedEvidencePackUnsigned   = "SIGNED_EVIDENCE_PACK_UNSIGNED"    // evidence pack lacks cryptographic signature
	ReasonGovernanceChainBroken        = "GOVERNANCE_CHAIN_BROKEN"          // governance decision chain hash mismatch
	ReasonGovernanceChainMissing       = "GOVERNANCE_CHAIN_MISSING"         // no governance chain found
	ReasonDelegationSessionProofMissing = "DELEGATION_SESSION_PROOF_MISSING" // delegation session lacks proof
	ReasonDelegationSessionExpired     = "DELEGATION_SESSION_EXPIRED"       // delegation session past TTL
	ReasonDelegationScopeExceeded      = "DELEGATION_SCOPE_EXCEEDED"        // delegation exceeded granted scope
	ReasonMultiPartyQuorumNotMet       = "MULTI_PARTY_QUORUM_NOT_MET"       // multi-party attestation quorum missing
	ReasonMultiPartySignerDuplicate    = "MULTI_PARTY_SIGNER_DUPLICATE"     // duplicate signer in attestation set
	ReasonMultiPartySignerUnauthorized = "MULTI_PARTY_SIGNER_UNAUTHORIZED"  // signer not in authorized set
)

// AllReasonCodes returns the full set of normative reason codes.
func AllReasonCodes() []string {
	return []string{
		ReasonBuildIdentityMissing,
		ReasonTrustRootsMissing,
		ReasonReceiptChainBroken,
		ReasonReceiptDAGBroken,
		ReasonSignatureInvalid,
		ReasonPayloadCommitmentMismatch,
		ReasonReceiptEmissionPanic,
		ReasonReplayHashDivergence,
		ReasonReplayTapeMiss,
		ReasonTapeResidencyViolation,
		ReasonPolicyDecisionMissing,
		ReasonSchemaValidationFailed,
		ReasonBudgetExhausted,
		ReasonContainmentNotTriggered,
		ReasonTaintFlowViolation,
		ReasonTenantIsolationViolation,
		ReasonTenantIDMissing,
		ReasonEnvelopeNotBound,
		ReasonEnvelopeNotEnforced,
		ReasonEnvelopeDenialNoReceipt,
		ReasonProxyToolAllowed,
		ReasonProxyToolDenied,
		ReasonProxyBudgetExhausted,
		ReasonProxyIterationLimit,
		ReasonProxyWallclockLimit,
		ReasonSystemFrozen,
		ReasonContextMismatch,
		ReasonDataEgressBlocked,
		ReasonIdentityIsolationViolation,
		ReasonApprovalRequired,
		ReasonApprovalTimeout,
		ReasonDelegationInvalid,
		ReasonDelegationScopeViolation,
		ReasonTaintedInputDeny,
		ReasonPromptInjectionDetected,
		ReasonUnicodeObfuscationDetected,
		ReasonTaintedCredentialDeny,
		ReasonTaintedPublishDeny,
		ReasonTaintedInvokeDeny,
		ReasonTaintedEgressDeny,
		ReasonTaintedEscalate,
		ReasonSignedEvidencePackInvalid,
		ReasonSignedEvidencePackUnsigned,
		ReasonGovernanceChainBroken,
		ReasonGovernanceChainMissing,
		ReasonDelegationSessionProofMissing,
		ReasonDelegationSessionExpired,
		ReasonDelegationScopeExceeded,
		ReasonMultiPartyQuorumNotMet,
		ReasonMultiPartySignerDuplicate,
		ReasonMultiPartySignerUnauthorized,
	}
}
