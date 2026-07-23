package actioninbox

import (
	"fmt"
	"strings"
	"time"
)

// DenyFeedbackSchemaVersion versions the structured denial feedback payload.
// The schema is additive: new fields may be added with omitempty; existing
// field names and meanings must never change without a version bump.
const DenyFeedbackSchemaVersion = "deny_feedback.v1"

// Denial reason codes for the actioninbox / hook UX layer. These are
// model-actionable steering codes; they are deliberately namespaced (INBOX_*)
// so they cannot be confused with canonical Kernel verdict reason codes
// (contracts.CoreReasonCodes). They carry no authority: they explain and
// steer, they never permit.
const (
	// ReasonHumanRejected is a plain human rejection of an inbox item.
	ReasonHumanRejected = "INBOX_HUMAN_REJECTED"
	// ReasonCascadeRejected marks an item denied because an identical
	// same-session pending ask was rejected (cascade-reject).
	ReasonCascadeRejected = "INBOX_CASCADE_REJECTED"
	// ReasonDoomLoopDetected marks a denial forced by the doom-loop
	// circuit breaker after N identical settled/attempted tool calls.
	ReasonDoomLoopDetected = "INBOX_DOOM_LOOP_DETECTED"
	// ReasonSignerUnavailable marks a fail-closed denial emitted when the
	// local receipt signer cannot be loaded.
	ReasonSignerUnavailable = "INBOX_SIGNER_UNAVAILABLE"
	// ReasonReceiptPersistence marks a fail-closed denial emitted when the
	// decision receipt cannot be persisted.
	ReasonReceiptPersistence = "INBOX_RECEIPT_PERSISTENCE_UNAVAILABLE"
	// ReasonKernelPolicyDeny is the generic wrapper when a Kernel verdict
	// reason code has no specific steering entry.
	ReasonKernelPolicyDeny = "INBOX_KERNEL_POLICY_DENY"
)

// DenialRecord is the structured, model-actionable denial payload attached
// to an inbox item or rendered into a PreToolUse hook deny response. It is
// data, not authority: it explains a denial that already happened and steers
// the requesting agent toward self-correction or escalation.
type DenialRecord struct {
	SchemaVersion string    `json:"schema_version"`
	ReasonCode    string    `json:"reason_code"`
	Explanation   string    `json:"explanation"`
	Remediation   string    `json:"remediation,omitempty"`
	Escalation    string    `json:"escalation_route,omitempty"`
	Feedback      string    `json:"feedback,omitempty"`
	CascadedFrom  string    `json:"cascaded_from,omitempty"`
	KernelCode    string    `json:"kernel_reason_code,omitempty"`
	PrincipalID   string    `json:"principal_id,omitempty"`
	DecidedAt     time.Time `json:"decided_at"`
}

// kernelDenyGuidance maps canonical Kernel verdict reason codes to
// agent-actionable explanation, remediation, and escalation text. Unknown
// codes fall through to a fail-closed generic entry in DenyFeedbackFor.
var kernelDenyGuidance = map[string]struct {
	Explanation string
	Remediation string
	Escalation  string
}{
	"OPERATE_PERMISSIONS_EMPTY": {
		Explanation: "No operate-class permissions are granted in the active workstation policy profile, so this effect cannot be authorized.",
		Remediation: "Do not retry the same call. Rework the approach to use observe/draft-class effects (read-only commands, in-workspace drafts), or ask the operator to grant the required operate permission in the policy profile.",
		Escalation:  "Ask the human operator to update the workstation policy profile (operate.permissions) and re-run; the denial receipt is the audit anchor.",
	},
	"OPERATE_PERMISSION_NOT_GRANTED": {
		Explanation: "The active workstation policy profile does not grant the specific operate permission this effect requires.",
		Remediation: "Switch to an approach that needs only already-granted permissions, or request the specific missing permission from the operator instead of retrying.",
		Escalation:  "Ask the human operator to grant the specific permission named in the decision receipt.",
	},
	"EGRESS_ALLOWLIST_EMPTY": {
		Explanation: "The workstation egress allowlist is empty, so all network egress fails closed.",
		Remediation: "Do not retry network calls. Work offline from local state, or ask the operator to add the destination to the egress allowlist.",
		Escalation:  "Ask the human operator to add the destination host/protocol to the workstation egress allowlist.",
	},
	"EGRESS_DESTINATION_NOT_ALLOWED": {
		Explanation: "The destination is outside the workstation egress allowlist.",
		Remediation: "Use an allowlisted destination or fetch the needed data through an already-approved channel; do not probe alternate routes to the same host.",
		Escalation:  "Ask the human operator to allowlist this destination if the egress is genuinely required.",
	},
	"DRAFT_TARGET_OUTSIDE_WORKSPACE_SCOPE": {
		Explanation: "The write target is outside the configured workspace roots; drafts are confined to the workspace scope.",
		Remediation: "Retarget the write to a path inside the configured workspace roots.",
		Escalation:  "Ask the human operator to widen draft workspace roots only if the out-of-scope write is intended.",
	},
	"TAINTED_CONTEXT_REQUIRES_DENY": {
		Explanation: "The run context is tainted, and tainted context cannot authorize operate-class effects.",
		Remediation: "Stop attempting operate-class effects in this run. Request a fresh, untainted session for the operation.",
		Escalation:  "Escalate to the human operator; taint clearance is a principal decision, not an agent decision.",
	},
	"MEMORY_CLASS_DISALLOWED": {
		Explanation: "The memory class is not allowed by the workstation memory policy.",
		Remediation: "Write the information to an allowed memory class or keep it out of durable memory.",
		Escalation:  "Ask the human operator to permit the memory class in policy if retention is required.",
	},
	"MEMORY_TTL_EXCEEDS_POLICY": {
		Explanation: "The requested memory TTL exceeds the workstation policy maximum.",
		Remediation: "Retry with a TTL at or below the policy maximum.",
		Escalation:  "Ask the human operator to raise the memory TTL cap if longer retention is justified.",
	},
	"RECURRING_LOOP_MISSING_SCHEDULE": {
		Explanation: "The recurring loop registration is missing a schedule.",
		Remediation: "Re-register the loop with an explicit schedule.",
		Escalation:  "Ask the human operator if loop policy should change.",
	},
	"RECURRING_LOOP_MISSING_MAX_RUNTIME": {
		Explanation: "The recurring loop registration is missing a max runtime bound.",
		Remediation: "Re-register the loop with an explicit max runtime.",
		Escalation:  "Ask the human operator if loop policy should change.",
	},
	"RECURRING_LOOP_MISSING_TOOL_SCOPE": {
		Explanation: "The recurring loop registration is missing a tool scope.",
		Remediation: "Re-register the loop with an explicit, minimal tool scope.",
		Escalation:  "Ask the human operator if loop policy should change.",
	},
	"RECURRING_LOOP_MISSING_EXPIRATION": {
		Explanation: "The recurring loop registration is missing an expiration.",
		Remediation: "Re-register the loop with an explicit expiration time.",
		Escalation:  "Ask the human operator if loop policy should change.",
	},
}

// DenyFeedbackFor builds a model-actionable DenialRecord for a denial that
// carries the given Kernel verdict reason code. Unknown or empty codes are
// mapped to a generic fail-closed record: the agent is told not to retry and
// to escalate, never to probe.
func DenyFeedbackFor(kernelReasonCode string, decidedAt time.Time) DenialRecord {
	code := strings.TrimSpace(kernelReasonCode)
	if g, ok := kernelDenyGuidance[code]; ok {
		return DenialRecord{
			SchemaVersion: DenyFeedbackSchemaVersion,
			ReasonCode:    ReasonKernelPolicyDeny,
			KernelCode:    code,
			Explanation:   g.Explanation,
			Remediation:   g.Remediation,
			Escalation:    g.Escalation,
			DecidedAt:     decidedAt,
		}
	}
	return DenialRecord{
		SchemaVersion: DenyFeedbackSchemaVersion,
		ReasonCode:    ReasonKernelPolicyDeny,
		KernelCode:    code,
		Explanation:   "HELM denied this effect under the active policy; the specific reason code has no steering guidance.",
		Remediation:   "Do not retry the same call unchanged. Change the approach or stop.",
		Escalation:    "Escalate to the human operator with the decision receipt if you believe this denial is wrong.",
		DecidedAt:     decidedAt,
	}
}

// RenderSteeringText renders a DenialRecord as the single-string reason a
// PreToolUse hook can hand back to the agent. The format keeps the machine-
// readable code first, then explanation, remediation, and escalation, so the
// model can self-correct instead of retrying blind.
func RenderSteeringText(d DenialRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]", d.ReasonCode)
	if d.KernelCode != "" {
		fmt.Fprintf(&b, " kernel=%s", d.KernelCode)
	}
	if d.Explanation != "" {
		fmt.Fprintf(&b, " %s", d.Explanation)
	}
	if d.Feedback != "" {
		fmt.Fprintf(&b, " Operator feedback: %s", d.Feedback)
	}
	if d.Remediation != "" {
		fmt.Fprintf(&b, " Remediation: %s", d.Remediation)
	}
	if d.Escalation != "" {
		fmt.Fprintf(&b, " Escalation: %s", d.Escalation)
	}
	return b.String()
}
