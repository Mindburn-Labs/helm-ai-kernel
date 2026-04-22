package attention

// EscalationHint provides routing guidance when a signal's attention score
// exceeds the escalation threshold. It does not trigger escalation itself —
// the surface layer uses this hint to decide presentation and notification.
type EscalationHint struct {
	// Reason explains why escalation was suggested.
	Reason string `json:"reason"`

	// TargetRole is the recommended approver or responder role.
	TargetRole string `json:"target_role"`

	// Urgency classifies the escalation urgency.
	Urgency string `json:"urgency"`
}

// Urgency levels for escalation hints.
const (
	UrgencyLow       = "low"
	UrgencyMedium    = "medium"
	UrgencyHigh      = "high"
	UrgencyImmediate = "immediate"
)

// escalationThreshold is the score above which an escalation hint is generated.
const escalationThreshold = 0.8

// ShouldEscalate evaluates whether the given score warrants an escalation hint.
// Returns nil if the score is at or below the threshold.
func ShouldEscalate(score float64) *EscalationHint {
	if score <= escalationThreshold {
		return nil
	}

	urgency := UrgencyHigh
	if score > 0.95 {
		urgency = UrgencyImmediate
	}

	return &EscalationHint{
		Reason:     "attention score exceeds escalation threshold",
		TargetRole: "operator",
		Urgency:    urgency,
	}
}
