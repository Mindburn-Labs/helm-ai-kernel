// Package signals implements the canonical typed signal ingestion layer for HELM.
//
// Signals are the atomic units of inbound business events — email, chat, docs,
// meetings, tickets, CRM updates, approvals, and system alerts. Every signal
// is normalized into a SignalEnvelope, content-hashed, and emitted to the
// EventRepository and ProofGraph for governance and replay.
package signals

// SignalClass classifies the kind of business event represented by a signal.
type SignalClass string

const (
	SignalClassEmail       SignalClass = "EMAIL"
	SignalClassChat        SignalClass = "CHAT_MESSAGE"
	SignalClassDoc         SignalClass = "DOC_UPDATE"
	SignalClassMeeting     SignalClass = "MEETING"
	SignalClassTicket      SignalClass = "TICKET"
	SignalClassCRM         SignalClass = "CRM_UPDATE"
	SignalClassApproval    SignalClass = "APPROVAL"
	SignalClassSystemAlert SignalClass = "SYSTEM_ALERT"
)

// ValidSignalClasses returns all recognized signal classes.
func ValidSignalClasses() []SignalClass {
	return []SignalClass{
		SignalClassEmail,
		SignalClassChat,
		SignalClassDoc,
		SignalClassMeeting,
		SignalClassTicket,
		SignalClassCRM,
		SignalClassApproval,
		SignalClassSystemAlert,
	}
}

// IsValid returns true if the signal class is recognized.
func (c SignalClass) IsValid() bool {
	for _, valid := range ValidSignalClasses() {
		if c == valid {
			return true
		}
	}
	return false
}
