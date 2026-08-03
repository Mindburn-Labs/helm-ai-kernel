package events

import (
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// The eight lifecycle event types of the pilot business-telemetry contract
// (§5). Together they let one governed request be explained end to end by
// querying events joined on correlation_id — the operator flow is an
// aggregate panel drilling into an event query, never a per-request metric
// label (§6.1).
//
// Only the first two are written from scratch. The rest are projections of
// structs the kernel already produces, so the event stream cannot disagree
// with the receipts and decisions it exists to explain.
const (
	RequestReceived     = "helm.request.received.v1"
	RequestClassified   = "helm.request.classified.v1"
	PolicyApplied       = "helm.policy.applied.v1"
	DecisionMade        = "helm.decision.made.v1"
	EscalationTriggered = "helm.escalation.triggered.v1"
	DispatchCompleted   = "helm.dispatch.completed.v1"
	RequestFailed       = "helm.request.failed.v1"
	RequestCompleted    = "helm.request.completed.v1"
)

// LifecycleEventTypes returns the eight types in lifecycle order.
func LifecycleEventTypes() []string {
	return []string{
		RequestReceived,
		RequestClassified,
		PolicyApplied,
		DecisionMade,
		EscalationTriggered,
		DispatchCompleted,
		RequestFailed,
		RequestCompleted,
	}
}

// terminalEventTypes are the two ways a request can end (§5.1).
func isTerminal(eventType string) bool {
	return eventType == RequestFailed || eventType == RequestCompleted
}

// LifecycleEvent is one envelope plus the key fields of its type. Fields are a
// projection of existing structs, never a second source of truth.
type LifecycleEvent struct {
	Meta   EventMeta      `json:"meta"`
	Fields map[string]any `json:"fields,omitempty"`
}

func newEvent(meta EventMeta, eventType string, fields map[string]any) LifecycleEvent {
	meta.EventType = eventType
	if meta.SchemaVersion == 0 {
		meta.SchemaVersion = EventSchemaVersion
	}
	return LifecycleEvent{Meta: meta, Fields: fields}
}

// NewRequestReceived emits #1 at ingress. Every request must produce exactly
// one of these; it is what makes a missing terminal event detectable.
func NewRequestReceived(meta EventMeta, action, resource string) LifecycleEvent {
	return newEvent(meta, RequestReceived, map[string]any{
		"action":   action,
		"resource": resource,
	})
}

// NewRequestClassified emits #2 once the PEP has classified the request's
// effect. Written from scratch: no existing struct records the classification
// as a distinct step.
func NewRequestClassified(meta EventMeta, effectClass, riskTier string) LifecycleEvent {
	return newEvent(meta, RequestClassified, map[string]any{
		"effect_class": effectClass,
		"risk_tier":    riskTier,
	})
}

// NewPolicyApplied projects #3 from the policy identity already bound into the
// decision, plus the rules the evidence recorded as fired.
func NewPolicyApplied(meta EventMeta, decision contracts.DecisionRecord, rulesFired []string) LifecycleEvent {
	return newEvent(meta, PolicyApplied, map[string]any{
		"decision_id":         decision.ID,
		"policy_version":      decision.PolicyVersion,
		"policy_content_hash": decision.PolicyContentHash,
		"policy_epoch":        decision.PolicyEpoch,
		"rules_fired":         rulesFired,
	})
}

// NewDecisionMade projects #4 from the signed decision. The verdict here is
// the decision's verdict — inventing one would let the event stream disagree
// with the receipt it explains.
func NewDecisionMade(meta EventMeta, decision contracts.DecisionRecord) LifecycleEvent {
	return newEvent(meta, DecisionMade, map[string]any{
		"decision_id":          decision.ID,
		"verdict":              decision.Verdict,
		"reason_code":          decision.ReasonCode,
		"action":               decision.Action,
		"resource":             decision.Resource,
		"subject_id":           decision.SubjectID,
		"policy_decision_hash": decision.PolicyDecisionHash,
	})
}

// ErrNotEscalation reports a decision that cannot be projected into #5.
var ErrNotEscalation = errors.New("decision verdict is not ESCALATE")

// NewEscalationTriggered projects #5 from an ESCALATE verdict. Alone among the
// eight it has a precondition its argument can violate: the others project
// whatever the struct holds and so cannot be wrong, but an escalation event
// built from an ALLOW asserts a human approval step that never happened. That
// is the one way a projection could still disagree with the decision it
// explains, so it returns an error rather than emitting the wrong event.
func NewEscalationTriggered(meta EventMeta, decision contracts.DecisionRecord) (LifecycleEvent, error) {
	if decision.Verdict != string(contracts.VerdictEscalate) {
		return LifecycleEvent{}, fmt.Errorf(
			"%w: decision %s has verdict %q", ErrNotEscalation, decision.ID, decision.Verdict,
		)
	}

	return newEvent(meta, EscalationTriggered, map[string]any{
		"decision_id": decision.ID,
		"reason_code": decision.ReasonCode,
		"action":      decision.Action,
		"resource":    decision.Resource,
	}), nil
}

// NewDispatchCompleted projects #6 from the receipt the PEP wrote.
func NewDispatchCompleted(meta EventMeta, receipt contracts.Receipt, intentHash string) LifecycleEvent {
	return newEvent(meta, DispatchCompleted, map[string]any{
		"receipt_id":  receipt.ID,
		"status":      receipt.Status,
		"intent_hash": intentHash,
	})
}

// NewRequestFailed projects #7 from a denied or failed attempt. It is one of
// the two terminal events.
//
// It takes no free-text reason on purpose. §6 prohibits prose in exported
// events alongside the request-scoped values it keeps out of metric labels:
// this stream is retained and shipped off-box, and prose is where customer data
// rides along. reasonCode is the registry code every consumer keys on anyway —
// the same swap HELM-303 made in the signing preimage. Prose describing one
// failure belongs in the evidence pack, which is not exported.
func NewRequestFailed(meta EventMeta, reasonCode string, retryNumber int) LifecycleEvent {
	return newEvent(meta, RequestFailed, map[string]any{
		"reason_code":  reasonCode,
		"retry_number": retryNumber,
	})
}

// NewRequestCompleted projects #8 from the execution record, summing the PAL
// receipts' token counts so per-request cost is answerable without reading
// every receipt. The other terminal event.
func NewRequestCompleted(meta EventMeta, execution contracts.EvidencePackExecution, palReceipts []contracts.PALReceiptRef) LifecycleEvent {
	tokensIn, tokensOut := 0, 0
	for _, receipt := range palReceipts {
		tokensIn += receipt.TokensIn
		tokensOut += receipt.TokensOut
	}

	return newEvent(meta, RequestCompleted, map[string]any{
		"execution_id": execution.ExecutionID,
		"status":       execution.Status,
		"retry_count":  execution.RetryCount,
		"duration_ms":  execution.DurationMs,
		"tokens_in":    tokensIn,
		"tokens_out":   tokensOut,
	})
}

// ValidateRequestSequence enforces the completeness invariant (§5.1): every
// request emits helm.request.received.v1 and exactly one terminal event.
//
// The point is that a missing terminal is itself a signal — an unclosed
// request — rather than silence. A monitor that only counts emitted events
// cannot tell "nothing went wrong" from "the process died mid-request".
//
// All events must also share one non-empty correlation_id; a sequence spanning
// two would silently merge two requests into one story, and an empty one is
// worse: it joins nothing, so every such sequence collides with every other.
// Checking the anchor is enough — the others are required to equal it.
func ValidateRequestSequence(sequence []LifecycleEvent) error {
	if len(sequence) == 0 {
		return errors.New("empty sequence: a request must emit at least received and one terminal event")
	}

	var (
		correlationID string
		received      int
		terminals     int
	)

	for i, event := range sequence {
		if i == 0 {
			correlationID = event.Meta.CorrelationID
			if correlationID == "" {
				return errors.New("sequence has an empty correlation id: an unjoinable sequence is not a request story")
			}
		} else if event.Meta.CorrelationID != correlationID {
			return fmt.Errorf(
				"sequence spans correlation ids %q and %q: these are two requests, not one",
				correlationID, event.Meta.CorrelationID,
			)
		}

		switch {
		case event.Meta.EventType == RequestReceived:
			received++
		case isTerminal(event.Meta.EventType):
			terminals++
		}
	}

	if received != 1 {
		return fmt.Errorf("sequence has %d %s events, want exactly 1", received, RequestReceived)
	}
	if terminals != 1 {
		return fmt.Errorf(
			"sequence has %d terminal events (%s / %s), want exactly 1; an unclosed request is a signal, not silence",
			terminals, RequestCompleted, RequestFailed,
		)
	}

	return nil
}
