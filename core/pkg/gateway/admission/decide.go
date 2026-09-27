package admission

import (
	"math"
	"slices"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// Verdict is decide's outcome.
type Verdict string

const (
	Allow    Verdict = "ALLOW"
	Deny     Verdict = "DENY"
	Escalate Verdict = "ESCALATE"
)

// Link is one mandate of the delegation chain, root first, as admission
// locked it.
type Link struct {
	Mandate mandates.Mandate
	// Condition is the mandate's compiled condition when it sets one. A
	// condition that failed to compile is nil here, and decide denies it.
	Condition *authority.Snapshot
}

// CounterState is a locked counter with the delta this request would add.
type CounterState struct {
	LimitID  string
	Limit    int64
	Used     int64
	Reserved int64
	Delta    int64
}

// Input is everything decide reads. The admission transaction supplies it;
// decide does no I/O, reads no clock and draws no randomness (R7). Now is
// the database time of the transaction.
type Input struct {
	Now             time.Time
	PrincipalID     string
	PrincipalFound  bool
	PrincipalActive bool
	Chain           []Link
	EffectType      string
	EffectTypeFound bool
	// RiskClass is the effect type row's class raised by every link's
	// RiskClasses entry for the effect type.
	RiskClass mandates.RiskClass
	Target    string
	// Args is the parsed argument object, the input.args of a condition.
	Args        map[string]any
	Quote       []Amount
	ActiveStops []string
	Counters    []CounterState
	// Approval is the recorded decision Approve re-admits with; nil on
	// Propose.
	Approval *ApprovalState
}

// ApprovalState is a recorded approval or rejection of the attempt.
type ApprovalState struct {
	ApproverID string
	Approved   bool
}

// Decision is decide's output. Reason is a registry code (§11.1).
type Decision struct {
	Verdict Verdict
	Reason  contracts.ReasonCode
}

// Decide is the pure authority function of ADR-0001 §1 step 5. Order: stops,
// principal, the chain link by link, the effect type, the amount, counters,
// then approval. Everything that can deny is checked first, so a human is
// never asked to approve what would be denied anyway.
func Decide(in Input) Decision {
	if len(in.ActiveStops) > 0 {
		return deny(contracts.ReasonEmergencyStopFenced)
	}
	if !in.PrincipalFound || !in.PrincipalActive {
		return deny(contracts.ReasonPrincipalInactive)
	}
	if len(in.Chain) == 0 {
		return deny(contracts.ReasonMandateInactive)
	}
	amount, ok := quoteTotal(in.Quote)
	for i, link := range in.Chain {
		m := link.Mandate
		if !m.Active {
			return deny(contracts.ReasonMandateInactive)
		}
		// Delegation only narrows: re-checked here, not only at creation.
		if i > 0 && m.Terms.Within(in.Chain[i-1].Mandate.Terms) != nil {
			return deny(contracts.ReasonDelegationScopeViolation)
		}
		if in.Now.Before(m.Terms.ValidFrom) || !in.Now.Before(m.Terms.ValidUntil) {
			return deny(contracts.ReasonMandateOutsideValidity)
		}
		// Every link must allow the effect type and the target.
		if !slices.Contains(m.Terms.EffectTypes, in.EffectType) {
			return deny(contracts.ReasonEffectOutOfScope)
		}
		if m.Terms.Targets != nil && !slices.Contains(m.Terms.Targets, in.Target) {
			return deny(contracts.ReasonEffectOutOfScope)
		}
		if !ok {
			return deny(contracts.ReasonArithmeticOverflow)
		}
		if m.Terms.PerCallLimit != nil && amount > *m.Terms.PerCallLimit {
			return deny(contracts.ReasonPerCallLimit)
		}
		if m.Terms.Condition != "" {
			d := authority.Decide(authority.Input{
				Action: mandates.ConditionAction,
				Attributes: map[string]any{
					"args":        in.Args,
					"target":      in.Target,
					"effect_type": in.EffectType,
				},
				Time: in.Now,
			}, link.Condition)
			if d.Verdict != contracts.VerdictAllow {
				return deny(d.ReasonCode)
			}
		}
	}
	if !in.EffectTypeFound {
		return deny(contracts.ReasonEffectOutOfScope)
	}
	for _, c := range in.Counters {
		total, ok := add3(c.Used, c.Reserved, c.Delta)
		if !ok {
			return deny(contracts.ReasonArithmeticOverflow)
		}
		if total > c.Limit {
			return deny(contracts.ReasonBudgetExceeded)
		}
	}
	if needsApproval(in, amount) {
		switch {
		case in.Approval == nil:
			return Decision{Verdict: Escalate, Reason: contracts.ReasonApprovalRequired}
		case in.Approval.ApproverID == in.PrincipalID:
			// A backstop: Approve refuses self-approval before recording it.
			return deny(contracts.ReasonApproverNotDistinct)
		case !in.Approval.Approved:
			return deny(contracts.ReasonApprovalRejected)
		}
	}
	return Decision{Verdict: Allow}
}

// needsApproval: a high or irreversible risk class, a link that requires
// approval for the effect type, or an amount at or above any link's approval
// threshold (ADR-0001 §4, HELM-750 terms).
func needsApproval(in Input, amount int64) bool {
	if in.RiskClass == mandates.RiskHigh || in.RiskClass == mandates.RiskIrreversible {
		return true
	}
	for _, link := range in.Chain {
		if slices.Contains(link.Mandate.Terms.ApprovalRequired, in.EffectType) {
			return true
		}
		if t := link.Mandate.Terms.ApprovalThreshold; t != nil && amount >= *t {
			return true
		}
	}
	return false
}

func deny(reason contracts.ReasonCode) Decision {
	return Decision{Verdict: Deny, Reason: reason}
}

// quoteTotal sums the quote, overflow-checked.
func quoteTotal(quote []Amount) (int64, bool) {
	var total int64
	for _, q := range quote {
		if q.Amount < 0 || total > math.MaxInt64-q.Amount {
			return 0, false
		}
		total += q.Amount
	}
	return total, true
}

func add3(a, b, c int64) (int64, bool) {
	if a < 0 || b < 0 || c < 0 || a > math.MaxInt64-b {
		return 0, false
	}
	s := a + b
	if s > math.MaxInt64-c {
		return 0, false
	}
	return s + c, true
}
