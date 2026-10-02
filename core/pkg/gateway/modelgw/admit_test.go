package modelgw

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

const attemptID = "01a0f278-0000-7000-8000-0000000000aa"

// admitting runs admitAndClaim against a scripted ledger.
func admitting(t *testing.T, l *stubLedger) (*admission.ModelCallClaim, *replayed, *apiError, *pending) {
	t.Helper()
	gw := &Gateway{Config: testConfig(t, "http://127.0.0.1:9", "http://127.0.0.1:9/v1", "http://127.0.0.1:9/v1"), Ledger: l}
	p := &pending{caller: admission.Caller{TenantID: "t", WorkspaceID: "w", PrincipalID: "agt:seat-1"}, scope: "ep-1", digest: strings.Repeat("ab", 32),
		route: mustRoute(t, routeSonnet), caseID: "c", args: []byte(`{}`), call: &call{API: "anthropic-messages", Body: []byte(`{}`), MaxOutputTokens: 100}, quote: []admission.Amount{{Unit: "usd_micros", Amount: 10}}}
	h := &handler{g: gw, l: Listener{Name: "test"}}
	claim, replay, aerr := h.admitAndClaim(context.Background(), p)
	return claim, replay, aerr, p
}

func attemptIn(state, outcome, reason string) admission.Attempt {
	return admission.Attempt{ID: attemptID, State: state, Outcome: outcome, ReasonCode: reason}
}

func claimed() *admission.ModelCallClaim {
	return &admission.ModelCallClaim{TenantID: "t", WorkspaceID: "w", AttemptID: attemptID, ClaimID: "c1", Route: routeSonnet, HeldMicros: 10}
}

// script returns a ledger whose Propose answers each key in turn.
func script(t *testing.T, answers ...admission.Attempt) (*stubLedger, *[]bool) {
	t.Helper()
	next, existing := 0, []bool{}
	l := &stubLedger{t: t}
	l.OnPropose = func(_ admission.Caller, in admission.ProposeInput) (admission.Attempt, bool, error) {
		if next >= len(answers) {
			t.Fatalf("Propose called %d times; scripted %d (last key %s)", next+1, len(answers), in.IdempotencyKey)
		}
		a := answers[next]
		next++
		// Everything but the first answer, or a state that has not run yet,
		// is an attempt the key already named.
		e := a.State != "" && (a.Version > 0)
		existing = append(existing, e)
		return a, e, nil
	}
	return l, &existing
}

func existingAttempt(state, outcome, reason string) admission.Attempt {
	a := attemptIn(state, outcome, reason)
	a.Version = 1 // marks it as one the key already named (see script)
	return a
}

func keys(l *stubLedger) []string {
	var out []string
	for _, in := range l.proposed {
		out = append(out, in.IdempotencyKey[strings.LastIndex(in.IdempotencyKey, ":")+1:])
	}
	return out
}

func TestAnAdmittedRequestThatWasNeverClaimedIsClaimedNow(t *testing.T) {
	l, _ := script(t, existingAttempt("ADMITTED", "", ""))
	l.OnClaim = func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
		return claimed(), attemptIn("DISPATCHING", "", ""), nil
	}
	claim, replay, aerr, _ := admitting(t, l)
	if aerr != nil || replay != nil || claim == nil || len(l.proposed) != 1 || len(l.cancels) != 0 {
		t.Fatalf("claim %v replay %v err %v, %d proposals", claim, replay, aerr, len(l.proposed))
	}
}

func TestAnAttemptInFlightIsAConflictNotASecondCall(t *testing.T) {
	for _, state := range []string{"DISPATCHING", "DISPATCHED"} {
		l, _ := script(t, existingAttempt(state, "", ""))
		_, _, aerr, _ := admitting(t, l)
		if aerr == nil || aerr.Status != 409 || aerr.Code != "request_in_flight" || aerr.AttemptID != attemptID {
			t.Fatalf("%s: %+v", state, aerr)
		}
	}
	// A concurrent request wins the claim: the loser sees the attempt claimed.
	l, _ := script(t, attemptIn("ADMITTED", "", ""))
	l.OnClaim = func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
		return nil, attemptIn("DISPATCHING", "", ""), nil
	}
	if _, _, aerr, _ := admitting(t, l); aerr == nil || aerr.Status != 409 {
		t.Fatalf("a lost claim: %+v", aerr)
	}
}

func TestAStoredAnswerIsReplayedAndAMissingOneIsNotInvented(t *testing.T) {
	for _, state := range []string{"SETTLED", "OBSERVED", "RECONCILED"} {
		l, _ := script(t, existingAttempt(state, "SUCCEEDED", ""))
		l.OnReplay = func(admission.Caller, string) (*admission.ModelCallReplay, error) {
			return &admission.ModelCallReplay{StatusCode: 200, Body: []byte("stored")}, nil
		}
		claim, replay, aerr, _ := admitting(t, l)
		if aerr != nil || claim != nil || replay == nil || string(replay.Body) != "stored" || replay.AttemptID != attemptID || len(l.proposed) != 1 {
			t.Fatalf("%s: %v %v %v", state, claim, replay, aerr)
		}
	}
	// Succeeded, but the stored response is gone (too large, or expired): the
	// request is paid for again, under the next key.
	l, _ := script(t, existingAttempt("SETTLED", "SUCCEEDED", ""), attemptIn("ADMITTED", "", ""))
	l.OnReplay = func(admission.Caller, string) (*admission.ModelCallReplay, error) { return nil, nil }
	l.OnClaim = func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
		return claimed(), attemptIn("DISPATCHING", "", ""), nil
	}
	if claim, replay, aerr, _ := admitting(t, l); aerr != nil || replay != nil || claim == nil {
		t.Fatalf("no stored response: %v %v %v", claim, replay, aerr)
	}
	if got := keys(l); len(got) != 2 || got[0] != "0" || got[1] != "1" {
		t.Fatalf("keys = %v", got)
	}
}

func TestAnEarlierAttemptWithNoReusableAnswerTakesTheNextKey(t *testing.T) {
	for _, test := range []struct {
		name  string
		first admission.Attempt
	}{
		{"denied", existingAttempt("DENIED", "", string(contracts.ReasonBudgetExceeded))},
		{"cancelled", existingAttempt("CANCELLED", "", "")},
		{"expired", existingAttempt("EXPIRED", "", "")},
		{"failed", existingAttempt("OBSERVED", "FAILED", string(contracts.ReasonProviderError))},
		{"unknown", existingAttempt("UNKNOWN", "", string(contracts.ReasonProviderError))},
		{"handed to a human", existingAttempt("ESCALATED_TO_HUMAN", "", "")},
		{"reconciled failed", existingAttempt("RECONCILED", "FAILED", "")},
	} {
		l, _ := script(t, test.first, attemptIn("ADMITTED", "", ""))
		l.OnClaim = func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
			return claimed(), attemptIn("DISPATCHING", "", ""), nil
		}
		if claim, _, aerr, _ := admitting(t, l); aerr != nil || claim == nil {
			t.Fatalf("%s: %v %v", test.name, claim, aerr)
		}
		if got := keys(l); len(got) != 2 || got[1] != "1" {
			t.Fatalf("%s: keys = %v", test.name, got)
		}
	}
	// An escalation left by a handler that died is cancelled first.
	l, _ := script(t, existingAttempt("ESCALATED", "", ""), attemptIn("ADMITTED", "", ""))
	l.OnCancel = func(admission.Caller, string) (admission.Attempt, bool, error) {
		return attemptIn("CANCELLED", "", ""), false, nil
	}
	l.OnClaim = func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
		return claimed(), attemptIn("DISPATCHING", "", ""), nil
	}
	if claim, _, aerr, _ := admitting(t, l); aerr != nil || claim == nil || len(l.cancels) != 1 {
		t.Fatalf("a stale escalation: %v %v %d cancels", claim, aerr, len(l.cancels))
	}
}

func TestAKeyUsedByADifferentRequestTakesTheNextKey(t *testing.T) {
	calls := 0
	l := &stubLedger{t: t}
	l.OnPropose = func(admission.Caller, admission.ProposeInput) (admission.Attempt, bool, error) {
		calls++
		if calls == 1 {
			return admission.Attempt{}, false, &admission.Error{Code: admission.CodeAlreadyExists, Reason: contracts.ReasonIdempotencyConflict, Message: "the idempotency key was used with a different request"}
		}
		return attemptIn("ADMITTED", "", ""), false, nil
	}
	l.OnClaim = func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
		return claimed(), attemptIn("DISPATCHING", "", ""), nil
	}
	if claim, _, aerr, _ := admitting(t, l); aerr != nil || claim == nil {
		t.Fatalf("%v %v", claim, aerr)
	}
	if got := keys(l); len(got) != 2 || got[0] != "0" || got[1] != "1" {
		t.Fatalf("keys = %v", got)
	}
}

func TestAChainThatGainedASummedUnitIsPricedAgainOnce(t *testing.T) {
	grantCalls := 0
	l := &stubLedger{t: t}
	l.OnGrants = func(admission.Caller) (admission.Grants, error) {
		grantCalls++
		return admission.Grants{PrincipalKind: "agent", PrincipalActive: true, SumUnits: []string{"tokens", "usd_micros"},
			Leaves: []admission.LeafGrant{{MandateID: "m", Active: true, AnyTarget: true}}}, nil
	}
	l.OnPropose = func(_ admission.Caller, in admission.ProposeInput) (admission.Attempt, bool, error) {
		if len(in.Quote) == 1 { // priced before the limit existed
			return admission.Attempt{}, false, &admission.Error{Code: admission.CodeInvalidArgument, Reason: contracts.ReasonSchemaViolation,
				Message: `a sum limit counts "tokens", and the quote carries no amount for it`}
		}
		return attemptIn("ADMITTED", "", ""), false, nil
	}
	l.OnClaim = func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
		return claimed(), attemptIn("DISPATCHING", "", ""), nil
	}
	claim, _, aerr, _ := admitting(t, l)
	if aerr != nil || claim == nil || grantCalls != 1 || len(l.proposed) != 2 || len(l.proposed[1].Quote) != 2 {
		t.Fatalf("%v %v grants %d proposals %d", claim, aerr, grantCalls, len(l.proposed))
	}
	// The same refusal twice is the ledger's answer: 4xx, not a loop.
	l2 := &stubLedger{t: t, OnGrants: l.OnGrants}
	l2.OnPropose = func(admission.Caller, admission.ProposeInput) (admission.Attempt, bool, error) {
		return admission.Attempt{}, false, &admission.Error{Code: admission.CodeInvalidArgument, Reason: contracts.ReasonSchemaViolation,
			Message: `a sum limit counts "tokens", and the quote carries no amount for it`}
	}
	if _, _, aerr, _ := admitting(t, l2); aerr == nil || aerr.Status != 500 || len(l2.proposed) != 2 {
		t.Fatalf("a persistent refusal: %+v after %d proposals", aerr, len(l2.proposed))
	}
}

func TestADenialAnEscalationAndALedgerFailureEachHaveTheirAnswer(t *testing.T) {
	// A fresh DENIED: 403 with the registry reason and the attempt.
	l, _ := script(t, attemptIn("DENIED", "", string(contracts.ReasonPerCallLimit)))
	_, _, aerr, _ := admitting(t, l)
	if aerr == nil || aerr.Status != 403 || aerr.Reason != contracts.ReasonPerCallLimit || aerr.AttemptID != attemptID || !strings.Contains(aerr.Message, "per-call limit") {
		t.Fatalf("denial: %+v", aerr)
	}
	// A fresh ESCALATED: cancelled, so nothing waits on an approver.
	l, _ = script(t, attemptIn("ESCALATED", "", string(contracts.ReasonApprovalRequired)))
	l.OnCancel = func(admission.Caller, string) (admission.Attempt, bool, error) {
		return attemptIn("CANCELLED", "", ""), false, nil
	}
	_, _, aerr, _ = admitting(t, l)
	if aerr == nil || aerr.Status != 403 || aerr.Reason != contracts.ReasonApprovalRequired || len(l.cancels) != 1 {
		t.Fatalf("escalation: %+v", aerr)
	}
	// A cancel that fails is a ledger failure, not a silent hold.
	l, _ = script(t, attemptIn("ESCALATED", "", ""))
	l.OnCancel = func(admission.Caller, string) (admission.Attempt, bool, error) {
		return admission.Attempt{}, false, errors.New("db down")
	}
	if _, _, aerr, _ = admitting(t, l); aerr == nil || aerr.Status != 503 {
		t.Fatalf("a failed cancel: %+v", aerr)
	}
	// A refusal of the request by admission: 403 for permission, with its reason.
	l = &stubLedger{t: t, OnPropose: func(admission.Caller, admission.ProposeInput) (admission.Attempt, bool, error) {
		return admission.Attempt{}, false, &admission.Error{Code: admission.CodePermissionDenied, Reason: contracts.ReasonTenantIsolation, Message: "the token's tenant has no authority rows in this gateway"}
	}}
	if _, _, aerr, _ = admitting(t, l); aerr == nil || aerr.Status != 403 || aerr.Reason != contracts.ReasonTenantIsolation {
		t.Fatalf("a tenant with no rows: %+v", aerr)
	}
	// A database failure is 503, retryable, and never a 4xx the caller acts on.
	l = &stubLedger{t: t, OnPropose: func(admission.Caller, admission.ProposeInput) (admission.Attempt, bool, error) {
		return admission.Attempt{}, false, errors.New("connection refused")
	}}
	if _, _, aerr, _ = admitting(t, l); aerr == nil || aerr.Status != 503 || strings.Contains(aerr.Message, "refused") {
		t.Fatalf("a database failure: %+v", aerr)
	}
}

func TestARefusedClaimIsRetriedOnlyWhenAuthorityMoved(t *testing.T) {
	refuse := func(reason contracts.ReasonCode) func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
		return func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
			return nil, attemptIn("CANCELLED", "", string(reason)), nil
		}
	}
	// A stop, or a mandate outside its window, is the answer.
	for _, reason := range []contracts.ReasonCode{contracts.ReasonEmergencyStopFenced, contracts.ReasonMandateOutsideValidity} {
		l, _ := script(t, attemptIn("ADMITTED", "", ""))
		l.OnClaim = refuse(reason)
		_, _, aerr, _ := admitting(t, l)
		if aerr == nil || aerr.Status != 403 || aerr.Reason != reason || len(l.proposed) != 1 {
			t.Fatalf("%s: %+v after %d proposals", reason, aerr, len(l.proposed))
		}
	}
	// Authority changed between the proposal and the claim: propose again, twice
	// at most, then say so.
	l, _ := script(t, attemptIn("ADMITTED", "", ""), attemptIn("ADMITTED", "", ""), attemptIn("ADMITTED", "", ""), attemptIn("ADMITTED", "", ""))
	l.OnClaim = refuse(contracts.ReasonAuthorityChanged)
	_, _, aerr, _ := admitting(t, l)
	if aerr == nil || aerr.Status != 503 || aerr.Code != "authority_changing" || len(l.proposed) != 3 {
		t.Fatalf("a permit that keeps going stale: %+v after %d proposals", aerr, len(l.proposed))
	}
	// And it goes through when the second try holds.
	tries := 0
	l, _ = script(t, attemptIn("ADMITTED", "", ""), attemptIn("ADMITTED", "", ""))
	l.OnClaim = func(admission.Caller, string) (*admission.ModelCallClaim, admission.Attempt, error) {
		if tries++; tries == 1 {
			return nil, attemptIn("CANCELLED", "", string(contracts.ReasonAuthorityChanged)), nil
		}
		return claimed(), attemptIn("DISPATCHING", "", ""), nil
	}
	if claim, _, aerr, _ := admitting(t, l); aerr != nil || claim == nil || len(l.proposed) != 2 {
		t.Fatalf("%v %v", claim, aerr)
	}
}

func TestTheKeysTriedForOneRequestAreBounded(t *testing.T) {
	answers := make([]admission.Attempt, maxAdmitAttempts)
	for i := range answers {
		answers[i] = existingAttempt("UNKNOWN", "", string(contracts.ReasonProviderError))
	}
	l, _ := script(t, answers...)
	_, _, aerr, _ := admitting(t, l)
	if aerr == nil || aerr.Status != 409 || aerr.Code != "too_many_attempts" || len(l.proposed) != maxAdmitAttempts {
		t.Fatalf("%+v after %d proposals", aerr, len(l.proposed))
	}
	if got := keys(l); got[0] != "0" || got[len(got)-1] != fmt.Sprint(maxAdmitAttempts-1) {
		t.Fatalf("keys = %v", got)
	}
}
