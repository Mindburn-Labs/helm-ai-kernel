// Package negative executes the fail-closed conformance vectors declared by
// conformance.DefaultNegativeBoundaryVectors against a live Guardian.
//
// Those vectors carry an expected verdict, an expected reason code, and a
// prose Trigger — but no way to produce the trigger, so until now nothing ran
// them: the catalog's only consumers print it or serialize it to JSON. A
// declared fail-closed boundary that is never exercised is a claim, not a
// control.
//
// Binding a vector means writing a harness that drives a Guardian into the
// state the Trigger describes. Most vectors cannot be bound yet — their gate
// is unimplemented, or their reason code has no producer anywhere in the tree.
// Run reports those as unbound instead of skipping them, because a suite that
// silently exercises five of forty-three vectors reads as "fail-closed
// verified" when it is nothing of the kind. The denominator is the point.
package negative

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// Case drives one vector's trigger. Build returns a Guardian in the state the
// vector describes, plus the request that must be refused.
type Case struct {
	VectorID string
	Build    func() (*guardian.Guardian, guardian.DecisionRequest, error)
}

// Result is one vector's outcome. An unbound vector is neither pass nor fail:
// it is unmeasured, and collapsing that into "fail" would make the report
// unreadable while collapsing it into "pass" would make it a lie.
type Result struct {
	VectorID      string   `json:"vector_id"`
	Bound         bool     `json:"bound"`
	Pass          bool     `json:"pass"`
	GotVerdict    string   `json:"got_verdict,omitempty"`
	GotReasonCode string   `json:"got_reason_code,omitempty"`
	Failures      []string `json:"failures,omitempty"`
}

// Report is the measurement. Bound/Total is the coverage of the fail-closed
// suite; Passed/Bound is how much of what is measured actually holds.
type Report struct {
	Total      int      `json:"total"`
	Bound      int      `json:"bound"`
	Passed     int      `json:"passed"`
	Failed     int      `json:"failed"`
	UnboundIDs []string `json:"unbound_ids,omitempty"`
	UnknownIDs []string `json:"unknown_ids,omitempty"`
	Results    []Result `json:"results"`
}

// Run executes every bound case against the catalog and reports the rest.
func Run(ctx context.Context, cases []Case) Report {
	byID := make(map[string]Case, len(cases))
	for _, c := range cases {
		byID[c.VectorID] = c
	}

	vectors := conformance.DefaultNegativeBoundaryVectors()
	report := Report{Total: len(vectors)}
	catalog := make(map[string]bool, len(vectors))

	for _, vector := range vectors {
		catalog[vector.ID] = true

		bound, ok := byID[vector.ID]
		if !ok {
			report.UnboundIDs = append(report.UnboundIDs, vector.ID)
			report.Results = append(report.Results, Result{VectorID: vector.ID})
			continue
		}

		report.Bound++
		result := runOne(ctx, vector, bound)
		if result.Pass {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Results = append(report.Results, result)
	}

	// A harness whose VectorID matches nothing is a typo that would otherwise
	// look identical to a passing suite with one fewer case.
	for _, c := range cases {
		if !catalog[c.VectorID] {
			report.UnknownIDs = append(report.UnknownIDs, c.VectorID)
		}
	}

	return report
}

func runOne(ctx context.Context, vector conformance.NegativeBoundaryVector, bound Case) Result {
	result := Result{VectorID: vector.ID, Bound: true}
	fail := func(format string, args ...any) {
		result.Failures = append(result.Failures, fmt.Sprintf(format, args...))
	}

	guard, request, err := bound.Build()
	if err != nil {
		fail("building the trigger state: %v", err)
		return result
	}

	decision, err := guard.EvaluateDecision(ctx, request)
	if err != nil {
		fail("evaluating the decision: %v", err)
		return result
	}
	if decision == nil {
		fail("evaluation returned no decision")
		return result
	}

	result.GotVerdict = decision.Verdict
	result.GotReasonCode = decision.ReasonCode

	if want := string(vector.ExpectedVerdict); decision.Verdict != want {
		fail("verdict is %q, want %q", decision.Verdict, want)
	}
	if want := string(vector.ExpectedReasonCode); decision.ReasonCode != want {
		fail("reason code is %q, want %q", decision.ReasonCode, want)
	}

	if vector.MustEmitReceipt && decision.Signature == "" {
		// The Guardian mints a signed DecisionRecord, not a contracts.Receipt —
		// it has no receipt-minting method at all. An unsigned refusal is the
		// part of MustEmitReceipt that is checkable here: an offline verifier
		// can do nothing with it.
		fail("refusal is unsigned, so it cannot be verified offline")
	}

	if vector.MustNotDispatch {
		effect := &contracts.Effect{EffectID: "eff-" + vector.ID, EffectType: request.Action}
		if _, err := guard.IssueExecutionIntent(ctx, decision, effect); err == nil {
			fail("dispatch authority was issued for a refused decision")
		}
	}

	result.Pass = len(result.Failures) == 0
	return result
}
