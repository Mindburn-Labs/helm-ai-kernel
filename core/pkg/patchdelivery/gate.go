package patchdelivery

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Lifecycle values. The lifecycle answers only "did the run finish its own
// work", never "should the work be delivered".
const (
	LifecycleSucceeded = "succeeded"
	LifecycleFailed    = "failed"
	LifecycleRunning   = "running"
)

// Checks values — the run's own deterministic verification.
const (
	ChecksPassed        = "passed"
	ChecksFailed        = "failed"
	ChecksNotConfigured = "not_configured"
)

// Review values — the human/authority decision on the run's work product.
const (
	ReviewApproved = "approved"
	ReviewBlocked  = "blocked"
	ReviewNotRun   = "not_run"
)

// Operator override actions.
const (
	OverrideAcceptRisk = "accept_risk"
	OverrideNeedsHuman = "override_needs_human"
)

// OutcomeFacts describes a finished run on three ORTHOGONAL axes rather than
// one status enum.
//
// The axes are separate because a single enum forces false choices. The classic
// one is "needs decision": with one enum it becomes a state that competes with
// "succeeded", so a run that did its job perfectly and is merely waiting on a
// reviewer gets recorded as though it did not succeed. It did. It is a
// SUCCEEDED lifecycle whose Review axis is still open. Collapsing those loses
// the ability to tell "the agent failed" from "nobody has looked yet", which is
// exactly the distinction an operator needs at the moment of apply.
//
// Checks and Review are likewise independent: checks can pass while a reviewer
// blocks, and a reviewer can approve work whose checks were never configured.
type OutcomeFacts struct {
	Lifecycle string `json:"lifecycle"`
	Checks    string `json:"checks"`
	Review    string `json:"review"`
	NoChanges bool   `json:"no_changes"`
	Reason    string `json:"reason,omitempty"`
}

// NeedsDecision reports whether the run is parked awaiting a human. This is the
// only condition under which an operator override has any scope at all.
func (f OutcomeFacts) NeedsDecision() bool {
	return f.Review == ReviewBlocked || f.Checks == ChecksFailed
}

// OperatorOverride is an EffectPermit in miniature.
//
// A permit in core/pkg/effects binds a verdict to a connector, an action, and a
// scope, so the authorization cannot be replayed against a different effect.
// This binds an operator's acceptance to one exact patch by content hash, for
// the same reason: the thing the operator looked at and the thing that gets
// applied must be provably identical. Change one byte of the patch and the
// override no longer authorizes it, because it no longer describes it.
type OperatorOverride struct {
	// Action must be OverrideAcceptRisk or OverrideNeedsHuman.
	Action string `json:"action"`
	// PatchSHA256 is the hex SHA-256 of the exact patch bytes the operator
	// accepted.
	PatchSHA256 string `json:"patch_sha256"`
}

// GateInput is everything Eligibility is allowed to consider. If a caller wants
// a new input to influence the apply decision, it belongs here — not in a
// second decision site.
type GateInput struct {
	// Lifecycle is the caller's view of the run lifecycle. It is cross-checked
	// against Facts.Lifecycle; a disagreement is a contract error, not something
	// to silently resolve.
	Lifecycle string
	Facts     OutcomeFacts
	Patch     []byte
	BaseSHA   string
	// OriginalRepoRoot is the repository the patch was captured for.
	// TargetRepoRoot is the repository the caller intends to mutate.
	OriginalRepoRoot string
	TargetRepoRoot   string
	Verify           *VerifyRecord
	Override         *OperatorOverride
}

// Decision is the machine-readable outcome plus the text an operator reads.
// The axes stay structured on the Decision; they are never only sentences
// inside Refusal, so a caller can branch on state without parsing prose.
type Decision struct {
	Verdict    contracts.Verdict    `json:"verdict"`
	ReasonCode contracts.ReasonCode `json:"reason_code,omitempty"`
	// Refusal is human-readable and safe to print. Empty when allowed.
	Refusal string        `json:"refusal,omitempty"`
	Facts   OutcomeFacts  `json:"facts"`
	Verify  *VerifyRecord `json:"verify,omitempty"`
	// OverrideAccepted records whether a supplied override was honoured.
	OverrideAccepted bool `json:"override_accepted"`
	// OverrideRefusal explains why a supplied override was not honoured.
	OverrideRefusal string `json:"override_refusal,omitempty"`
}

// MayApply reports whether the caller is authorized to mutate the live tree.
func (d Decision) MayApply() bool { return d.Verdict == contracts.VerdictAllow }

// Eligibility decides whether a run's patch may be applied to a live project
// tree.
//
// THIS IS THE ONLY PLACE APPLY POLICY IS DECIDED. Every caller — CLI, control
// API, scheduler, future UI — must route through this function and act on the
// returned Decision. A caller that re-implements "looks approved to me" creates
// a second policy with no receipt, and the two will drift; the first divergence
// is a mutation nobody authorized. Add inputs to GateInput and rules here.
//
// Apply requires all of: the lifecycle succeeded, the review approved, the
// checks did not fail, and a fresh verify that did not block.
func Eligibility(input GateInput) (Decision, error) {
	d := Decision{Facts: input.Facts, Verify: input.Verify}

	lifecycle := input.Facts.Lifecycle
	if lifecycle == "" {
		lifecycle = input.Lifecycle
	}
	if lifecycle == "" {
		return Decision{}, errors.New("delivery: no lifecycle recorded; cannot decide eligibility")
	}
	// The redundant field is a cross-check, not a fallback. Two sources that
	// disagree about whether the run finished is a broken contract, and guessing
	// which one is right is how a failed run gets delivered.
	if input.Lifecycle != "" && input.Facts.Lifecycle != "" && input.Lifecycle != input.Facts.Lifecycle {
		return deny(d, contracts.ReasonHarnessChangeContractInvalid, fmt.Sprintf(
			"run lifecycle is reported two different ways (%q and %q); refusing to guess which is true",
			input.Lifecycle, input.Facts.Lifecycle)), nil
	}

	// A patch is only meaningful against the repository it was captured from.
	if mismatch, why := repoMismatch(input.OriginalRepoRoot, input.TargetRepoRoot); mismatch {
		return deny(d, contracts.ReasonContextMismatch, why), nil
	}

	// No fresh verify at all means the caller skipped the gate rather than the
	// gate failing. Not override-eligible: there is nothing to accept the risk
	// of, because no risk was ever measured.
	if input.Verify == nil {
		return deny(d, contracts.ReasonVerificationScopeRequired,
			"no fresh verification was performed immediately before apply"), nil
	}

	// PROVEN conflict. Checked before any override is even evaluated, so no
	// ordering mistake can let an authority reach a patch that factually does
	// not apply. There is no operator on earth who can make it apply.
	if input.Verify.ProvenUndeliverable() {
		return deny(d, contracts.ReasonPlanTransactionConflict, fmt.Sprintf(
			"the patch was proven not to apply to a clean base (%s): %s. This is a fact about the patch, not a policy block, and no override can clear it",
			shortSHA(input.Verify.BaseSHA), input.Verify.Reason)), nil
	}

	if lifecycle != LifecycleSucceeded {
		return deny(d, contracts.ReasonMissingRequirement, fmt.Sprintf(
			"run lifecycle is %q, not %q", lifecycle, LifecycleSucceeded)), nil
	}

	if input.Facts.NoChanges || len(input.Patch) == 0 {
		return deny(d, contracts.ReasonMissingRequirement,
			"the run produced no changes; there is nothing to deliver"), nil
	}

	// Evaluate the override once, up front, so every block below consults the
	// same answer and none of them can accidentally apply a laxer rule.
	overrideOK, overrideWhy := evaluateOverride(input.Override, input.Facts, input.Patch)
	d.OverrideAccepted = overrideOK
	d.OverrideRefusal = overrideWhy

	// UNKNOWN deliverability: blocks fail-closed, but is override-eligible.
	//
	// Note the interaction with override scope: an override is only valid on a
	// run that is genuinely needs-decision. So a run that is otherwise clean and
	// merely hit a broken verifier CANNOT be overridden — the correct response
	// there is to fix the verifier and re-run it, not to wave the patch through
	// on an authority that was never meant for it.
	if input.Verify.Unknown() && !overrideOK {
		return escalate(d, contracts.ReasonAssumptionStale, fmt.Sprintf(
			"deliverability is unknown: %s%s", input.Verify.Reason, suffix(overrideWhy))), nil
	}

	// Verification gates ran and did not pass. Unlike a proven conflict the
	// patch does apply, so this is a risk judgment an operator may accept.
	if input.Verify.GatesPassed != nil && !*input.Verify.GatesPassed && !overrideOK {
		return escalate(d, contracts.ReasonVerification, fmt.Sprintf(
			"verification gates did not pass: %s%s", input.Verify.Reason, suffix(overrideWhy))), nil
	}

	if input.Facts.Checks == ChecksFailed && !overrideOK {
		return escalate(d, contracts.ReasonApprovalRequired, fmt.Sprintf(
			"the run's checks failed%s", suffix(overrideWhy))), nil
	}

	if input.Facts.Review != ReviewApproved && !overrideOK {
		return escalate(d, contracts.ReasonApprovalRequired, fmt.Sprintf(
			"review is %q, not %q%s", input.Facts.Review, ReviewApproved, suffix(overrideWhy))), nil
	}

	d.Verdict = contracts.VerdictAllow
	return d, nil
}

// evaluateOverride returns whether the override authorizes bypassing the
// override-eligible blocks, and if not, why not.
func evaluateOverride(o *OperatorOverride, facts OutcomeFacts, patch []byte) (bool, string) {
	if o == nil {
		return false, ""
	}
	if o.Action != OverrideAcceptRisk && o.Action != OverrideNeedsHuman {
		return false, fmt.Sprintf("override action %q is not one of %q or %q",
			o.Action, OverrideAcceptRisk, OverrideNeedsHuman)
	}
	// Scope. An override is an answer to a question that was actually asked. If
	// nothing is blocked pending a human, there is no question, and accepting
	// risk on an unreviewed run would silently replace the review.
	if !facts.NeedsDecision() {
		return false, fmt.Sprintf(
			"this run is not awaiting a decision (review=%q, checks=%q), so there is no risk decision to accept; it needs a review, not an override",
			facts.Review, facts.Checks)
	}
	// Binding. The permit names one exact patch by content hash.
	actual := canonicalize.HashBytes(patch)
	if !strings.EqualFold(o.PatchSHA256, actual) {
		return false, fmt.Sprintf(
			"the override authorizes patch %s but the patch presented is %s; the patch changed after it was accepted",
			shortSHA(o.PatchSHA256), shortSHA(actual))
	}
	return true, ""
}

// repoMismatch reports whether a patch captured for one repository is being
// pointed at another.
func repoMismatch(original, target string) (bool, string) {
	if original == "" || target == "" {
		return false, ""
	}
	o, err1 := filepath.Abs(original)
	t, err2 := filepath.Abs(target)
	if err1 != nil || err2 != nil {
		return true, "could not resolve the source and target repository paths"
	}
	if filepath.Clean(o) == filepath.Clean(t) {
		return false, ""
	}
	return true, fmt.Sprintf(
		"the patch was captured for %s but the apply target is %s", o, t)
}

func deny(d Decision, code contracts.ReasonCode, refusal string) Decision {
	d.Verdict = contracts.VerdictDeny
	d.ReasonCode = code
	d.Refusal = refusal
	return d
}

func escalate(d Decision, code contracts.ReasonCode, refusal string) Decision {
	d.Verdict = contracts.VerdictEscalate
	d.ReasonCode = code
	d.Refusal = refusal
	return d
}

func suffix(why string) string {
	if why == "" {
		return ""
	}
	return "; the supplied override was refused: " + why
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "(none)"
	}
	return s
}
