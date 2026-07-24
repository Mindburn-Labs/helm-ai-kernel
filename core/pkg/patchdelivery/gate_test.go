package patchdelivery

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var samplePatch = []byte("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+x\n")

func cleanFacts() OutcomeFacts {
	return OutcomeFacts{
		Lifecycle: LifecycleSucceeded,
		Checks:    ChecksPassed,
		Review:    ReviewApproved,
	}
}

// needsDecisionFacts is a SUCCEEDED run parked awaiting a human — the only
// shape an operator override has any scope over.
func needsDecisionFacts() OutcomeFacts {
	f := cleanFacts()
	f.Review = ReviewBlocked
	return f
}

func verifyOK() *VerifyRecord {
	return &VerifyRecord{Attempted: true, AppliedCleanly: boolPtr(true), GatesPassed: boolPtr(true), BaseSHA: "abc123"}
}

func verifyNoGates() *VerifyRecord {
	return &VerifyRecord{Attempted: true, AppliedCleanly: boolPtr(true), BaseSHA: "abc123",
		Reason: "patch applies to a clean base; no gates configured, so nothing else was verified"}
}

func verifyGatesFailed() *VerifyRecord {
	return &VerifyRecord{Attempted: true, AppliedCleanly: boolPtr(true), GatesPassed: boolPtr(false),
		BaseSHA: "abc123", Reason: `gate "unit" failed`}
}

func verifyProvenConflict() *VerifyRecord {
	return &VerifyRecord{Attempted: true, AppliedCleanly: boolPtr(false), BaseSHA: "abc123",
		Reason: "patch does not apply to a clean base: conflict in x"}
}

func verifyUnknown() *VerifyRecord {
	return &VerifyRecord{Attempted: true, BaseSHA: "abc123",
		Reason: "verifier could not run git apply: exec format error"}
}

func validOverride(patch []byte) *OperatorOverride {
	return &OperatorOverride{Action: OverrideAcceptRisk, PatchSHA256: canonicalize.HashBytes(patch)}
}

func inputFor(facts OutcomeFacts, verify *VerifyRecord, override *OperatorOverride) GateInput {
	return GateInput{
		Lifecycle: facts.Lifecycle,
		Facts:     facts,
		Patch:     samplePatch,
		BaseSHA:   "abc123",
		Verify:    verify,
		Override:  override,
	}
}

// The core matrix. An override may bypass UNKNOWN; it may never bypass
// PROVEN-FALSE.
func TestEligibilityTriStateMatrix(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		facts        OutcomeFacts
		verify       *VerifyRecord
		override     *OperatorOverride
		wantVerdict  contracts.Verdict
		wantReason   contracts.ReasonCode
		wantOverride bool
		refusalHas   string
	}{
		{
			name:        "clean run with passing gates applies",
			facts:       cleanFacts(),
			verify:      verifyOK(),
			wantVerdict: contracts.VerdictAllow,
		},
		{
			name:        "clean run with no gates configured still applies",
			facts:       cleanFacts(),
			verify:      verifyNoGates(),
			wantVerdict: contracts.VerdictAllow,
		},
		{
			name:        "PROVEN conflict is denied outright",
			facts:       cleanFacts(),
			verify:      verifyProvenConflict(),
			wantVerdict: contracts.VerdictDeny,
			wantReason:  contracts.ReasonPlanTransactionConflict,
			refusalHas:  "no override can clear it",
		},
		{
			name:     "PROVEN conflict cannot be overridden even by a valid override on a needs-decision run",
			facts:    needsDecisionFacts(),
			verify:   verifyProvenConflict(),
			override: validOverride(samplePatch),
			// The decisive case: every override precondition is satisfied and the
			// answer is still DENY, because no authority makes a conflicting patch
			// apply.
			wantVerdict: contracts.VerdictDeny,
			wantReason:  contracts.ReasonPlanTransactionConflict,
			refusalHas:  "fact about the patch",
		},
		{
			name:        "UNKNOWN blocks fail-closed without an override",
			facts:       needsDecisionFacts(),
			verify:      verifyUnknown(),
			wantVerdict: contracts.VerdictEscalate,
			wantReason:  contracts.ReasonAssumptionStale,
			refusalHas:  "deliverability is unknown",
		},
		{
			name:         "UNKNOWN IS overridable on a needs-decision run",
			facts:        needsDecisionFacts(),
			verify:       verifyUnknown(),
			override:     validOverride(samplePatch),
			wantVerdict:  contracts.VerdictAllow,
			wantOverride: true,
		},
		{
			name:        "failed verification gates block without an override",
			facts:       needsDecisionFacts(),
			verify:      verifyGatesFailed(),
			wantVerdict: contracts.VerdictEscalate,
			wantReason:  contracts.ReasonVerification,
			refusalHas:  "verification gates did not pass",
		},
		{
			name:         "failed verification gates are overridable — the patch does apply",
			facts:        needsDecisionFacts(),
			verify:       verifyGatesFailed(),
			override:     validOverride(samplePatch),
			wantVerdict:  contracts.VerdictAllow,
			wantOverride: true,
		},
		{
			name:        "a blocked review escalates rather than denying",
			facts:       needsDecisionFacts(),
			verify:      verifyOK(),
			wantVerdict: contracts.VerdictEscalate,
			wantReason:  contracts.ReasonApprovalRequired,
		},
		{
			name: "failed checks escalate",
			facts: func() OutcomeFacts {
				f := cleanFacts()
				f.Checks = ChecksFailed
				return f
			}(),
			verify:      verifyOK(),
			wantVerdict: contracts.VerdictEscalate,
			wantReason:  contracts.ReasonApprovalRequired,
			refusalHas:  "checks failed",
		},
		{
			name: "checks that were never configured do not block an approved run",
			facts: func() OutcomeFacts {
				f := cleanFacts()
				f.Checks = ChecksNotConfigured
				return f
			}(),
			verify:      verifyOK(),
			wantVerdict: contracts.VerdictAllow,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Eligibility(inputFor(tc.facts, tc.verify, tc.override))
			if err != nil {
				t.Fatalf("Eligibility: %v", err)
			}
			if got.Verdict != tc.wantVerdict {
				t.Errorf("Verdict = %q, want %q (refusal: %s)", got.Verdict, tc.wantVerdict, got.Refusal)
			}
			if tc.wantReason != "" && got.ReasonCode != tc.wantReason {
				t.Errorf("ReasonCode = %q, want %q", got.ReasonCode, tc.wantReason)
			}
			if got.OverrideAccepted != tc.wantOverride {
				t.Errorf("OverrideAccepted = %v, want %v (refusal: %s)", got.OverrideAccepted, tc.wantOverride, got.OverrideRefusal)
			}
			if tc.refusalHas != "" && !strings.Contains(got.Refusal, tc.refusalHas) {
				t.Errorf("Refusal = %q, want it to contain %q", got.Refusal, tc.refusalHas)
			}
			if got.MayApply() != (tc.wantVerdict == contracts.VerdictAllow) {
				t.Errorf("MayApply() = %v but verdict is %q", got.MayApply(), got.Verdict)
			}
			// The axes must survive onto the Decision, not only into prose.
			if got.Facts.Review != tc.facts.Review || got.Facts.Checks != tc.facts.Checks {
				t.Errorf("Decision lost the machine-readable axes: %+v", got.Facts)
			}
		})
	}
}

// The override is bound to one exact patch by content hash, exactly as an
// EffectPermit is bound to one effect. Change a single byte and the
// authorization no longer describes what is being applied.
func TestOverrideBindingRejectsAMutatedPatch(t *testing.T) {
	t.Parallel()

	original := append([]byte(nil), samplePatch...)
	override := validOverride(original)

	// Sanity: the override authorizes the patch it was issued for.
	in := inputFor(needsDecisionFacts(), verifyUnknown(), override)
	in.Patch = original
	if got, err := Eligibility(in); err != nil || !got.OverrideAccepted {
		t.Fatalf("baseline override should be accepted: accepted=%v err=%v refusal=%s",
			got.OverrideAccepted, err, got.OverrideRefusal)
	}

	// Flip exactly one byte.
	mutated := append([]byte(nil), original...)
	mutated[len(mutated)-2] ^= 0x01

	in.Patch = mutated
	got, err := Eligibility(in)
	if err != nil {
		t.Fatalf("Eligibility: %v", err)
	}
	if got.OverrideAccepted {
		t.Fatal("a one-byte change to the patch left the override valid; the permit is not bound to content")
	}
	if got.MayApply() {
		t.Fatal("apply was allowed on a patch the operator never accepted")
	}
	if !strings.Contains(got.OverrideRefusal, "changed after it was accepted") {
		t.Errorf("OverrideRefusal = %q, want it to name the content mismatch", got.OverrideRefusal)
	}
}

// An override answers a question that was actually asked. On a run nobody has
// reviewed, there is no risk decision to accept — it needs a review.
func TestOverrideScopeRefusedWhenRunIsNotNeedsDecision(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		facts OutcomeFacts
	}{
		{"review never ran", func() OutcomeFacts {
			f := cleanFacts()
			f.Review = ReviewNotRun
			return f
		}()},
		{"already approved, nothing to decide", cleanFacts()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Eligibility(inputFor(tc.facts, verifyUnknown(), validOverride(samplePatch)))
			if err != nil {
				t.Fatalf("Eligibility: %v", err)
			}
			if got.OverrideAccepted {
				t.Fatal("accept_risk was honoured on a run that is not awaiting a decision")
			}
			if got.MayApply() {
				t.Fatal("an unverified run was applied on the strength of an out-of-scope override")
			}
			if !strings.Contains(got.OverrideRefusal, "needs a review, not an override") {
				t.Errorf("OverrideRefusal = %q, want it to explain the scope error", got.OverrideRefusal)
			}
		})
	}
}

func TestOverrideRejectsUnknownAction(t *testing.T) {
	t.Parallel()
	bad := &OperatorOverride{Action: "force_push_it", PatchSHA256: canonicalize.HashBytes(samplePatch)}
	got, err := Eligibility(inputFor(needsDecisionFacts(), verifyUnknown(), bad))
	if err != nil {
		t.Fatalf("Eligibility: %v", err)
	}
	if got.OverrideAccepted {
		t.Fatal("an unrecognized override action was honoured")
	}
	if !strings.Contains(got.OverrideRefusal, "is not one of") {
		t.Errorf("OverrideRefusal = %q", got.OverrideRefusal)
	}
}

func TestEligibilityStructuralRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		mutate     func(*GateInput)
		wantReason contracts.ReasonCode
		refusalHas string
	}{
		{
			name:       "no fresh verification at all",
			mutate:     func(in *GateInput) { in.Verify = nil },
			wantReason: contracts.ReasonVerificationScopeRequired,
			refusalHas: "no fresh verification",
		},
		{
			name: "lifecycle reported two different ways",
			mutate: func(in *GateInput) {
				in.Lifecycle = LifecycleFailed
				in.Facts.Lifecycle = LifecycleSucceeded
			},
			wantReason: contracts.ReasonHarnessChangeContractInvalid,
			refusalHas: "two different ways",
		},
		{
			name: "patch targeted at a different repository",
			mutate: func(in *GateInput) {
				in.OriginalRepoRoot = "/tmp/project-a"
				in.TargetRepoRoot = "/tmp/project-b"
			},
			wantReason: contracts.ReasonContextMismatch,
			refusalHas: "apply target is",
		},
		{
			name: "run did not succeed",
			mutate: func(in *GateInput) {
				in.Lifecycle = LifecycleFailed
				in.Facts.Lifecycle = LifecycleFailed
			},
			wantReason: contracts.ReasonMissingRequirement,
			refusalHas: "not \"succeeded\"",
		},
		{
			name:       "run produced no changes",
			mutate:     func(in *GateInput) { in.Facts.NoChanges = true },
			wantReason: contracts.ReasonMissingRequirement,
			refusalHas: "nothing to deliver",
		},
		{
			name:       "empty patch",
			mutate:     func(in *GateInput) { in.Patch = nil },
			wantReason: contracts.ReasonMissingRequirement,
			refusalHas: "nothing to deliver",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := inputFor(cleanFacts(), verifyOK(), nil)
			tc.mutate(&in)

			got, err := Eligibility(in)
			if err != nil {
				t.Fatalf("Eligibility: %v", err)
			}
			if got.MayApply() {
				t.Fatal("expected a refusal, got ALLOW")
			}
			if got.ReasonCode != tc.wantReason {
				t.Errorf("ReasonCode = %q, want %q (refusal: %s)", got.ReasonCode, tc.wantReason, got.Refusal)
			}
			if !strings.Contains(got.Refusal, tc.refusalHas) {
				t.Errorf("Refusal = %q, want it to contain %q", got.Refusal, tc.refusalHas)
			}
		})
	}
}

// The same repository expressed two ways is not a mismatch.
func TestEligibilityAcceptsEquivalentRepoPaths(t *testing.T) {
	t.Parallel()
	in := inputFor(cleanFacts(), verifyOK(), nil)
	in.OriginalRepoRoot = "/tmp/project"
	in.TargetRepoRoot = "/tmp/./project"

	got, err := Eligibility(in)
	if err != nil {
		t.Fatalf("Eligibility: %v", err)
	}
	if !got.MayApply() {
		t.Fatalf("equivalent paths were treated as a mismatch: %s", got.Refusal)
	}
}

func TestEligibilityRequiresALifecycle(t *testing.T) {
	t.Parallel()
	in := inputFor(cleanFacts(), verifyOK(), nil)
	in.Lifecycle = ""
	in.Facts.Lifecycle = ""

	if _, err := Eligibility(in); err == nil {
		t.Fatal("expected an error when no lifecycle was recorded")
	}
}
