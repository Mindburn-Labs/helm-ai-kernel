package releasepermit

import (
	"reflect"
	"testing"
)

const (
	testBaseSHA     = "1111111111111111111111111111111111111111"
	testHeadSHA     = "2222222222222222222222222222222222222222"
	testWorkflowSHA = "3333333333333333333333333333333333333333"
	testMergeSHA    = "4444444444444444444444444444444444444444"
	testMergeTree   = "5555555555555555555555555555555555555555"
	testContextSHA  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testResponseA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testResponseB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestEvaluateAllowsTwoProviderQuorum(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)
	reviews[0].Findings = []Finding{{Severity: "P3", Code: "STYLE", Summary: "Non-blocking naming improvement"}}

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if permit.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want %q; reasons = %#v", permit.Decision, DecisionAllow, permit.Reasons)
	}
	if permit.PermitID == "" {
		t.Fatal("PermitID is empty")
	}
	if got := permit.Reviews[0].AdvisoryFindings; got != 1 {
		t.Fatalf("AdvisoryFindings = %d, want 1", got)
	}
}

func TestEvaluateDeniesBlockingFinding(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)
	reviews[1].Findings = []Finding{{Severity: "P1", Code: "AUTH_BYPASS", Summary: "Authorization is bypassed"}}

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertDeniedFor(t, permit, "BLOCKING_FINDING")
}

func TestEvaluateDeniesStaleHead(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)
	reviews[0].HeadSHA = "4444444444444444444444444444444444444444"

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertDeniedFor(t, permit, "REVIEW_METADATA_MISMATCH")
}

func TestEvaluateDeniesMergeTreeSubstitution(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)
	reviews[0].MergeTreeSHA = "6666666666666666666666666666666666666666"

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertDeniedFor(t, permit, "REVIEW_METADATA_MISMATCH")
}

func TestEvaluateDeniesMissingReviewer(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)[:1]

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertDeniedFor(t, permit, "REVIEW_MISSING")
	assertDeniedFor(t, permit, "REVIEW_COUNT_MISMATCH")
}

func TestEvaluateDeniesDuplicateReviewer(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)
	reviews[1].Reviewer = reviews[0].Reviewer

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertDeniedFor(t, permit, "REVIEW_DUPLICATE")
	assertDeniedFor(t, permit, "REVIEW_MISSING")
}

func TestEvaluateDuplicateEvidenceIsOrderIndependent(t *testing.T) {
	context := validContext()
	firstReview := validReview(context, context.RequiredReviewers[0], testResponseA)
	secondReview := validReview(context, context.RequiredReviewers[0], testResponseB)

	first, err := Evaluate(context, testContextSHA, []Review{firstReview, secondReview})
	if err != nil {
		t.Fatalf("Evaluate(first) error = %v", err)
	}
	second, err := Evaluate(context, testContextSHA, []Review{secondReview, firstReview})
	if err != nil {
		t.Fatalf("Evaluate(second) error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("duplicate permits differ by input order:\nfirst: %#v\nsecond: %#v", first, second)
	}
}

func TestEvaluateRejectsInvalidContext(t *testing.T) {
	context := validContext()
	context.RequiredReviewers[1].Provider = context.RequiredReviewers[0].Provider

	if _, err := Evaluate(context, testContextSHA, validReviews(context)); err == nil {
		t.Fatal("Evaluate() error = nil, want invalid distinct-provider context error")
	}
}

func TestEvaluateAcceptsGitHubWorkflowRefIdentity(t *testing.T) {
	context := validContext()
	context.WorkflowRef = context.WorkflowRepository + "/" + context.WorkflowPath + "@refs/heads/codex/autonomous-release-permit"

	permit, err := Evaluate(context, testContextSHA, validReviews(context))
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if permit.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want %q; reasons = %#v", permit.Decision, DecisionAllow, permit.Reasons)
	}
}

func TestEvaluateRejectsMismatchedGitHubWorkflowRefIdentity(t *testing.T) {
	context := validContext()
	context.WorkflowRef = "Mindburn-Labs/other/.github/workflows/ci.yml@refs/heads/main"

	if _, err := Evaluate(context, testContextSHA, validReviews(context)); err == nil {
		t.Fatal("Evaluate() error = nil, want mismatched workflow identity error")
	}
}

func TestEvaluateRejectsAmbiguousReviewerIdentity(t *testing.T) {
	context := validContext()
	context.RequiredReviewers[0].Provider = "anthropic/team"

	if _, err := Evaluate(context, testContextSHA, validReviews(context)); err == nil {
		t.Fatal("Evaluate() error = nil, want ambiguous reviewer identity error")
	}
}

func TestEvaluatePermitIDIsIndependentOfInputReviewOrder(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)
	first, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate(first) error = %v", err)
	}
	reversed := []Review{reviews[1], reviews[0]}
	second, err := Evaluate(context, testContextSHA, reversed)
	if err != nil {
		t.Fatalf("Evaluate(second) error = %v", err)
	}
	if first.PermitID != second.PermitID {
		t.Fatalf("PermitID differs by input order: %q != %q", first.PermitID, second.PermitID)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("permits differ by input order:\nfirst: %#v\nsecond: %#v", first, second)
	}
}

func TestEvaluateDeniesContextSubstitution(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)
	reviews[0].ContextSHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertDeniedFor(t, permit, "REVIEW_CONTEXT_MISMATCH")
}

func TestEvaluateDeniesNilFindings(t *testing.T) {
	context := validContext()
	reviews := validReviews(context)
	reviews[0].Findings = nil

	permit, err := Evaluate(context, testContextSHA, reviews)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	assertDeniedFor(t, permit, "REVIEW_FINDINGS_INVALID")
}

func TestEvaluateDeniesInvalidReviewFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Review)
		code   string
	}{
		{
			name: "empty reviewer",
			mutate: func(review *Review) {
				review.Reviewer.Provider = ""
			},
			code: "REVIEW_REVIEWER_INVALID",
		},
		{
			name: "invalid verdict",
			mutate: func(review *Review) {
				review.Verdict = "MAYBE"
			},
			code: "REVIEW_VERDICT_INVALID",
		},
		{
			name: "denied verdict",
			mutate: func(review *Review) {
				review.Verdict = DecisionDeny
			},
			code: "REVIEW_DENIED",
		},
		{
			name: "invalid response digest",
			mutate: func(review *Review) {
				review.ResponseSHA256 = "not-a-digest"
			},
			code: "REVIEW_DIGEST_INVALID",
		},
		{
			name: "invalid finding severity",
			mutate: func(review *Review) {
				review.Findings = []Finding{{Severity: "P4", Code: "BAD", Summary: "invalid severity"}}
			},
			code: "REVIEW_FINDINGS_INVALID",
		},
		{
			name: "too many findings",
			mutate: func(review *Review) {
				review.Findings = make([]Finding, 201)
			},
			code: "REVIEW_FINDINGS_INVALID",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := validContext()
			reviews := validReviews(context)
			test.mutate(&reviews[0])
			permit, err := Evaluate(context, testContextSHA, reviews)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			assertDeniedFor(t, permit, test.code)
		})
	}
}

func validContext() Context {
	return Context{
		Schema:             ContextSchema,
		Repository:         "Mindburn-Labs/example",
		Event:              "pull_request",
		PullRequest:        42,
		BaseRef:            "refs/heads/main",
		BaseSHA:            testBaseSHA,
		HeadSHA:            testHeadSHA,
		MergeSHA:           testMergeSHA,
		MergeTreeSHA:       testMergeTree,
		WorkflowRepository: "Mindburn-Labs/.github",
		WorkflowPath:       ".github/workflows/autonomous-release-permit.yml",
		WorkflowRef:        "refs/heads/main",
		WorkflowSHA:        testWorkflowSHA,
		RunID:              101,
		RunAttempt:         1,
		IssuedAt:           "2026-07-14T10:00:00Z",
		RequiredReviewers: []Reviewer{
			{Provider: "anthropic", Model: "claude-fable-5"},
			{Provider: "openai", Model: "gpt-5.6-sol"},
		},
	}
}

func validReviews(context Context) []Review {
	return []Review{
		validReview(context, context.RequiredReviewers[0], testResponseA),
		validReview(context, context.RequiredReviewers[1], testResponseB),
	}
}

func validReview(context Context, reviewer Reviewer, digest string) Review {
	return Review{
		Schema:         ReviewSchema,
		Repository:     context.Repository,
		PullRequest:    context.PullRequest,
		BaseSHA:        context.BaseSHA,
		HeadSHA:        context.HeadSHA,
		MergeSHA:       context.MergeSHA,
		MergeTreeSHA:   context.MergeTreeSHA,
		WorkflowSHA:    context.WorkflowSHA,
		RunID:          context.RunID,
		RunAttempt:     context.RunAttempt,
		ContextSHA256:  testContextSHA,
		Reviewer:       reviewer,
		Verdict:        DecisionAllow,
		ResponseSHA256: digest,
		Findings:       []Finding{},
	}
}

func assertDeniedFor(t *testing.T, permit Permit, code string) {
	t.Helper()
	if permit.Decision != DecisionDeny {
		t.Fatalf("Decision = %q, want %q", permit.Decision, DecisionDeny)
	}
	for _, reason := range permit.Reasons {
		if reason.Code == code {
			return
		}
	}
	t.Fatalf("reasons %#v do not contain %q", permit.Reasons, code)
}
