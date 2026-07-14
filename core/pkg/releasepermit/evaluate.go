package releasepermit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	hexSHA40Pattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexSHA256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Evaluate validates a two-provider review quorum and returns a deterministic
// permit. A structurally invalid context is an error because no trustworthy
// decision can be bound to it. Invalid, stale, missing, or denying reviews
// produce a well-formed DENY permit.
func Evaluate(context Context, contextSHA256 string, reviews []Review) (Permit, error) {
	if err := validateContext(context); err != nil {
		return Permit{}, err
	}
	if !hexSHA256Pattern.MatchString(contextSHA256) {
		return Permit{}, errors.New("context_sha256 must be lowercase hexadecimal")
	}

	permit := Permit{
		Schema:             PermitSchema,
		Decision:           DecisionAllow,
		Repository:         context.Repository,
		PullRequest:        context.PullRequest,
		BaseRef:            context.BaseRef,
		BaseSHA:            context.BaseSHA,
		HeadSHA:            context.HeadSHA,
		MergeSHA:           context.MergeSHA,
		MergeTreeSHA:       context.MergeTreeSHA,
		WorkflowRepository: context.WorkflowRepository,
		WorkflowPath:       context.WorkflowPath,
		WorkflowRef:        context.WorkflowRef,
		WorkflowSHA:        context.WorkflowSHA,
		RunID:              context.RunID,
		RunAttempt:         context.RunAttempt,
		IssuedAt:           context.IssuedAt,
		ContextSHA256:      contextSHA256,
		Reviews:            make([]ReviewSummary, 0, len(context.RequiredReviewers)),
		Reasons:            []Reason{},
	}

	required := make(map[string]Reviewer, len(context.RequiredReviewers))
	for _, reviewer := range context.RequiredReviewers {
		required[reviewerKey(reviewer)] = reviewer
	}

	provided := make(map[string][]Review, len(reviews))
	for _, review := range reviews {
		key := reviewerKey(review.Reviewer)
		provided[key] = append(provided[key], review)
		if review.Reviewer.Provider == "" || review.Reviewer.Model == "" ||
			strings.Contains(review.Reviewer.Provider, "/") || strings.Contains(review.Reviewer.Model, "/") {
			permit.addReason("REVIEW_REVIEWER_INVALID", key, "reviewer provider and model must be non-empty and cannot contain slash")
		}
		if _, expected := required[key]; !expected {
			permit.addReason("REVIEW_UNEXPECTED", key, "reviewer is not part of the required quorum")
		}
	}
	for key, group := range provided {
		if len(group) > 1 {
			permit.addReason("REVIEW_DUPLICATE", key, "more than one review used the same provider and model")
		}
	}

	for _, expected := range context.RequiredReviewers {
		key := reviewerKey(expected)
		group := provided[key]
		if len(group) == 0 {
			permit.addReason("REVIEW_MISSING", key, "required reviewer did not produce a result")
			continue
		}
		if len(group) > 1 {
			permit.addReason("REVIEW_MISSING", key, "required reviewer did not produce one unique result")
			continue
		}

		summary, reasons := validateReview(context, contextSHA256, group[0])
		permit.Reviews = append(permit.Reviews, summary)
		for _, reason := range reasons {
			permit.addReason(reason.Code, reason.Reviewer, reason.Detail)
		}
	}

	if len(reviews) != len(context.RequiredReviewers) {
		permit.addReason("REVIEW_COUNT_MISMATCH", "", fmt.Sprintf(
			"received %d reviews for a %d-reviewer quorum",
			len(reviews), len(context.RequiredReviewers),
		))
	}

	if len(permit.Reasons) > 0 {
		permit.Decision = DecisionDeny
	}
	sort.Slice(permit.Reasons, func(i, j int) bool {
		left := permit.Reasons[i].Code + "\x00" + permit.Reasons[i].Reviewer + "\x00" + permit.Reasons[i].Detail
		right := permit.Reasons[j].Code + "\x00" + permit.Reasons[j].Reviewer + "\x00" + permit.Reasons[j].Detail
		return left < right
	})

	digestInput := permit
	digestInput.PermitID = ""
	encoded, err := json.Marshal(digestInput)
	if err != nil {
		return Permit{}, fmt.Errorf("marshal permit digest input: %w", err)
	}
	digest := sha256.Sum256(encoded)
	permit.PermitID = "sha256:" + hex.EncodeToString(digest[:])
	return permit, nil
}

func validateContext(context Context) error {
	var problems []string
	if context.Schema != ContextSchema {
		problems = append(problems, "unsupported context schema")
	}
	if !repositoryPattern.MatchString(context.Repository) {
		problems = append(problems, "invalid repository")
	}
	if context.Event != "pull_request" {
		problems = append(problems, "event must be pull_request")
	}
	if context.PullRequest <= 0 {
		problems = append(problems, "pull_request must be positive")
	}
	if !strings.HasPrefix(context.BaseRef, "refs/heads/") {
		problems = append(problems, "base_ref must be a branch ref")
	}
	if !hexSHA40Pattern.MatchString(context.BaseSHA) {
		problems = append(problems, "base_sha must be a lowercase 40-character Git SHA")
	}
	if !hexSHA40Pattern.MatchString(context.HeadSHA) {
		problems = append(problems, "head_sha must be a lowercase 40-character Git SHA")
	}
	if !hexSHA40Pattern.MatchString(context.MergeSHA) {
		problems = append(problems, "merge_sha must be a lowercase 40-character Git SHA")
	}
	if !hexSHA40Pattern.MatchString(context.MergeTreeSHA) {
		problems = append(problems, "merge_tree_sha must be a lowercase 40-character Git SHA")
	}
	if !repositoryPattern.MatchString(context.WorkflowRepository) {
		problems = append(problems, "invalid workflow_repository")
	}
	if !strings.HasPrefix(context.WorkflowPath, ".github/workflows/") ||
		(!strings.HasSuffix(context.WorkflowPath, ".yml") && !strings.HasSuffix(context.WorkflowPath, ".yaml")) {
		problems = append(problems, "workflow_path must name a GitHub Actions workflow")
	}
	workflowRef := context.WorkflowRef
	workflowIdentityPrefix := context.WorkflowRepository + "/" + context.WorkflowPath + "@"
	if strings.HasPrefix(workflowRef, workflowIdentityPrefix) {
		workflowRef = strings.TrimPrefix(workflowRef, workflowIdentityPrefix)
	}
	if !strings.HasPrefix(workflowRef, "refs/heads/") && !strings.HasPrefix(workflowRef, "refs/tags/") {
		problems = append(problems, "workflow_ref must be a branch or tag ref")
	}
	if !hexSHA40Pattern.MatchString(context.WorkflowSHA) {
		problems = append(problems, "workflow_sha must be a lowercase 40-character Git SHA")
	}
	if context.RunID <= 0 || context.RunAttempt <= 0 {
		problems = append(problems, "run_id and run_attempt must be positive")
	}
	if _, err := time.Parse(time.RFC3339, context.IssuedAt); err != nil {
		problems = append(problems, "issued_at must be RFC3339")
	}
	if len(context.RequiredReviewers) != 2 {
		problems = append(problems, "exactly two reviewers are required")
	} else {
		seenKeys := map[string]bool{}
		seenProviders := map[string]bool{}
		for _, reviewer := range context.RequiredReviewers {
			key := reviewerKey(reviewer)
			if reviewer.Provider == "" || reviewer.Model == "" {
				problems = append(problems, "reviewer provider and model are required")
			}
			if strings.Contains(reviewer.Provider, "/") || strings.Contains(reviewer.Model, "/") {
				problems = append(problems, "reviewer provider and model cannot contain slash")
			}
			if seenKeys[key] {
				problems = append(problems, "required reviewers must be unique")
			}
			if seenProviders[reviewer.Provider] {
				problems = append(problems, "required reviewers must use distinct providers")
			}
			seenKeys[key] = true
			seenProviders[reviewer.Provider] = true
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func validateReview(context Context, contextSHA256 string, review Review) (ReviewSummary, []Reason) {
	key := reviewerKey(review.Reviewer)
	summary := ReviewSummary{
		Reviewer:       review.Reviewer,
		Verdict:        review.Verdict,
		ResponseSHA256: review.ResponseSHA256,
	}
	var reasons []Reason
	add := func(code, detail string) {
		reasons = append(reasons, Reason{Code: code, Reviewer: key, Detail: detail})
	}

	if review.Schema != ReviewSchema {
		add("REVIEW_SCHEMA_INVALID", "unsupported review schema")
	}
	if review.Reviewer.Provider == "" || review.Reviewer.Model == "" ||
		strings.Contains(review.Reviewer.Provider, "/") || strings.Contains(review.Reviewer.Model, "/") {
		add("REVIEW_REVIEWER_INVALID", "reviewer provider and model must be non-empty and cannot contain slash")
	}
	if review.Repository != context.Repository ||
		review.PullRequest != context.PullRequest ||
		review.BaseSHA != context.BaseSHA ||
		review.HeadSHA != context.HeadSHA ||
		review.MergeSHA != context.MergeSHA ||
		review.MergeTreeSHA != context.MergeTreeSHA ||
		review.WorkflowSHA != context.WorkflowSHA ||
		review.RunID != context.RunID ||
		review.RunAttempt != context.RunAttempt {
		add("REVIEW_METADATA_MISMATCH", "review is not bound to the requested repository, commit, workflow, and run")
	}
	if review.ContextSHA256 != contextSHA256 {
		add("REVIEW_CONTEXT_MISMATCH", "review is not bound to the complete permit context")
	}
	if !hexSHA256Pattern.MatchString(review.ResponseSHA256) {
		add("REVIEW_DIGEST_INVALID", "response_sha256 must be lowercase hexadecimal")
	}
	if review.Verdict != DecisionAllow && review.Verdict != DecisionDeny {
		add("REVIEW_VERDICT_INVALID", "verdict must be ALLOW or DENY")
	} else if review.Verdict == DecisionDeny {
		add("REVIEW_DENIED", "reviewer denied the proposed change")
	}
	if review.Findings == nil || len(review.Findings) > 200 {
		add("REVIEW_FINDINGS_INVALID", "review findings must be an explicit array of at most 200 items")
	}
	for _, finding := range review.Findings {
		if finding.Code == "" || finding.Summary == "" || len(finding.Code) > 120 || len(finding.Summary) > 2000 {
			add("REVIEW_FINDINGS_INVALID", "finding code and bounded summary are required")
			continue
		}
		if finding.Line < 0 {
			add("REVIEW_FINDINGS_INVALID", "finding line cannot be negative")
			continue
		}
		switch finding.Severity {
		case "P0", "P1", "P2":
			summary.BlockingFindings++
		case "P3":
			summary.AdvisoryFindings++
		default:
			add("REVIEW_FINDINGS_INVALID", "finding severity must be P0, P1, P2, or P3")
		}
	}
	if summary.BlockingFindings > 0 {
		add("BLOCKING_FINDING", fmt.Sprintf("review contains %d P0-P2 findings", summary.BlockingFindings))
	}
	return summary, reasons
}

func (permit *Permit) addReason(code, reviewer, detail string) {
	for _, existing := range permit.Reasons {
		if existing.Code == code && existing.Reviewer == reviewer && existing.Detail == detail {
			return
		}
	}
	permit.Reasons = append(permit.Reasons, Reason{Code: code, Reviewer: reviewer, Detail: detail})
}

func reviewerKey(reviewer Reviewer) string {
	return reviewer.Provider + "/" + reviewer.Model
}
