package releasepermit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	hexSHA40Pattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexSHA256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reviewerPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
)

const maxFindings = 200

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
		Authority:          context.Authority,
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
		if !reviewerPattern.MatchString(review.Reviewer.Provider) || !reviewerPattern.MatchString(review.Reviewer.Model) {
			permit.addReason("REVIEW_REVIEWER_INVALID", key, "reviewer provider and model must be canonical lowercase identifiers")
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

	permitID, err := calculatePermitID(permit)
	if err != nil {
		return Permit{}, err
	}
	permit.PermitID = permitID
	return permit, nil
}

// ValidateAllowPermit verifies that an existing serialized permit is a complete,
// internally consistent ALLOW decision bound to an independently trusted
// context and exact reviewer quorum. This is semantic validation, not artifact
// authentication: callers must first verify the permit's signed provenance.
func ValidateAllowPermit(permit Permit, trustedContext Context, contextSHA256 string) error {
	var problems []string
	if err := validateContext(trustedContext); err != nil {
		problems = append(problems, "trusted context is invalid: "+err.Error())
	}
	if !hexSHA256Pattern.MatchString(contextSHA256) {
		problems = append(problems, "trusted context_sha256 must be lowercase hexadecimal")
	}
	contextMatch := func(label string, matches bool) {
		if !matches {
			problems = append(problems, label+" does not match the trusted context")
		}
	}
	contextMatch("repository", permit.Repository == trustedContext.Repository)
	contextMatch("pull_request", permit.PullRequest == trustedContext.PullRequest)
	contextMatch("base_ref", permit.BaseRef == trustedContext.BaseRef)
	contextMatch("base_sha", permit.BaseSHA == trustedContext.BaseSHA)
	contextMatch("head_sha", permit.HeadSHA == trustedContext.HeadSHA)
	contextMatch("merge_sha", permit.MergeSHA == trustedContext.MergeSHA)
	contextMatch("merge_tree_sha", permit.MergeTreeSHA == trustedContext.MergeTreeSHA)
	contextMatch("workflow_repository", permit.WorkflowRepository == trustedContext.WorkflowRepository)
	contextMatch("workflow_path", permit.WorkflowPath == trustedContext.WorkflowPath)
	contextMatch("workflow_ref", permit.WorkflowRef == trustedContext.WorkflowRef)
	contextMatch("workflow_sha", permit.WorkflowSHA == trustedContext.WorkflowSHA)
	contextMatch("run_id", permit.RunID == trustedContext.RunID)
	contextMatch("run_attempt", permit.RunAttempt == trustedContext.RunAttempt)
	contextMatch("issued_at", permit.IssuedAt == trustedContext.IssuedAt)
	contextMatch("authority", reflect.DeepEqual(permit.Authority, trustedContext.Authority))
	contextMatch("context_sha256", permit.ContextSHA256 == contextSHA256)

	expectedReviewers := make(map[string]struct{}, len(trustedContext.RequiredReviewers))
	for _, reviewer := range trustedContext.RequiredReviewers {
		expectedReviewers[reviewerKey(reviewer)] = struct{}{}
	}
	if permit.Schema != PermitSchema {
		problems = append(problems, "unsupported permit schema")
	}
	if permit.Decision != DecisionAllow {
		problems = append(problems, "permit decision must be ALLOW")
	}
	if !repositoryPattern.MatchString(permit.Repository) {
		problems = append(problems, "invalid repository")
	}
	if permit.PullRequest <= 0 {
		problems = append(problems, "pull_request must be positive")
	}
	if !validGitRef(permit.BaseRef, false) {
		problems = append(problems, "base_ref must be a branch ref")
	}
	for label, value := range map[string]string{
		"base_sha":       permit.BaseSHA,
		"head_sha":       permit.HeadSHA,
		"merge_sha":      permit.MergeSHA,
		"merge_tree_sha": permit.MergeTreeSHA,
		"workflow_sha":   permit.WorkflowSHA,
	} {
		if !hexSHA40Pattern.MatchString(value) {
			problems = append(problems, label+" must be a lowercase 40-character Git SHA")
		}
	}
	if !repositoryPattern.MatchString(permit.WorkflowRepository) {
		problems = append(problems, "invalid workflow_repository")
	}
	if !validWorkflowPath(permit.WorkflowPath) {
		problems = append(problems, "workflow_path must name a GitHub Actions workflow")
	}
	workflowRef := normalizeWorkflowRef(permit.WorkflowRepository, permit.WorkflowPath, permit.WorkflowRef)
	if !validGitRef(workflowRef, true) {
		problems = append(problems, "workflow_ref must be a branch or tag ref")
	}
	if strings.EqualFold(permit.Repository, permit.WorkflowRepository) &&
		(permit.WorkflowSHA == permit.HeadSHA || permit.WorkflowSHA == permit.MergeSHA) {
		problems = append(problems, "authority workflow cannot review its own head or merge commit")
	}
	if permit.Authority.Generation > 1 &&
		(permit.Authority.KernelSHA == permit.HeadSHA || permit.Authority.KernelSHA == permit.MergeSHA) {
		problems = append(problems, "non-bootstrap authority cannot use the target head or merge commit as its Kernel")
	}
	if permit.RunID <= 0 || permit.RunAttempt <= 0 {
		problems = append(problems, "run_id and run_attempt must be positive")
	}
	if _, err := time.Parse(time.RFC3339, permit.IssuedAt); err != nil {
		problems = append(problems, "issued_at must be RFC3339")
	}
	problems = append(problems, validateAuthority(permit.Authority, permit.WorkflowSHA)...)
	if !hexSHA256Pattern.MatchString(permit.ContextSHA256) {
		problems = append(problems, "context_sha256 must be lowercase hexadecimal")
	}
	if permit.Reasons == nil || len(permit.Reasons) != 0 {
		problems = append(problems, "ALLOW permit reasons must be an explicit empty array")
	}
	if len(permit.Reviews) != 2 {
		problems = append(problems, "ALLOW permit must contain exactly two reviews")
	} else {
		seenKeys := map[string]bool{}
		seenProviders := map[string]bool{}
		for _, review := range permit.Reviews {
			key := reviewerKey(review.Reviewer)
			if !reviewerPattern.MatchString(review.Reviewer.Provider) || !reviewerPattern.MatchString(review.Reviewer.Model) {
				problems = append(problems, "reviewer provider and model must be canonical lowercase identifiers")
			}
			if seenKeys[key] || seenProviders[review.Reviewer.Provider] {
				problems = append(problems, "ALLOW permit reviews must use unique reviewers and distinct providers")
			}
			if _, expected := expectedReviewers[key]; !expected {
				problems = append(problems, "ALLOW permit reviewer is not in the trusted context quorum")
			}
			seenKeys[key] = true
			seenProviders[review.Reviewer.Provider] = true
			if review.Verdict != DecisionAllow || review.BlockingFindings != 0 {
				problems = append(problems, "every ALLOW permit review must be non-blocking ALLOW")
			}
			if review.AdvisoryFindings < 0 || review.AdvisoryFindings > maxFindings {
				problems = append(problems, "review advisory_findings must be between 0 and 200")
			}
			if !hexSHA256Pattern.MatchString(review.ResponseSHA256) {
				problems = append(problems, "review response_sha256 must be lowercase hexadecimal")
			}
		}
		if len(seenKeys) != len(expectedReviewers) {
			problems = append(problems, "ALLOW permit reviewer quorum does not match the trusted context")
		}
	}
	permitID, err := calculatePermitID(permit)
	if err != nil {
		problems = append(problems, err.Error())
	} else if permit.PermitID != permitID {
		problems = append(problems, "permit_id does not match the canonical permit body")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func calculatePermitID(permit Permit) (string, error) {
	digestInput := permit
	digestInput.PermitID = ""
	encoded, err := json.Marshal(digestInput)
	if err != nil {
		return "", fmt.Errorf("marshal permit digest input: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
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
	if !validGitRef(context.BaseRef, false) {
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
	if !validWorkflowPath(context.WorkflowPath) {
		problems = append(problems, "workflow_path must name a GitHub Actions workflow")
	}
	workflowRef := normalizeWorkflowRef(context.WorkflowRepository, context.WorkflowPath, context.WorkflowRef)
	if !validGitRef(workflowRef, true) {
		problems = append(problems, "workflow_ref must be a branch or tag ref")
	}
	if !hexSHA40Pattern.MatchString(context.WorkflowSHA) {
		problems = append(problems, "workflow_sha must be a lowercase 40-character Git SHA")
	}
	if strings.EqualFold(context.Repository, context.WorkflowRepository) &&
		(context.WorkflowSHA == context.HeadSHA || context.WorkflowSHA == context.MergeSHA) {
		problems = append(problems, "authority workflow cannot review its own head or merge commit")
	}
	if context.Authority.Generation > 1 &&
		(context.Authority.KernelSHA == context.HeadSHA || context.Authority.KernelSHA == context.MergeSHA) {
		problems = append(problems, "non-bootstrap authority cannot use the target head or merge commit as its Kernel")
	}
	if context.RunID <= 0 || context.RunAttempt <= 0 {
		problems = append(problems, "run_id and run_attempt must be positive")
	}
	if _, err := time.Parse(time.RFC3339, context.IssuedAt); err != nil {
		problems = append(problems, "issued_at must be RFC3339")
	}
	problems = append(problems, validateAuthority(context.Authority, context.WorkflowSHA)...)
	if len(context.RequiredReviewers) != 2 {
		problems = append(problems, "exactly two reviewers are required")
	} else {
		seenKeys := map[string]bool{}
		seenProviders := map[string]bool{}
		for _, reviewer := range context.RequiredReviewers {
			key := reviewerKey(reviewer)
			if !reviewerPattern.MatchString(reviewer.Provider) || !reviewerPattern.MatchString(reviewer.Model) {
				problems = append(problems, "reviewer provider and model must be canonical lowercase identifiers")
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

func validateAuthority(authority Authority, workflowSHA string) []string {
	var problems []string
	if authority.Schema != AuthoritySchema {
		problems = append(problems, "unsupported authority schema")
	}
	if authority.Generation <= 0 {
		problems = append(problems, "authority generation must be positive")
	}
	if !hexSHA40Pattern.MatchString(authority.KernelSHA) {
		problems = append(problems, "authority kernel_sha must be a lowercase 40-character Git SHA")
	}
	if !hexSHA256Pattern.MatchString(authority.GateProfilesSHA256) {
		problems = append(problems, "authority gate_profiles_sha256 must be lowercase hexadecimal")
	}
	if !hexSHA256Pattern.MatchString(authority.AdversarialCorpusSHA256) {
		problems = append(problems, "authority adversarial_corpus_sha256 must be lowercase hexadecimal")
	}
	if authority.Generation == 1 {
		if authority.Parent != nil {
			problems = append(problems, "authority generation 1 cannot declare a parent")
		}
		return problems
	}
	if authority.Parent == nil {
		return append(problems, "authority generations after 1 require a parent")
	}
	if authority.Parent.Generation != authority.Generation-1 {
		problems = append(problems, "authority parent generation must immediately precede the current generation")
	}
	if !hexSHA40Pattern.MatchString(authority.Parent.WorkflowSHA) {
		problems = append(problems, "authority parent workflow_sha must be a lowercase 40-character Git SHA")
	} else if authority.Parent.WorkflowSHA == workflowSHA {
		problems = append(problems, "authority cannot name its own workflow SHA as its parent")
	}
	return problems
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
	if !reviewerPattern.MatchString(review.Reviewer.Provider) || !reviewerPattern.MatchString(review.Reviewer.Model) {
		add("REVIEW_REVIEWER_INVALID", "reviewer provider and model must be canonical lowercase identifiers")
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
	if review.Findings == nil || len(review.Findings) > maxFindings {
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
		if len(finding.Path) > 1000 || strings.ContainsRune(finding.Path, '\x00') {
			add("REVIEW_FINDINGS_INVALID", "finding path must be bounded and contain no NUL")
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
	return strings.ToLower(reviewer.Provider) + "/" + strings.ToLower(reviewer.Model)
}

func validWorkflowPath(path string) bool {
	const prefix = ".github/workflows/"
	name := strings.TrimPrefix(path, prefix)
	return name != path && name != "" && len(name) <= 255 &&
		!strings.ContainsAny(name, "/\\\x00\r\n") &&
		(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml"))
}

func normalizeWorkflowRef(repository, path, ref string) string {
	return strings.TrimPrefix(ref, repository+"/"+path+"@")
}

func validGitRef(ref string, allowTag bool) bool {
	prefix := "refs/heads/"
	if allowTag && strings.HasPrefix(ref, "refs/tags/") {
		prefix = "refs/tags/"
	}
	if !strings.HasPrefix(ref, prefix) || len(ref) == len(prefix) ||
		strings.ContainsAny(ref, " ~^:?*[\\") || strings.Contains(ref, "..") ||
		strings.Contains(ref, "@{") || strings.Contains(ref, "//") ||
		strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(ref, prefix), "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	for _, character := range ref {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
