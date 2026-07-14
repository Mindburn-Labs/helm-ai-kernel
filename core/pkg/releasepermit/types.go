// Package releasepermit reduces independent, commit-bound AI review results
// into a deterministic release decision. Model output is advisory until this
// reducer validates the complete review quorum and its GitHub workflow binding.
package releasepermit

const (
	ContextSchema   = "mindburn.release-permit-context/v2"
	ReviewSchema    = "mindburn.release-review/v1"
	PermitSchema    = "mindburn.release-permit/v2"
	AuthoritySchema = "mindburn.release-authority/v1"

	DecisionAllow = "ALLOW"
	DecisionDeny  = "DENY"
)

// AuthorityParent identifies the immediately preceding immutable workflow
// generation. The previous generation must review and ratify the complete next
// generation before an external promotion broker advances the ruleset pin.
type AuthorityParent struct {
	Generation  int64  `json:"generation"`
	WorkflowSHA string `json:"workflow_sha"`
}

// Authority binds the workflow generation to the exact Kernel verifier and
// source-owned deterministic/adversarial policy inputs it executes.
type Authority struct {
	Schema                  string           `json:"schema"`
	Generation              int64            `json:"generation"`
	KernelSHA               string           `json:"kernel_sha"`
	GateProfilesSHA256      string           `json:"gate_profiles_sha256"`
	AdversarialCorpusSHA256 string           `json:"adversarial_corpus_sha256"`
	Parent                  *AuthorityParent `json:"parent"`
}

// Reviewer identifies one independently executed model review lane.
type Reviewer struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// Context binds a permit to the exact pull request, commit, policy workflow,
// and GitHub Actions execution that requested it.
type Context struct {
	Schema             string     `json:"schema"`
	Repository         string     `json:"repository"`
	Event              string     `json:"event"`
	PullRequest        int64      `json:"pull_request"`
	BaseRef            string     `json:"base_ref"`
	BaseSHA            string     `json:"base_sha"`
	HeadSHA            string     `json:"head_sha"`
	MergeSHA           string     `json:"merge_sha"`
	MergeTreeSHA       string     `json:"merge_tree_sha"`
	WorkflowRepository string     `json:"workflow_repository"`
	WorkflowPath       string     `json:"workflow_path"`
	WorkflowRef        string     `json:"workflow_ref"`
	WorkflowSHA        string     `json:"workflow_sha"`
	RunID              int64      `json:"run_id"`
	RunAttempt         int64      `json:"run_attempt"`
	IssuedAt           string     `json:"issued_at"`
	Authority          Authority  `json:"authority"`
	RequiredReviewers  []Reviewer `json:"required_reviewers"`
}

// Finding is one model-reported issue. P0-P2 findings block a permit; P3 is
// retained as advisory evidence.
type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Summary  string `json:"summary"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// Review is the protected workflow envelope around one model response.
type Review struct {
	Schema         string    `json:"schema"`
	Repository     string    `json:"repository"`
	PullRequest    int64     `json:"pull_request"`
	BaseSHA        string    `json:"base_sha"`
	HeadSHA        string    `json:"head_sha"`
	MergeSHA       string    `json:"merge_sha"`
	MergeTreeSHA   string    `json:"merge_tree_sha"`
	WorkflowSHA    string    `json:"workflow_sha"`
	RunID          int64     `json:"run_id"`
	RunAttempt     int64     `json:"run_attempt"`
	ContextSHA256  string    `json:"context_sha256"`
	Reviewer       Reviewer  `json:"reviewer"`
	Verdict        string    `json:"verdict"`
	ResponseSHA256 string    `json:"response_sha256"`
	Findings       []Finding `json:"findings"`
}

// Reason records one deterministic cause for a denied permit.
type Reason struct {
	Code     string `json:"code"`
	Reviewer string `json:"reviewer,omitempty"`
	Detail   string `json:"detail"`
}

// ReviewSummary retains the model identity and response digest without
// treating raw model prose as an authorization record.
type ReviewSummary struct {
	Reviewer         Reviewer `json:"reviewer"`
	Verdict          string   `json:"verdict"`
	ResponseSHA256   string   `json:"response_sha256"`
	BlockingFindings int      `json:"blocking_findings"`
	AdvisoryFindings int      `json:"advisory_findings"`
}

// Permit is the deterministic output consumed by a required GitHub workflow.
// PermitID is a SHA-256 digest over the same structure with PermitID empty.
type Permit struct {
	Schema             string          `json:"schema"`
	PermitID           string          `json:"permit_id"`
	Decision           string          `json:"decision"`
	Repository         string          `json:"repository"`
	PullRequest        int64           `json:"pull_request"`
	BaseRef            string          `json:"base_ref"`
	BaseSHA            string          `json:"base_sha"`
	HeadSHA            string          `json:"head_sha"`
	MergeSHA           string          `json:"merge_sha"`
	MergeTreeSHA       string          `json:"merge_tree_sha"`
	WorkflowRepository string          `json:"workflow_repository"`
	WorkflowPath       string          `json:"workflow_path"`
	WorkflowRef        string          `json:"workflow_ref"`
	WorkflowSHA        string          `json:"workflow_sha"`
	RunID              int64           `json:"run_id"`
	RunAttempt         int64           `json:"run_attempt"`
	IssuedAt           string          `json:"issued_at"`
	Authority          Authority       `json:"authority"`
	ContextSHA256      string          `json:"context_sha256"`
	Reviews            []ReviewSummary `json:"reviews"`
	Reasons            []Reason        `json:"reasons"`
}
