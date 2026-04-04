// Package github provides a HELM connector for the GitHub API.
//
// Architecture:
//   - types.go:     Request/response types for GitHub operations
//   - client.go:    HTTP client stub (requires personal access token for production use)
//   - connector.go: High-level connector composing client + ZeroTrust gate + ProofGraph
//
// Per HELM Standard v1.2: every tool call becomes an INTENT -> EFFECT chain
// in the ProofGraph DAG.
package github

import "time"

// ConnectorID is the canonical identifier for this connector.
const ConnectorID = "github-v1"

// AllowedDataClasses returns the data class allowlist for the GitHub connector.
func AllowedDataClasses() []string {
	return []string{
		"github.pr.list",
		"github.pr.read",
		"github.issue.create",
		"github.comment.add",
	}
}

// toolDataClassMap maps tool names to their required data classes.
var toolDataClassMap = map[string]string{
	"github.list_prs":     "github.pr.list",
	"github.read_pr":      "github.pr.read",
	"github.create_issue": "github.issue.create",
	"github.add_comment":  "github.comment.add",
}

// PullRequest represents a GitHub pull request.
type PullRequest struct {
	Number     int       `json:"number"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	State      string    `json:"state"`
	Author     string    `json:"author"`
	HeadBranch string    `json:"head_branch"`
	BaseBranch string    `json:"base_branch"`
	CreatedAt  time.Time `json:"created_at"`
}

// ListPRsResponse is the response from listing pull requests.
type ListPRsResponse struct {
	PullRequests []PullRequest `json:"pull_requests"`
}

// CreateIssueRequest is the request to create a new GitHub issue.
type CreateIssueRequest struct {
	Repo      string   `json:"repo"`
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Labels    []string `json:"labels,omitempty"`
	Assignees []string `json:"assignees,omitempty"`
}

// CreateIssueResponse is the response after creating an issue.
type CreateIssueResponse struct {
	Number  int    `json:"number"`
	HtmlURL string `json:"html_url"`
}

// AddCommentRequest is the request to add a comment to an issue or PR.
type AddCommentRequest struct {
	Repo        string `json:"repo"`
	IssueNumber int    `json:"issue_number"`
	Body        string `json:"body"`
}

// AddCommentResponse is the response after adding a comment.
type AddCommentResponse struct {
	CommentID int64     `json:"comment_id"`
	CreatedAt time.Time `json:"created_at"`
}
