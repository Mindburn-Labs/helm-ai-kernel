// Package linear provides a HELM connector for the Linear project management API.
//
// Architecture:
//   - types.go:     Request/response types for Linear operations
//   - client.go:    HTTP client stub (requires API key for production use)
//   - connector.go: High-level connector composing client + ZeroTrust gate + ProofGraph
//
// Per HELM Standard v1.2: every tool call becomes an INTENT -> EFFECT chain
// in the ProofGraph DAG.
package linear

import "time"

// ConnectorID is the canonical identifier for this connector.
const ConnectorID = "linear-v1"

// AllowedDataClasses returns the data class allowlist for the Linear connector.
func AllowedDataClasses() []string {
	return []string{
		"linear.issue.create",
		"linear.issue.update",
		"linear.issue.list",
		"linear.comment.add",
	}
}

// toolDataClassMap maps tool names to their required data classes.
var toolDataClassMap = map[string]string{
	"linear.create_issue": "linear.issue.create",
	"linear.update_issue": "linear.issue.update",
	"linear.list_issues":  "linear.issue.list",
	"linear.add_comment":  "linear.comment.add",
}

// Issue represents a Linear issue.
type Issue struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	State        string    `json:"state"`
	Priority     string    `json:"priority"`
	AssigneeName string    `json:"assignee_name"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// CreateIssueRequest is the request to create a new Linear issue.
type CreateIssueRequest struct {
	TeamID      string   `json:"team_id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Priority    string   `json:"priority,omitempty"`
	AssigneeID  string   `json:"assignee_id,omitempty"`
	LabelIDs    []string `json:"label_ids,omitempty"`
}

// CreateIssueResponse is the response after creating an issue.
type CreateIssueResponse struct {
	IssueID    string `json:"issue_id"`
	Identifier string `json:"identifier"`
}

// UpdateIssueRequest is the request to update a Linear issue.
type UpdateIssueRequest struct {
	IssueID     string  `json:"issue_id"`
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
	State       *string `json:"state,omitempty"`
	Priority    *string `json:"priority,omitempty"`
	AssigneeID  *string `json:"assignee_id,omitempty"`
}

// ListIssuesResponse is the response from listing Linear issues.
type ListIssuesResponse struct {
	Issues []Issue `json:"issues"`
}

// AddCommentRequest is the request to add a comment to a Linear issue.
type AddCommentRequest struct {
	IssueID string `json:"issue_id"`
	Body    string `json:"body"`
}

// AddCommentResponse is the response after adding a comment.
type AddCommentResponse struct {
	CommentID string    `json:"comment_id"`
	CreatedAt time.Time `json:"created_at"`
}
