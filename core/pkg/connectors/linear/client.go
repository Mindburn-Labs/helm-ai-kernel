// Package linear is a STUB connector. All public methods return "not connected"
// errors until a real Linear GraphQL client ships. Tracked as roadmap item P2-03
// (real connector set: GitHub + Slack + Linear). DO NOT depend on this package
// for production workloads.
package linear

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is an HTTP client for the Linear GraphQL API. STUB — see package doc.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Linear API client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateIssue creates a new issue in Linear.
func (c *Client) CreateIssue(_ context.Context, req *CreateIssueRequest) (*CreateIssueResponse, error) {
	return nil, fmt.Errorf("linear: CreateIssue(team=%q, title=%q): not connected: requires API key", req.TeamID, req.Title)
}

// UpdateIssue updates an existing issue in Linear.
func (c *Client) UpdateIssue(_ context.Context, req *UpdateIssueRequest) error {
	return fmt.Errorf("linear: UpdateIssue(%q): not connected: requires API key", req.IssueID)
}

// GetIssue retrieves a single issue by ID.
// TODO: Implement GraphQL query against Linear API.
// The real implementation should send a query like:
//
//	query { issue(id: "...") { id title description state { name } priority assignee { name } createdAt updatedAt } }
//
// Rate limiting: Linear enforces 1,500 requests/hour with complexity-weighted
// cost per query. The connector's ZeroTrustGate rate limit should stay well
// below this ceiling.
func (c *Client) GetIssue(_ context.Context, issueID string) (*GetIssueResponse, error) {
	return nil, fmt.Errorf("linear: GetIssue(%q): not connected: requires API key", issueID)
}

// ListIssues lists issues, optionally filtered by team or state.
func (c *Client) ListIssues(_ context.Context, teamID, state string) (*ListIssuesResponse, error) {
	return nil, fmt.Errorf("linear: ListIssues(team=%q, state=%q): not connected: requires API key", teamID, state)
}

// AddComment adds a comment to a Linear issue.
func (c *Client) AddComment(_ context.Context, req *AddCommentRequest) (*AddCommentResponse, error) {
	return nil, fmt.Errorf("linear: AddComment(issue=%q): not connected: requires API key", req.IssueID)
}
