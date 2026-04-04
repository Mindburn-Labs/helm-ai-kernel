package linear

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is an HTTP client for the Linear GraphQL API.
// All methods return descriptive errors until an API key is configured.
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

// ListIssues lists issues, optionally filtered by team or state.
func (c *Client) ListIssues(_ context.Context, teamID, state string) (*ListIssuesResponse, error) {
	return nil, fmt.Errorf("linear: ListIssues(team=%q, state=%q): not connected: requires API key", teamID, state)
}

// AddComment adds a comment to a Linear issue.
func (c *Client) AddComment(_ context.Context, req *AddCommentRequest) (*AddCommentResponse, error) {
	return nil, fmt.Errorf("linear: AddComment(issue=%q): not connected: requires API key", req.IssueID)
}
