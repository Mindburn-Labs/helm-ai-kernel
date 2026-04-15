// Package github is a STUB connector. All public methods return "not connected"
// errors until a real GitHub REST/GraphQL client ships with OAuth, rate-limit
// handling, retry, and pagination. Tracked as roadmap item P2-01 (real connector
// set: GitHub + Slack + Linear). DO NOT depend on this package for production
// workloads — the stub return value is a sentinel error, not a placeholder value.
package github

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is an HTTP client for the GitHub REST API. STUB — see package doc.
// All methods return descriptive errors until a personal access token is configured.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new GitHub API client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ListPRs lists pull requests for a repository.
func (c *Client) ListPRs(_ context.Context, repo, state string) (*ListPRsResponse, error) {
	return nil, fmt.Errorf("github: ListPRs(%q, state=%q): not connected: requires personal access token", repo, state)
}

// ReadPR retrieves details of a specific pull request.
func (c *Client) ReadPR(_ context.Context, repo string, number int) (*PullRequest, error) {
	return nil, fmt.Errorf("github: ReadPR(%q, #%d): not connected: requires personal access token", repo, number)
}

// CreateIssue creates a new issue in a repository.
func (c *Client) CreateIssue(_ context.Context, req *CreateIssueRequest) (*CreateIssueResponse, error) {
	return nil, fmt.Errorf("github: CreateIssue(%q, %q): not connected: requires personal access token", req.Repo, req.Title)
}

// AddComment adds a comment to an issue or pull request.
func (c *Client) AddComment(_ context.Context, req *AddCommentRequest) (*AddCommentResponse, error) {
	return nil, fmt.Errorf("github: AddComment(%q, #%d): not connected: requires personal access token", req.Repo, req.IssueNumber)
}
