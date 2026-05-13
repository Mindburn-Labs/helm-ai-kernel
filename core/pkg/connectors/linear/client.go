// Package linear provides a HELM connector for the Linear GraphQL API.
//
// This file implements a real Linear GraphQL client (https://api.linear.app/graphql).
//
// Two construction modes:
//   - NewClient(baseURL)                   — no API key, all calls return
//     "not connected" sentinels (backward-compat for unit tests).
//   - NewClientWithToken(baseURL, apiKey)  — authenticated GraphQL mutations
//     and queries with retry-on-5xx/429, rate-limit awareness, and
//     structured error mapping from Linear's `errors` array.
//
// Supported tools (HELM tool → GraphQL op):
//   - linear.create_issue → mutation issueCreate
//   - linear.update_issue → mutation issueUpdate
//   - linear.get_issue    → query     issue
//   - linear.list_issues  → query     issues
//   - linear.add_comment  → mutation commentCreate
package linear

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// defaultBaseURL is Linear's public GraphQL endpoint.
const defaultBaseURL = "https://api.linear.app/graphql"

// userAgent identifies HELM on requests to api.linear.app.
const userAgent = "helm-ai-kernel/0.4.0 (+https://github.com/Mindburn-Labs/helm-ai-kernel)"

// maxRetries bounds transient-failure retries.
const maxRetries = 3

// Client is a Linear GraphQL client.
// An empty apiKey results in "not connected" errors (safe for unit tests).
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	userAgent  string
}

// NewClient creates a Linear client without authentication.
// All methods return sentinel errors. Use NewClientWithToken for real calls.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: userAgent,
	}
}

// NewClientWithToken creates an authenticated Linear client. Accepts either
// a personal API key (lin_api_...) or an OAuth bearer token. For API keys
// Linear expects the key as the raw Authorization value; for OAuth, HELM
// auto-detects and adds "Bearer " per Linear's spec.
func NewClientWithToken(baseURL, apiKey string) *Client {
	c := NewClient(baseURL)
	c.apiKey = apiKey
	return c
}

// CreateIssue creates a new issue in Linear.
func (c *Client) CreateIssue(ctx context.Context, req *CreateIssueRequest) (*CreateIssueResponse, error) {
	if req == nil {
		return nil, errors.New("linear: CreateIssue: nil request")
	}
	if c.apiKey == "" {
		return nil, fmt.Errorf("linear: CreateIssue(team=%q, title=%q): not connected: requires API key", req.TeamID, req.Title)
	}
	if req.TeamID == "" {
		return nil, errors.New("linear: CreateIssue: team_id required")
	}
	if req.Title == "" {
		return nil, errors.New("linear: CreateIssue: title required")
	}

	input := map[string]any{
		"teamId": req.TeamID,
		"title":  req.Title,
	}
	if req.Description != "" {
		input["description"] = req.Description
	}
	if req.Priority != "" {
		if p, ok := priorityStringToInt(req.Priority); ok {
			input["priority"] = p
		}
	}
	if req.AssigneeID != "" {
		input["assigneeId"] = req.AssigneeID
	}
	if len(req.LabelIDs) > 0 {
		input["labelIds"] = req.LabelIDs
	}

	query := `mutation IssueCreate($input: IssueCreateInput!) {
		issueCreate(input: $input) {
			success
			issue { id identifier }
		}
	}`
	var out struct {
		IssueCreate struct {
			Success bool `json:"success"`
			Issue   struct {
				ID         string `json:"id"`
				Identifier string `json:"identifier"`
			} `json:"issue"`
		} `json:"issueCreate"`
	}
	if err := c.doGraphQL(ctx, query, map[string]any{"input": input}, &out); err != nil {
		return nil, err
	}
	if !out.IssueCreate.Success {
		return nil, errors.New("linear: CreateIssue: server reported success=false")
	}
	return &CreateIssueResponse{
		IssueID:    out.IssueCreate.Issue.ID,
		Identifier: out.IssueCreate.Issue.Identifier,
	}, nil
}

// UpdateIssue updates fields on an existing Linear issue.
func (c *Client) UpdateIssue(ctx context.Context, req *UpdateIssueRequest) error {
	if req == nil {
		return errors.New("linear: UpdateIssue: nil request")
	}
	if c.apiKey == "" {
		return fmt.Errorf("linear: UpdateIssue(%q): not connected: requires API key", req.IssueID)
	}
	if req.IssueID == "" {
		return errors.New("linear: UpdateIssue: issue_id required")
	}

	input := map[string]any{}
	if req.Title != nil {
		input["title"] = *req.Title
	}
	if req.Description != nil {
		input["description"] = *req.Description
	}
	if req.State != nil {
		input["stateId"] = *req.State
	}
	if req.Priority != nil {
		if p, ok := priorityStringToInt(*req.Priority); ok {
			input["priority"] = p
		}
	}
	if req.AssigneeID != nil {
		input["assigneeId"] = *req.AssigneeID
	}
	if len(input) == 0 {
		return errors.New("linear: UpdateIssue: no fields to update")
	}

	query := `mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
		issueUpdate(id: $id, input: $input) {
			success
		}
	}`
	var out struct {
		IssueUpdate struct {
			Success bool `json:"success"`
		} `json:"issueUpdate"`
	}
	if err := c.doGraphQL(ctx, query, map[string]any{"id": req.IssueID, "input": input}, &out); err != nil {
		return err
	}
	if !out.IssueUpdate.Success {
		return errors.New("linear: UpdateIssue: server reported success=false")
	}
	return nil
}

// GetIssue retrieves a Linear issue by ID.
func (c *Client) GetIssue(ctx context.Context, issueID string) (*GetIssueResponse, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("linear: GetIssue(%q): not connected: requires API key", issueID)
	}
	if issueID == "" {
		return nil, errors.New("linear: GetIssue: issue_id required")
	}

	query := `query Issue($id: String!) {
		issue(id: $id) {
			id
			title
			description
			priorityLabel
			state { name }
			assignee { name }
			createdAt
			updatedAt
		}
	}`
	var out struct {
		Issue linearIssueNode `json:"issue"`
	}
	if err := c.doGraphQL(ctx, query, map[string]any{"id": issueID}, &out); err != nil {
		return nil, err
	}
	return &GetIssueResponse{Issue: out.Issue.toModel()}, nil
}

// ListIssues lists Linear issues, optionally filtered by team and/or state.
// `state` is compared against the human-readable state name (e.g., "Todo", "In Progress").
func (c *Client) ListIssues(ctx context.Context, teamID, state string) (*ListIssuesResponse, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("linear: ListIssues(team=%q, state=%q): not connected: requires API key", teamID, state)
	}

	filter := map[string]any{}
	if teamID != "" {
		filter["team"] = map[string]any{"id": map[string]any{"eq": teamID}}
	}
	if state != "" {
		filter["state"] = map[string]any{"name": map[string]any{"eq": state}}
	}

	query := `query Issues($filter: IssueFilter, $first: Int) {
		issues(filter: $filter, first: $first) {
			nodes {
				id
				title
				description
				priorityLabel
				state { name }
				assignee { name }
				createdAt
				updatedAt
			}
		}
	}`
	vars := map[string]any{"first": 100}
	if len(filter) > 0 {
		vars["filter"] = filter
	}
	var out struct {
		Issues struct {
			Nodes []linearIssueNode `json:"nodes"`
		} `json:"issues"`
	}
	if err := c.doGraphQL(ctx, query, vars, &out); err != nil {
		return nil, err
	}
	resp := &ListIssuesResponse{Issues: make([]Issue, 0, len(out.Issues.Nodes))}
	for _, n := range out.Issues.Nodes {
		resp.Issues = append(resp.Issues, n.toModel())
	}
	return resp, nil
}

// AddComment adds a comment to a Linear issue.
func (c *Client) AddComment(ctx context.Context, req *AddCommentRequest) (*AddCommentResponse, error) {
	if req == nil {
		return nil, errors.New("linear: AddComment: nil request")
	}
	if c.apiKey == "" {
		return nil, fmt.Errorf("linear: AddComment(issue=%q): not connected: requires API key", req.IssueID)
	}
	if req.IssueID == "" {
		return nil, errors.New("linear: AddComment: issue_id required")
	}
	if req.Body == "" {
		return nil, errors.New("linear: AddComment: body required")
	}

	query := `mutation CommentCreate($input: CommentCreateInput!) {
		commentCreate(input: $input) {
			success
			comment { id createdAt }
		}
	}`
	var out struct {
		CommentCreate struct {
			Success bool `json:"success"`
			Comment struct {
				ID        string    `json:"id"`
				CreatedAt time.Time `json:"createdAt"`
			} `json:"comment"`
		} `json:"commentCreate"`
	}
	input := map[string]any{
		"issueId": req.IssueID,
		"body":    req.Body,
	}
	if err := c.doGraphQL(ctx, query, map[string]any{"input": input}, &out); err != nil {
		return nil, err
	}
	if !out.CommentCreate.Success {
		return nil, errors.New("linear: AddComment: server reported success=false")
	}
	return &AddCommentResponse{
		CommentID: out.CommentCreate.Comment.ID,
		CreatedAt: out.CommentCreate.Comment.CreatedAt,
	}, nil
}

// linearIssueNode is the raw GraphQL shape; toModel() flattens into HELM's Issue.
type linearIssueNode struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	PriorityLabel string `json:"priorityLabel"`
	State         struct {
		Name string `json:"name"`
	} `json:"state"`
	Assignee *struct {
		Name string `json:"name"`
	} `json:"assignee"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (n linearIssueNode) toModel() Issue {
	assignee := ""
	if n.Assignee != nil {
		assignee = n.Assignee.Name
	}
	return Issue{
		ID:           n.ID,
		Title:        n.Title,
		Description:  n.Description,
		State:        n.State.Name,
		Priority:     n.PriorityLabel,
		AssigneeName: assignee,
		CreatedAt:    n.CreatedAt,
		UpdatedAt:    n.UpdatedAt,
	}
}

// priorityStringToInt maps HELM's human priority labels to Linear's integer scale.
// Linear: 0=None, 1=Urgent, 2=High, 3=Medium, 4=Low.
func priorityStringToInt(s string) (int, bool) {
	switch s {
	case "None", "none":
		return 0, true
	case "Urgent", "urgent":
		return 1, true
	case "High", "high":
		return 2, true
	case "Medium", "medium":
		return 3, true
	case "Low", "low":
		return 4, true
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 4 {
		return n, true
	}
	return 0, false
}

// APIError is a structured error from Linear's GraphQL endpoint.
// Linear returns 200 + errors[] on logical failures; HTTP 4xx/5xx on auth/rate.
type APIError struct {
	StatusCode int
	Messages   []string
	Extensions []map[string]any
	RetryAfter time.Duration
	RawBody    string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if len(e.Messages) == 0 {
		return fmt.Sprintf("linear api: %d: (no message)", e.StatusCode)
	}
	return fmt.Sprintf("linear api: %d: %s", e.StatusCode, e.Messages[0])
}

// doGraphQL posts a GraphQL query or mutation to Linear with auth, retry on
// transient failures, and structured error parsing.
func (c *Client) doGraphQL(ctx context.Context, query string, variables map[string]any, out any) error {
	payload := map[string]any{
		"query":     query,
		"variables": variables,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	// Linear personal API keys are sent as the raw Authorization value
	// (no "Bearer " prefix). OAuth tokens need "Bearer " — auto-detect.
	authValue := c.apiKey
	if looksLikeOAuthToken(c.apiKey) {
		authValue = "Bearer " + c.apiKey
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", authValue)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("transport error: %w", err)
			if !shouldRetry(attempt) {
				return lastErr
			}
			time.Sleep(backoff(attempt))
			continue
		}
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("read response body: %w", readErr)
			if !shouldRetry(attempt) {
				return lastErr
			}
			time.Sleep(backoff(attempt))
			continue
		}

		// 429: rate limit — honor Retry-After.
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := retryAfter(resp)
			lastErr = &APIError{
				StatusCode: resp.StatusCode,
				Messages:   []string{"rate limited"},
				RetryAfter: wait,
				RawBody:    string(respBody),
			}
			if !shouldRetry(attempt) {
				return lastErr
			}
			if wait > 60*time.Second {
				wait = 60 * time.Second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		// 5xx: retry.
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			lastErr = &APIError{
				StatusCode: resp.StatusCode,
				Messages:   []string{"server error"},
				RawBody:    string(respBody),
			}
			if !shouldRetry(attempt) {
				return lastErr
			}
			time.Sleep(backoff(attempt))
			continue
		}

		// 4xx: non-retryable auth/validation error.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return &APIError{
				StatusCode: resp.StatusCode,
				Messages:   []string{http.StatusText(resp.StatusCode)},
				RawBody:    string(respBody),
			}
		}

		// 2xx: parse GraphQL envelope.
		var envelope struct {
			Data   json.RawMessage `json:"data"`
			Errors []struct {
				Message    string         `json:"message"`
				Extensions map[string]any `json:"extensions,omitempty"`
			} `json:"errors,omitempty"`
		}
		if err := json.Unmarshal(respBody, &envelope); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		if len(envelope.Errors) > 0 {
			msgs := make([]string, 0, len(envelope.Errors))
			exts := make([]map[string]any, 0, len(envelope.Errors))
			for _, e := range envelope.Errors {
				msgs = append(msgs, e.Message)
				if e.Extensions != nil {
					exts = append(exts, e.Extensions)
				}
			}
			return &APIError{
				StatusCode: resp.StatusCode,
				Messages:   msgs,
				Extensions: exts,
				RawBody:    string(respBody),
			}
		}
		if out != nil && len(envelope.Data) > 0 {
			if err := json.Unmarshal(envelope.Data, out); err != nil {
				return fmt.Errorf("decode data: %w", err)
			}
		}
		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("linear: retries exhausted without a definitive result")
	}
	return lastErr
}

// looksLikeOAuthToken returns true if the token looks like a Linear OAuth token
// (they begin with a UUID-ish prefix; personal API keys begin with "lin_api_").
func looksLikeOAuthToken(s string) bool {
	if len(s) < 8 {
		return false
	}
	// Personal API keys start with "lin_api_".
	if len(s) >= 8 && s[:8] == "lin_api_" {
		return false
	}
	// Default: treat as OAuth bearer token.
	return true
}

// retryAfter returns the delay for a 429 response.
func retryAfter(resp *http.Response) time.Duration {
	if s := resp.Header.Get("Retry-After"); s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 5 * time.Second
}

func backoff(attempt int) time.Duration { return 500 * time.Millisecond << attempt }
func shouldRetry(attempt int) bool      { return attempt < maxRetries-1 }
