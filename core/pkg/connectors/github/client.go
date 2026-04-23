// Package github provides a HELM connector for the GitHub API.
//
// This file implements a real GitHub REST API v3 client (api.github.com).
//
// Two construction modes:
//   - NewClient(baseURL)                   — no token, all calls return "not connected"
//     (backward-compat for unit tests and smoke scenarios).
//   - NewClientWithToken(baseURL, token)   — real Bearer-token auth,
//     rate-limit-aware, retry with exponential backoff, JSON body handling.
//
// When `token == ""`, methods return a sentinel "not connected: requires
// personal access token" error. This preserves deterministic smoke scenarios
// while keeping real API calls behind explicit credentials.
//
// Supported endpoints (HELM tool → REST path):
//   - github.list_prs     → GET  /repos/{owner}/{repo}/pulls?state=<state>
//   - github.read_pr      → GET  /repos/{owner}/{repo}/pulls/{number}
//   - github.create_issue → POST /repos/{owner}/{repo}/issues
//   - github.add_comment  → POST /repos/{owner}/{repo}/issues/{number}/comments
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultBaseURL is GitHub's public REST API root.
const defaultBaseURL = "https://api.github.com"

// apiVersion pins the REST API major version per GitHub's stability policy.
const apiVersion = "2022-11-28"

// userAgent identifies HELM to GitHub's servers.
// GitHub requires a non-empty User-Agent on all requests.
const userAgent = "helm-oss/0.4.0 (+https://github.com/Mindburn-Labs/helm-oss)"

// maxRetries bounds transient-failure retries. Non-retryable statuses
// (4xx other than 429) fail immediately.
const maxRetries = 3

// Client is an HTTP client for the GitHub REST API.
// When constructed without a token via NewClient, all methods return a sentinel
// "not connected" error shape. Use NewClientWithToken for real API access.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	userAgent  string
}

// NewClient creates a new GitHub API client without authentication.
// All methods on the returned client return "not connected" errors. Use this
// for tests, schema validation, or wiring sanity checks. For real API calls,
// use NewClientWithToken.
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

// NewClientWithToken creates a GitHub API client authenticated with a
// personal access token (classic or fine-grained). An empty baseURL falls
// back to GitHub's public API root.
//
// Scopes required per method:
//   - ListPRs / ReadPR:   `repo` (private) or none (public)
//   - CreateIssue:        `repo` (private) or `public_repo`
//   - AddComment:         same as CreateIssue
func NewClientWithToken(baseURL, token string) *Client {
	c := NewClient(baseURL)
	c.token = token
	return c
}

// ListPRs lists pull requests for a repository.
// `repo` is "owner/name". `state` ∈ {"open", "closed", "all"}.
func (c *Client) ListPRs(ctx context.Context, repo, state string) (*ListPRsResponse, error) {
	if c.token == "" {
		return nil, fmt.Errorf("github: ListPRs(%q, state=%q): not connected: requires personal access token", repo, state)
	}
	owner, name, err := splitRepo(repo)
	if err != nil {
		return nil, fmt.Errorf("github: ListPRs: %w", err)
	}
	if state == "" {
		state = "open"
	}

	// Pagination: GitHub caps per_page at 100. We collect up to 5 pages
	// (500 PRs) to keep memory bounded — most repos won't hit this.
	const maxPages = 5
	out := &ListPRsResponse{PullRequests: make([]PullRequest, 0, 32)}
	for page := 1; page <= maxPages; page++ {
		q := url.Values{}
		q.Set("state", state)
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		path := fmt.Sprintf("/repos/%s/%s/pulls?%s", owner, name, q.Encode())

		var raw []githubPR
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &raw); err != nil {
			return nil, err
		}
		if len(raw) == 0 {
			break
		}
		for _, pr := range raw {
			out.PullRequests = append(out.PullRequests, pr.toModel())
		}
		if len(raw) < 100 {
			break
		}
	}
	return out, nil
}

// ReadPR retrieves details of a specific pull request.
// `repo` is "owner/name".
func (c *Client) ReadPR(ctx context.Context, repo string, number int) (*PullRequest, error) {
	if c.token == "" {
		return nil, fmt.Errorf("github: ReadPR(%q, #%d): not connected: requires personal access token", repo, number)
	}
	owner, name, err := splitRepo(repo)
	if err != nil {
		return nil, fmt.Errorf("github: ReadPR: %w", err)
	}
	if number <= 0 {
		return nil, fmt.Errorf("github: ReadPR: invalid PR number %d", number)
	}
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, name, number)
	var raw githubPR
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &raw); err != nil {
		return nil, err
	}
	pr := raw.toModel()
	return &pr, nil
}

// CreateIssue creates a new issue in a repository.
func (c *Client) CreateIssue(ctx context.Context, req *CreateIssueRequest) (*CreateIssueResponse, error) {
	if req == nil {
		return nil, errors.New("github: CreateIssue: nil request")
	}
	if c.token == "" {
		return nil, fmt.Errorf("github: CreateIssue(%q, %q): not connected: requires personal access token", req.Repo, req.Title)
	}
	owner, name, err := splitRepo(req.Repo)
	if err != nil {
		return nil, fmt.Errorf("github: CreateIssue: %w", err)
	}

	body := map[string]any{
		"title": req.Title,
	}
	if req.Body != "" {
		body["body"] = req.Body
	}
	if len(req.Labels) > 0 {
		body["labels"] = req.Labels
	}
	if len(req.Assignees) > 0 {
		body["assignees"] = req.Assignees
	}

	path := fmt.Sprintf("/repos/%s/%s/issues", owner, name)
	var raw struct {
		Number  int    `json:"number"`
		HtmlURL string `json:"html_url"`
	}
	if err := c.doJSON(ctx, http.MethodPost, path, body, &raw); err != nil {
		return nil, err
	}
	return &CreateIssueResponse{Number: raw.Number, HtmlURL: raw.HtmlURL}, nil
}

// AddComment adds a comment to an issue or pull request.
// GitHub's REST API treats PRs as a specialized kind of issue; the same
// /issues/{number}/comments endpoint accepts comments on both.
func (c *Client) AddComment(ctx context.Context, req *AddCommentRequest) (*AddCommentResponse, error) {
	if req == nil {
		return nil, errors.New("github: AddComment: nil request")
	}
	if c.token == "" {
		return nil, fmt.Errorf("github: AddComment(%q, #%d): not connected: requires personal access token", req.Repo, req.IssueNumber)
	}
	owner, name, err := splitRepo(req.Repo)
	if err != nil {
		return nil, fmt.Errorf("github: AddComment: %w", err)
	}
	if req.IssueNumber <= 0 {
		return nil, fmt.Errorf("github: AddComment: invalid issue_number %d", req.IssueNumber)
	}
	if req.Body == "" {
		return nil, errors.New("github: AddComment: body required")
	}

	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, name, req.IssueNumber)
	var raw struct {
		ID        int64     `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := c.doJSON(ctx, http.MethodPost, path, map[string]any{"body": req.Body}, &raw); err != nil {
		return nil, err
	}
	return &AddCommentResponse{CommentID: raw.ID, CreatedAt: raw.CreatedAt}, nil
}

// githubPR is the raw GitHub API PR shape. toModel() flattens it into
// HELM's PullRequest type with only the fields HELM consumers care about.
type githubPR struct {
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		Ref string `json:"ref"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func (g githubPR) toModel() PullRequest {
	return PullRequest{
		Number:     g.Number,
		Title:      g.Title,
		Body:       g.Body,
		State:      g.State,
		Author:     g.User.Login,
		HeadBranch: g.Head.Ref,
		BaseBranch: g.Base.Ref,
		CreatedAt:  g.CreatedAt,
	}
}

// splitRepo parses an "owner/name" slug into its components.
// Rejects empty strings, missing slashes, and strings with more than one slash.
func splitRepo(repo string) (owner, name string, err error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "", "", errors.New("repo must be 'owner/name'")
	}
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("repo %q must be 'owner/name'", repo)
	}
	return parts[0], parts[1], nil
}

// doJSON performs an HTTP request against the GitHub REST API with
// authentication, JSON body handling, retry-on-transient-failure, and
// rate-limit awareness. The out parameter is JSON-decoded on 2xx success;
// for methods where no body is expected, pass a *struct{} or nil.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyBytes = b
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytesReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", apiVersion)
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Authorization", "Bearer "+c.token)
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("transport error: %w", err)
			if !shouldRetry(attempt) {
				return lastErr
			}
			time.Sleep(backoff(attempt))
			continue
		}

		// Always drain + close body so connections can be reused.
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

		// Rate-limit primary: 429 with Retry-After (secondary rate limit)
		// or 403 with X-RateLimit-Remaining: 0 (primary rate limit).
		if resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0") {
			wait := retryAfter(resp)
			lastErr = &APIError{
				StatusCode: resp.StatusCode,
				Message:    "rate limited",
				RetryAfter: wait,
				RawBody:    string(respBody),
			}
			if !shouldRetry(attempt) {
				return lastErr
			}
			// cap wait at 60s to avoid pathological stalls
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

		// 5xx: retry with exponential backoff.
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			lastErr = &APIError{
				StatusCode: resp.StatusCode,
				Message:    "server error",
				RawBody:    string(respBody),
			}
			if !shouldRetry(attempt) {
				return lastErr
			}
			time.Sleep(backoff(attempt))
			continue
		}

		// 4xx: structured error, no retry.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return parseAPIError(resp, respBody)
		}

		// 2xx success. Decode body if caller wants it.
		if out != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
		}
		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("github: retries exhausted without a definitive result")
	}
	return lastErr
}

// APIError is a structured error returned by the GitHub REST API.
// It preserves the HTTP status code, the GitHub-provided message, and a
// parsed list of per-field validation errors when present.
type APIError struct {
	StatusCode int
	Message    string
	Errors     []APIFieldError
	RetryAfter time.Duration // populated for 429 / rate-limit responses
	RawBody    string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if len(e.Errors) == 0 {
		return fmt.Sprintf("github api: %d: %s", e.StatusCode, e.Message)
	}
	parts := make([]string, 0, len(e.Errors))
	for _, fe := range e.Errors {
		parts = append(parts, fmt.Sprintf("%s.%s: %s", fe.Resource, fe.Field, fe.Code))
	}
	return fmt.Sprintf("github api: %d: %s (%s)", e.StatusCode, e.Message, strings.Join(parts, "; "))
}

// APIFieldError is one validation error in a 422 response.
type APIFieldError struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
	Code     string `json:"code"`
	Message  string `json:"message,omitempty"`
}

// parseAPIError converts a 4xx response body into an APIError.
func parseAPIError(resp *http.Response, body []byte) error {
	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		RawBody:    string(body),
	}
	var decoded struct {
		Message string          `json:"message"`
		Errors  []APIFieldError `json:"errors"`
	}
	if err := json.Unmarshal(body, &decoded); err == nil {
		apiErr.Message = decoded.Message
		apiErr.Errors = decoded.Errors
	}
	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(resp.StatusCode)
	}
	return apiErr
}

// retryAfter returns the duration to wait before retrying a rate-limited
// request. Prefers Retry-After (seconds) when present, else X-RateLimit-Reset
// (Unix epoch seconds), else a sane default.
func retryAfter(resp *http.Response) time.Duration {
	if s := resp.Header.Get("Retry-After"); s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	if s := resp.Header.Get("X-RateLimit-Reset"); s != "" {
		if epoch, err := strconv.ParseInt(s, 10, 64); err == nil {
			d := time.Until(time.Unix(epoch, 0))
			if d > 0 {
				return d
			}
		}
	}
	return 5 * time.Second
}

// backoff returns the exponential-backoff duration for the given attempt index
// (0-based). 500ms, 1s, 2s — with a small constant floor so tests are fast.
func backoff(attempt int) time.Duration {
	base := 500 * time.Millisecond
	return base << attempt
}

// shouldRetry returns whether to retry after the given attempt index.
// Valid attempts are 0 through maxRetries-1; after maxRetries-1 we stop.
func shouldRetry(attempt int) bool {
	return attempt < maxRetries-1
}

// bytesReader wraps a []byte in an io.Reader if non-nil, else returns nil.
// Returning a typed nil io.Reader confuses http.NewRequestWithContext, so we
// must return untyped nil when there is no body.
func bytesReader(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return bytes.NewReader(b)
}
