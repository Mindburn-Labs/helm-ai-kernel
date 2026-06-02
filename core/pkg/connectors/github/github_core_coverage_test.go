package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestClientLocalRESTSuccess(t *testing.T) {
	ctx := context.Background()
	now := "2026-06-02T10:00:00Z"
	var listState string
	var sawIssueMetadata bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghp-test" {
			t.Fatalf("authorization header = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Fatalf("user agent = %q", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != apiVersion {
			t.Fatalf("api version = %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			listState = r.URL.Query().Get("state")
			_, _ = w.Write([]byte(`[{"number":7,"title":"Fix","body":"Body","state":"open","created_at":"` + now + `","user":{"login":"ada"},"head":{"ref":"feature"},"base":{"ref":"main"}}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls/7":
			_, _ = w.Write([]byte(`{"number":7,"title":"Fix","body":"Body","state":"open","created_at":"` + now + `","user":{"login":"ada"},"head":{"ref":"feature"},"base":{"ref":"main"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/issues":
			var body struct {
				Title     string   `json:"title"`
				Body      string   `json:"body"`
				Labels    []string `json:"labels"`
				Assignees []string `json:"assignees"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode issue body: %v", err)
			}
			sawIssueMetadata = body.Title == "Bug" && len(body.Labels) == 2 && len(body.Assignees) == 1
			_, _ = w.Write([]byte(`{"number":11,"html_url":"https://github.test/owner/repo/issues/11"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/issues/7/comments":
			_, _ = w.Write([]byte(`{"id":99,"created_at":"` + now + `"}`))
		default:
			http.Error(w, "unexpected route", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClientWithToken(server.URL, "ghp-test")
	client.httpClient = server.Client()

	prs, err := client.ListPRs(ctx, "owner/repo", "")
	if err != nil {
		t.Fatalf("ListPRs: %v", err)
	}
	if listState != "open" || len(prs.PullRequests) != 1 || prs.PullRequests[0].Author != "ada" {
		t.Fatalf("unexpected list result=%+v state=%q", prs, listState)
	}

	pr, err := client.ReadPR(ctx, "owner/repo", 7)
	if err != nil {
		t.Fatalf("ReadPR: %v", err)
	}
	if pr.HeadBranch != "feature" || pr.BaseBranch != "main" {
		t.Fatalf("unexpected PR: %+v", pr)
	}

	issue, err := client.CreateIssue(ctx, &CreateIssueRequest{
		Repo:      "owner/repo",
		Title:     "Bug",
		Body:      "Details",
		Labels:    []string{"bug", "critical"},
		Assignees: []string{"ada"},
	})
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if issue.Number != 11 || !sawIssueMetadata {
		t.Fatalf("unexpected issue=%+v saw metadata=%v", issue, sawIssueMetadata)
	}

	comment, err := client.AddComment(ctx, &AddCommentRequest{
		Repo:        "owner/repo",
		IssueNumber: 7,
		Body:        "LGTM",
	})
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	if comment.CommentID != 99 || comment.CreatedAt.IsZero() {
		t.Fatalf("unexpected comment: %+v", comment)
	}
}

func TestClientValidationAndHelpers(t *testing.T) {
	ctx := context.Background()
	defaultClient := NewClient("")
	if defaultClient.baseURL != defaultBaseURL {
		t.Fatalf("default base URL = %q", defaultClient.baseURL)
	}

	tokenless := NewClient("")
	if _, err := tokenless.ListPRs(ctx, "owner/repo", "open"); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless list error, got %v", err)
	}
	if _, err := tokenless.ReadPR(ctx, "owner/repo", 1); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless read error, got %v", err)
	}
	if _, err := tokenless.AddComment(ctx, &AddCommentRequest{Repo: "owner/repo", IssueNumber: 1, Body: "x"}); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless comment error, got %v", err)
	}

	client := NewClientWithToken("https://github.test", "ghp-test")
	for _, repo := range []string{"", "owner", "owner/", "/repo", "owner/repo/extra"} {
		if _, _, err := splitRepo(repo); err == nil {
			t.Fatalf("splitRepo(%q): expected error", repo)
		}
	}
	owner, name, err := splitRepo(" owner/repo ")
	if err != nil || owner != "owner" || name != "repo" {
		t.Fatalf("splitRepo valid = %q,%q,%v", owner, name, err)
	}
	if _, err := client.ListPRs(ctx, "bad", "open"); err == nil || !strings.Contains(err.Error(), "repo") {
		t.Fatalf("expected list repo validation error, got %v", err)
	}
	if _, err := client.ReadPR(ctx, "owner/repo", 0); err == nil || !strings.Contains(err.Error(), "invalid PR number") {
		t.Fatalf("expected invalid PR number error, got %v", err)
	}
	if _, err := client.CreateIssue(ctx, nil); err == nil || !strings.Contains(err.Error(), "nil request") {
		t.Fatalf("expected nil create error, got %v", err)
	}
	if _, err := client.CreateIssue(ctx, &CreateIssueRequest{Repo: "bad", Title: "Bug"}); err == nil || !strings.Contains(err.Error(), "repo") {
		t.Fatalf("expected create repo validation error, got %v", err)
	}
	if _, err := client.AddComment(ctx, nil); err == nil || !strings.Contains(err.Error(), "nil request") {
		t.Fatalf("expected nil comment error, got %v", err)
	}
	if _, err := client.AddComment(ctx, &AddCommentRequest{Repo: "owner/repo"}); err == nil || !strings.Contains(err.Error(), "invalid issue_number") {
		t.Fatalf("expected invalid issue number error, got %v", err)
	}
	if _, err := client.AddComment(ctx, &AddCommentRequest{Repo: "owner/repo", IssueNumber: 1}); err == nil || !strings.Contains(err.Error(), "body required") {
		t.Fatalf("expected body required error, got %v", err)
	}

	if got, ok := intParam(map[string]any{"n": int64(4)}, "n"); !ok || got != 4 {
		t.Fatalf("intParam int64 = %d,%v", got, ok)
	}
	if _, ok := intParam(map[string]any{"n": "bad"}, "n"); ok {
		t.Fatal("intParam should reject strings")
	}
	if stringSliceParam(map[string]any{"labels": "bug"}, "labels") != nil {
		t.Fatal("stringSliceParam should reject scalar values")
	}

	if bytesReader(nil) != nil {
		t.Fatal("bytesReader(nil) returned reader")
	}
	if bytesReader([]byte("x")) == nil {
		t.Fatal("bytesReader(non-empty) returned nil")
	}
	if backoff(1) != time.Second || !shouldRetry(0) || shouldRetry(maxRetries-1) {
		t.Fatal("unexpected retry helper result")
	}

	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Retry-After", "2")
	if retryAfter(resp) != 2*time.Second {
		t.Fatalf("retryAfter header = %s", retryAfter(resp))
	}
	resp.Header.Del("Retry-After")
	resp.Header.Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10))
	if retryAfter(resp) <= 0 {
		t.Fatalf("retryAfter reset should be positive")
	}
	resp.Header.Set("X-RateLimit-Reset", "bad")
	if retryAfter(resp) != 5*time.Second {
		t.Fatalf("retryAfter fallback = %s", retryAfter(resp))
	}

	if (*APIError)(nil).Error() != "" {
		t.Fatal("nil APIError should render empty string")
	}
	if got := (&APIError{StatusCode: 404, Message: "not found"}).Error(); got != "github api: 404: not found" {
		t.Fatalf("APIError string = %q", got)
	}
	fieldErr := &APIError{
		StatusCode: 422,
		Message:    "validation failed",
		Errors: []APIFieldError{{
			Resource: "Issue",
			Field:    "title",
			Code:     "missing",
		}},
	}
	if got := fieldErr.Error(); !strings.Contains(got, "Issue.title: missing") {
		t.Fatalf("field APIError string = %q", got)
	}
}

func TestClientDoJSONErrorBranches(t *testing.T) {
	ctx := context.Background()
	client := NewClientWithToken("https://github.test", "ghp-test")

	if err := client.doJSON(ctx, http.MethodPost, "/x", map[string]any{"bad": func() {}}, nil); err == nil || !strings.Contains(err.Error(), "marshal request body") {
		t.Fatalf("expected marshal request body error, got %v", err)
	}

	badURL := NewClientWithToken("http://[::1", "ghp-test")
	if err := badURL.doJSON(ctx, http.MethodGet, "/x", nil, nil); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("expected build request error, got %v", err)
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer invalidJSON.Close()
	client.baseURL = invalidJSON.URL
	client.httpClient = invalidJSON.Client()
	var out struct {
		ID int `json:"id"`
	}
	if err := client.doJSON(ctx, http.MethodGet, "/x", nil, &out); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("expected decode response error, got %v", err)
	}

	successNoOut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer successNoOut.Close()
	client.baseURL = successNoOut.URL
	client.httpClient = successNoOut.Client()
	if err := client.doJSON(ctx, http.MethodGet, "/x", nil, nil); err != nil {
		t.Fatalf("success with nil out: %v", err)
	}

	validationError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Validation Failed","errors":[{"resource":"Issue","field":"title","code":"missing"}]}`))
	}))
	defer validationError.Close()
	client.baseURL = validationError.URL
	client.httpClient = validationError.Client()
	err := client.doJSON(ctx, http.MethodGet, "/x", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || len(apiErr.Errors) != 1 {
		t.Fatalf("expected validation APIError, got %v", err)
	}

	badAPIErrorBody := &http.Response{StatusCode: http.StatusBadRequest}
	if err := parseAPIError(badAPIErrorBody, []byte("{")); !errors.As(err, &apiErr) || apiErr.Message != http.StatusText(http.StatusBadRequest) {
		t.Fatalf("expected fallback APIError, got %v", err)
	}

	serverError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary", http.StatusBadGateway)
	}))
	defer serverError.Close()
	client.baseURL = serverError.URL
	client.httpClient = serverError.Client()
	err = client.doJSON(ctx, http.MethodGet, "/x", nil, nil)
	if !errors.As(err, &apiErr) || apiErr.Message != "server error" {
		t.Fatalf("expected server error APIError, got %v", err)
	}

	rateCtx, cancel := context.WithCancel(context.Background())
	rateLimited := NewClientWithToken("https://github.test", "ghp-test")
	rateLimited.httpClient = &http.Client{Transport: githubRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		cancel()
		resp := &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"message":"rate"}`)),
			Request:    req,
		}
		resp.Header.Set("Retry-After", "1")
		return resp, nil
	})}
	if err := rateLimited.doJSON(rateCtx, http.MethodGet, "/x", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled rate-limit wait, got %v", err)
	}
}

func TestConnectorExecuteSuccessWithLocalREST(t *testing.T) {
	now := "2026-06-02T10:00:00Z"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls":
			_, _ = w.Write([]byte(`[{"number":7,"title":"Fix","body":"Body","state":"open","created_at":"` + now + `","user":{"login":"ada"},"head":{"ref":"feature"},"base":{"ref":"main"}}]`))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/owner/repo/pulls/7":
			_, _ = w.Write([]byte(`{"number":7,"title":"Fix","body":"Body","state":"open","created_at":"` + now + `","user":{"login":"ada"},"head":{"ref":"feature"},"base":{"ref":"main"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/issues":
			_, _ = w.Write([]byte(`{"number":11,"html_url":"https://github.test/owner/repo/issues/11"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/issues/7/comments":
			_, _ = w.Write([]byte(`{"id":99,"created_at":"` + now + `"}`))
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn := NewConnector(Config{BaseURL: server.URL, Token: "ghp-test"})
	conn.client.httpClient = server.Client()
	ctx := context.Background()
	permit := validPermit()

	listed, err := conn.Execute(ctx, permit, "github.list_prs", map[string]any{"repo": "owner/repo", "state": "all"})
	if err != nil {
		t.Fatalf("list execute: %v", err)
	}
	if len(listed.(*ListPRsResponse).PullRequests) != 1 {
		t.Fatalf("unexpected list result: %+v", listed)
	}

	read, err := conn.Execute(ctx, permit, "github.read_pr", map[string]any{"repo": "owner/repo", "number": float64(7)})
	if err != nil {
		t.Fatalf("read execute: %v", err)
	}
	if read.(*PullRequest).Author != "ada" {
		t.Fatalf("unexpected read result: %+v", read)
	}

	created, err := conn.Execute(ctx, permit, "github.create_issue", map[string]any{
		"repo":      "owner/repo",
		"title":     "Bug",
		"body":      "Details",
		"labels":    []string{"bug"},
		"assignees": []any{"ada"},
	})
	if err != nil {
		t.Fatalf("create execute: %v", err)
	}
	if created.(*CreateIssueResponse).Number != 11 {
		t.Fatalf("unexpected create result: %+v", created)
	}

	comment, err := conn.Execute(ctx, permit, "github.add_comment", map[string]any{
		"repo":         "owner/repo",
		"issue_number": int64(7),
		"body":         "LGTM",
	})
	if err != nil {
		t.Fatalf("comment execute: %v", err)
	}
	if comment.(*AddCommentResponse).CommentID != 99 {
		t.Fatalf("unexpected comment result: %+v", comment)
	}

	if conn.Graph().Len() != 8 {
		t.Fatalf("graph len = %d, want 8 intent/effect nodes", conn.Graph().Len())
	}
}

func TestExecuteCanonicalHashError(t *testing.T) {
	conn := NewConnector(Config{Token: "ghp-test"})
	permit := validPermit()
	_, err := conn.Execute(context.Background(), permit, "github.list_prs", map[string]any{"repo": "owner/repo", "bad": func() {}})
	if err == nil || !strings.Contains(err.Error(), "canonical hash of params") {
		t.Fatalf("expected canonical hash error, got %v", err)
	}
}

type githubRoundTripFunc func(*http.Request) (*http.Response, error)

func (f githubRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
