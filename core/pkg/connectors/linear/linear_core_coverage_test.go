package linear

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientLocalGraphQLSuccess(t *testing.T) {
	ctx := context.Background()
	now := "2026-06-02T10:00:00Z"
	var sawCreatePriority bool
	var sawListFilter bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "lin_api_test" {
			t.Fatalf("authorization header = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Fatalf("user agent = %q", got)
		}

		var payload struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(payload.Query, "issueCreate"):
			input := payload.Variables["input"].(map[string]any)
			if input["priority"].(float64) == 2 && len(input["labelIds"].([]any)) == 2 {
				sawCreatePriority = true
			}
			_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"issue-1","identifier":"HEL-1"}}}}`))
		case strings.Contains(payload.Query, "issueUpdate"):
			_, _ = w.Write([]byte(`{"data":{"issueUpdate":{"success":true}}}`))
		case strings.Contains(payload.Query, "query Issue("):
			_, _ = w.Write([]byte(`{"data":{"issue":{"id":"issue-1","title":"Bug","description":"Fix it","priorityLabel":"High","state":{"name":"Todo"},"assignee":{"name":"Ada"},"createdAt":"` + now + `","updatedAt":"` + now + `"}}}`))
		case strings.Contains(payload.Query, "query Issues("):
			if _, ok := payload.Variables["filter"].(map[string]any); ok {
				sawListFilter = true
			}
			_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[{"id":"issue-1","title":"Bug","description":"Fix it","priorityLabel":"Medium","state":{"name":"Todo"},"assignee":null,"createdAt":"` + now + `","updatedAt":"` + now + `"}]}}}`))
		case strings.Contains(payload.Query, "commentCreate"):
			_, _ = w.Write([]byte(`{"data":{"commentCreate":{"success":true,"comment":{"id":"comment-1","createdAt":"` + now + `"}}}}`))
		default:
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := NewClientWithToken(server.URL, "lin_api_test")
	client.httpClient = server.Client()

	created, err := client.CreateIssue(ctx, &CreateIssueRequest{
		TeamID:      "team-1",
		Title:       "Bug",
		Description: "Fix it",
		Priority:    "High",
		AssigneeID:  "user-1",
		LabelIDs:    []string{"label-1", "label-2"},
	})
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if created.IssueID != "issue-1" || created.Identifier != "HEL-1" || !sawCreatePriority {
		t.Fatalf("unexpected create result=%+v saw priority=%v", created, sawCreatePriority)
	}

	title := "New title"
	description := "New description"
	state := "state-1"
	priority := "Urgent"
	assignee := "user-2"
	if err := client.UpdateIssue(ctx, &UpdateIssueRequest{
		IssueID:     "issue-1",
		Title:       &title,
		Description: &description,
		State:       &state,
		Priority:    &priority,
		AssigneeID:  &assignee,
	}); err != nil {
		t.Fatalf("UpdateIssue: %v", err)
	}

	got, err := client.GetIssue(ctx, "issue-1")
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if got.Issue.AssigneeName != "Ada" || got.Issue.Priority != "High" {
		t.Fatalf("unexpected issue: %+v", got.Issue)
	}

	listed, err := client.ListIssues(ctx, "team-1", "Todo")
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(listed.Issues) != 1 || listed.Issues[0].AssigneeName != "" || !sawListFilter {
		t.Fatalf("unexpected list result=%+v saw filter=%v", listed, sawListFilter)
	}

	comment, err := client.AddComment(ctx, &AddCommentRequest{IssueID: "issue-1", Body: "Working on it"})
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	if comment.CommentID != "comment-1" || comment.CreatedAt.IsZero() {
		t.Fatalf("unexpected comment: %+v", comment)
	}
}

func TestClientValidationAuthAndHelpers(t *testing.T) {
	ctx := context.Background()
	defaultClient := NewClient("")
	if defaultClient.baseURL != defaultBaseURL {
		t.Fatalf("default base URL = %q", defaultClient.baseURL)
	}

	tokenless := NewClient("")
	if err := tokenless.UpdateIssue(ctx, &UpdateIssueRequest{IssueID: "issue-1", Title: strPtr("x")}); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless update error, got %v", err)
	}
	if _, err := tokenless.GetIssue(ctx, "issue-1"); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless get error, got %v", err)
	}
	if _, err := tokenless.ListIssues(ctx, "", ""); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless list error, got %v", err)
	}
	if _, err := tokenless.AddComment(ctx, &AddCommentRequest{IssueID: "issue-1", Body: "x"}); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected tokenless comment error, got %v", err)
	}

	client := NewClientWithToken("https://linear.test/graphql", "lin_api_test")
	for name, req := range map[string]*CreateIssueRequest{
		"nil":          nil,
		"missing team": {Title: "x"},
		"missing title": {
			TeamID: "team-1",
		},
	} {
		if _, err := client.CreateIssue(ctx, req); err == nil {
			t.Fatalf("CreateIssue %s: expected validation error", name)
		}
	}
	for name, req := range map[string]*UpdateIssueRequest{
		"nil":        nil,
		"missing id": {Title: strPtr("x")},
		"no fields":  {IssueID: "issue-1"},
	} {
		if err := client.UpdateIssue(ctx, req); err == nil {
			t.Fatalf("UpdateIssue %s: expected validation error", name)
		}
	}
	if _, err := client.GetIssue(ctx, ""); err == nil || !strings.Contains(err.Error(), "issue_id required") {
		t.Fatalf("expected get issue validation error, got %v", err)
	}
	for name, req := range map[string]*AddCommentRequest{
		"nil":           nil,
		"missing issue": {Body: "x"},
		"missing body":  {IssueID: "issue-1"},
	} {
		if _, err := client.AddComment(ctx, req); err == nil {
			t.Fatalf("AddComment %s: expected validation error", name)
		}
	}

	for label, want := range map[string]int{
		"None": 0, "urgent": 1, "High": 2, "medium": 3, "Low": 4, "4": 4,
	} {
		if got, ok := priorityStringToInt(label); !ok || got != want {
			t.Fatalf("priorityStringToInt(%q) = %d,%v want %d,true", label, got, ok, want)
		}
	}
	if _, ok := priorityStringToInt("5"); ok {
		t.Fatal("priority 5 should be rejected")
	}
	if _, ok := priorityStringToInt("unknown"); ok {
		t.Fatal("unknown priority should be rejected")
	}

	if looksLikeOAuthToken("short") {
		t.Fatal("short token should not look like OAuth")
	}
	if looksLikeOAuthToken("lin_api_123") {
		t.Fatal("personal API key should not look like OAuth")
	}
	if !looksLikeOAuthToken("oauth-token") {
		t.Fatal("non-personal long token should look like OAuth")
	}

	if (*APIError)(nil).Error() != "" {
		t.Fatal("nil APIError should render empty string")
	}
	if got := (&APIError{StatusCode: 401}).Error(); got != "linear api: 401: (no message)" {
		t.Fatalf("APIError no-message string = %q", got)
	}
	if got := (&APIError{StatusCode: 200, Messages: []string{"bad query"}}).Error(); got != "linear api: 200: bad query" {
		t.Fatalf("APIError message string = %q", got)
	}

	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Retry-After", "3")
	if retryAfter(resp) != 3*time.Second {
		t.Fatalf("retryAfter valid = %s", retryAfter(resp))
	}
	resp.Header.Set("Retry-After", "bad")
	if retryAfter(resp) != 5*time.Second {
		t.Fatalf("retryAfter invalid = %s", retryAfter(resp))
	}
	if backoff(1) != time.Second || !shouldRetry(0) || shouldRetry(maxRetries-1) {
		t.Fatalf("unexpected retry helper results")
	}

	if stringSliceParam(map[string]any{"label_ids": "bad"}, "label_ids") != nil {
		t.Fatal("stringSliceParam should reject scalar values")
	}
}

func TestClientDoGraphQLErrorBranches(t *testing.T) {
	ctx := context.Background()
	client := NewClientWithToken("https://linear.test/graphql", "lin_api_test")

	if err := client.doGraphQL(ctx, "query {}", map[string]any{"bad": func() {}}, nil); err == nil || !strings.Contains(err.Error(), "marshal payload") {
		t.Fatalf("expected marshal payload error, got %v", err)
	}

	badURL := NewClientWithToken("http://[::1", "lin_api_test")
	if err := badURL.doGraphQL(ctx, "query {}", nil, nil); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("expected build request error, got %v", err)
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer invalidJSON.Close()
	client.baseURL = invalidJSON.URL
	client.httpClient = invalidJSON.Client()
	if err := client.doGraphQL(ctx, "query {}", nil, nil); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("expected decode response error, got %v", err)
	}

	badData := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"issue":"bad"}}`))
	}))
	defer badData.Close()
	client.baseURL = badData.URL
	client.httpClient = badData.Client()
	var out struct {
		Issue linearIssueNode `json:"issue"`
	}
	if err := client.doGraphQL(ctx, "query {}", nil, &out); err == nil || !strings.Contains(err.Error(), "decode data") {
		t.Fatalf("expected decode data error, got %v", err)
	}

	graphQLErrors := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"bad query","extensions":{"code":"BAD_USER_INPUT"}}]}`))
	}))
	defer graphQLErrors.Close()
	client.baseURL = graphQLErrors.URL
	client.httpClient = graphQLErrors.Client()
	err := client.doGraphQL(ctx, "query {}", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Messages[0] != "bad query" || len(apiErr.Extensions) != 1 {
		t.Fatalf("expected GraphQL APIError, got %v", err)
	}

	authFailure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer authFailure.Close()
	client.baseURL = authFailure.URL
	client.httpClient = authFailure.Client()
	err = client.doGraphQL(ctx, "query {}", nil, nil)
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 APIError, got %v", err)
	}

	serverError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary", http.StatusBadGateway)
	}))
	defer serverError.Close()
	client.baseURL = serverError.URL
	client.httpClient = serverError.Client()
	err = client.doGraphQL(ctx, "query {}", nil, nil)
	if !errors.As(err, &apiErr) || apiErr.Messages[0] != "server error" {
		t.Fatalf("expected server error APIError, got %v", err)
	}

	rateCtx, cancel := context.WithCancel(context.Background())
	rateLimited := NewClientWithToken("https://linear.test/graphql", "lin_api_test")
	rateLimited.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		cancel()
		resp := &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"errors":[]}`)),
			Request:    req,
		}
		resp.Header.Set("Retry-After", "1")
		return resp, nil
	})}
	if err := rateLimited.doGraphQL(rateCtx, "query {}", nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled rate-limit wait, got %v", err)
	}
}

func TestClientOAuthAuthorizationHeader(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[]}}}`))
	}))
	defer server.Close()

	client := NewClientWithToken(server.URL, "oauth-token")
	client.httpClient = server.Client()
	if _, err := client.ListIssues(context.Background(), "", ""); err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if authHeader != "Bearer oauth-token" {
		t.Fatalf("authorization header = %q", authHeader)
	}
}

func TestClientServerReportedSuccessFalse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		switch {
		case strings.Contains(payload.Query, "issueCreate"):
			_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":false,"issue":{"id":"","identifier":""}}}}`))
		case strings.Contains(payload.Query, "issueUpdate"):
			_, _ = w.Write([]byte(`{"data":{"issueUpdate":{"success":false}}}`))
		case strings.Contains(payload.Query, "commentCreate"):
			_, _ = w.Write([]byte(`{"data":{"commentCreate":{"success":false,"comment":{"id":"","createdAt":"2026-06-02T10:00:00Z"}}}}`))
		default:
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := NewClientWithToken(server.URL, "lin_api_test")
	client.httpClient = server.Client()
	ctx := context.Background()
	if _, err := client.CreateIssue(ctx, &CreateIssueRequest{TeamID: "team-1", Title: "Bug"}); err == nil || !strings.Contains(err.Error(), "success=false") {
		t.Fatalf("expected create success=false error, got %v", err)
	}
	if err := client.UpdateIssue(ctx, &UpdateIssueRequest{IssueID: "issue-1", Title: strPtr("x")}); err == nil || !strings.Contains(err.Error(), "success=false") {
		t.Fatalf("expected update success=false error, got %v", err)
	}
	if _, err := client.AddComment(ctx, &AddCommentRequest{IssueID: "issue-1", Body: "x"}); err == nil || !strings.Contains(err.Error(), "success=false") {
		t.Fatalf("expected comment success=false error, got %v", err)
	}
}

func TestConnectorExecuteSuccessWithLocalGraphQL(t *testing.T) {
	now := "2026-06-02T10:00:00Z"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		switch {
		case strings.Contains(payload.Query, "issueCreate"):
			_, _ = w.Write([]byte(`{"data":{"issueCreate":{"success":true,"issue":{"id":"issue-1","identifier":"HEL-1"}}}}`))
		case strings.Contains(payload.Query, "issueUpdate"):
			_, _ = w.Write([]byte(`{"data":{"issueUpdate":{"success":true}}}`))
		case strings.Contains(payload.Query, "query Issue("):
			_, _ = w.Write([]byte(`{"data":{"issue":{"id":"issue-1","title":"Bug","description":"Fix it","priorityLabel":"High","state":{"name":"Todo"},"assignee":{"name":"Ada"},"createdAt":"` + now + `","updatedAt":"` + now + `"}}}`))
		case strings.Contains(payload.Query, "query Issues("):
			_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[{"id":"issue-1","title":"Bug","description":"Fix it","priorityLabel":"Medium","state":{"name":"Todo"},"assignee":null,"createdAt":"` + now + `","updatedAt":"` + now + `"}]}}}`))
		case strings.Contains(payload.Query, "commentCreate"):
			_, _ = w.Write([]byte(`{"data":{"commentCreate":{"success":true,"comment":{"id":"comment-1","createdAt":"` + now + `"}}}}`))
		default:
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	conn := NewConnector(Config{BaseURL: server.URL, Token: "lin_api_test"})
	conn.client.httpClient = server.Client()
	ctx := context.Background()
	permit := validPermit()

	created, err := conn.Execute(ctx, permit, "linear.create_issue", map[string]any{
		"team_id":     "team-1",
		"title":       "Bug",
		"description": "Fix it",
		"priority":    "High",
		"assignee_id": "user-1",
		"label_ids":   []string{"label-1"},
	})
	if err != nil {
		t.Fatalf("create execute: %v", err)
	}
	if created.(*CreateIssueResponse).Identifier != "HEL-1" {
		t.Fatalf("unexpected create result: %+v", created)
	}

	updated, err := conn.Execute(ctx, permit, "linear.update_issue", map[string]any{
		"issue_id":    "issue-1",
		"title":       "New",
		"description": "New description",
		"state":       "state-1",
		"priority":    "Low",
		"assignee_id": "user-2",
	})
	if err != nil {
		t.Fatalf("update execute: %v", err)
	}
	if updated.(map[string]string)["status"] != "updated" {
		t.Fatalf("unexpected update result: %+v", updated)
	}

	got, err := conn.Execute(ctx, permit, "linear.get_issue", map[string]any{"issue_id": "issue-1"})
	if err != nil {
		t.Fatalf("get execute: %v", err)
	}
	if got.(*GetIssueResponse).Issue.AssigneeName != "Ada" {
		t.Fatalf("unexpected get result: %+v", got)
	}

	listed, err := conn.Execute(ctx, permit, "linear.list_issues", map[string]any{"team_id": "team-1", "state": "Todo"})
	if err != nil {
		t.Fatalf("list execute: %v", err)
	}
	if len(listed.(*ListIssuesResponse).Issues) != 1 {
		t.Fatalf("unexpected list result: %+v", listed)
	}

	comment, err := conn.Execute(ctx, permit, "linear.add_comment", map[string]any{"issue_id": "issue-1", "body": "Working"})
	if err != nil {
		t.Fatalf("comment execute: %v", err)
	}
	if comment.(*AddCommentResponse).CommentID != "comment-1" {
		t.Fatalf("unexpected comment result: %+v", comment)
	}

	if conn.Graph().Len() != 10 {
		t.Fatalf("graph len = %d, want 10 intent/effect nodes", conn.Graph().Len())
	}
}

func TestExecuteCanonicalHashError(t *testing.T) {
	conn := NewConnector(Config{Token: "lin_api_test"})
	permit := validPermit()
	_, err := conn.Execute(context.Background(), permit, "linear.list_issues", map[string]any{"bad": func() {}})
	if err == nil || !strings.Contains(err.Error(), "canonical hash of params") {
		t.Fatalf("expected canonical hash error, got %v", err)
	}
}

func strPtr(s string) *string { return &s }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
