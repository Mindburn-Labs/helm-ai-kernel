package github

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Integration tests against the real GitHub API. Guarded behind env vars so
// CI without credentials never hits the network.
//
// Required env (all must be set, else test is skipped):
//
//	HELM_GITHUB_PAT    — a GitHub personal access token (classic or fine-grained)
//	HELM_GITHUB_REPO   — "owner/name" of a repo the PAT can read
//
// Optional:
//
//	HELM_GITHUB_WRITE_REPO — "owner/name" of a repo the PAT can write to
//	                          (enables CreateIssue + AddComment tests, which
//	                          produce real artifacts in the target repo)
//
// These tests never destructively mutate anything; AddComment targets the issue
// it just created.

func skipIfNoIntegration(t *testing.T) (token, repo string) {
	t.Helper()
	token = os.Getenv("HELM_GITHUB_PAT")
	repo = os.Getenv("HELM_GITHUB_REPO")
	if token == "" || repo == "" {
		t.Skip("skipping: HELM_GITHUB_PAT + HELM_GITHUB_REPO required for integration")
	}
	return token, repo
}

func TestIntegration_ListPRs(t *testing.T) {
	token, repo := skipIfNoIntegration(t)

	client := NewClientWithToken("", token)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ListPRs(ctx, repo, "open")
	if err != nil {
		t.Fatalf("ListPRs returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("ListPRs returned nil response")
	}
	// Not asserting count — any repo may have zero open PRs; shape is the test.
	for _, pr := range resp.PullRequests {
		if pr.Number <= 0 {
			t.Fatalf("PR number must be > 0, got %d", pr.Number)
		}
		if pr.State == "" {
			t.Fatalf("PR %d missing state", pr.Number)
		}
	}
}

func TestIntegration_ReadPR_Unknown(t *testing.T) {
	token, repo := skipIfNoIntegration(t)

	client := NewClientWithToken("", token)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// PR #999999999 is extremely unlikely to exist in any repo — 404 is expected.
	_, err := client.ReadPR(ctx, repo, 999999999)
	if err == nil {
		t.Fatal("expected 404 error for PR #999999999")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", apiErr.StatusCode)
	}
}

func TestIntegration_CreateIssue_AddComment(t *testing.T) {
	token, _ := skipIfNoIntegration(t)
	writeRepo := os.Getenv("HELM_GITHUB_WRITE_REPO")
	if writeRepo == "" {
		t.Skip("skipping: HELM_GITHUB_WRITE_REPO required for write-path integration")
	}

	client := NewClientWithToken("", token)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stamp := time.Now().UTC().Format("20060102-150405")
	issue, err := client.CreateIssue(ctx, &CreateIssueRequest{
		Repo:   writeRepo,
		Title:  "HELM connector integration test " + stamp,
		Body:   "This issue was created by the HELM GitHub connector integration test (P2-01). It is safe to close.",
		Labels: []string{"helm-integration-test"},
	})
	if err != nil {
		// Label may not exist; retry without it.
		if strings.Contains(err.Error(), "label") {
			issue, err = client.CreateIssue(ctx, &CreateIssueRequest{
				Repo:  writeRepo,
				Title: "HELM connector integration test " + stamp,
				Body:  "This issue was created by the HELM GitHub connector integration test (P2-01). It is safe to close.",
			})
		}
		if err != nil {
			t.Fatalf("CreateIssue returned error: %v", err)
		}
	}
	if issue.Number <= 0 {
		t.Fatalf("CreateIssue returned invalid issue number: %+v", issue)
	}

	// Comment on the issue we just created — non-destructive.
	_, err = client.AddComment(ctx, &AddCommentRequest{
		Repo:        writeRepo,
		IssueNumber: issue.Number,
		Body:        "Integration test comment from HELM connector.",
	})
	if err != nil {
		t.Fatalf("AddComment returned error: %v", err)
	}
}

func TestIntegration_TokenlessReturnsSentinel(t *testing.T) {
	// The "no token" path must return the sentinel error, not perform an API call.
	client := NewClient("")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.ListPRs(ctx, "octocat/hello-world", "open")
	if err == nil {
		t.Fatal("expected error for tokenless ListPRs")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected 'not connected' sentinel, got: %v", err)
	}
}
