package linear

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Integration tests against the real Linear GraphQL API. Guarded behind env vars.
//
// Required env (all must be set, else test is skipped):
//
//	HELM_LINEAR_API_KEY — lin_api_... personal API key
//	HELM_LINEAR_TEAM_ID — a team UUID the API key can create issues in
//
// These tests create an issue and add a comment. Both are harmless and can be
// archived in Linear after the run.

func skipIfNoIntegration(t *testing.T) (apiKey, teamID string) {
	t.Helper()
	apiKey = os.Getenv("HELM_LINEAR_API_KEY")
	teamID = os.Getenv("HELM_LINEAR_TEAM_ID")
	if apiKey == "" || teamID == "" {
		t.Skip("skipping: HELM_LINEAR_API_KEY + HELM_LINEAR_TEAM_ID required for integration")
	}
	return apiKey, teamID
}

func TestIntegration_CreateIssue_GetIssue_AddComment(t *testing.T) {
	apiKey, teamID := skipIfNoIntegration(t)
	client := NewClientWithToken("", apiKey)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stamp := time.Now().UTC().Format("20060102-150405")
	title := "HELM Linear connector integration test " + stamp

	created, err := client.CreateIssue(ctx, &CreateIssueRequest{
		TeamID:      teamID,
		Title:       title,
		Description: "Integration test — safe to archive.",
		Priority:    "Low",
	})
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if created.IssueID == "" {
		t.Fatal("CreateIssue returned empty issue_id")
	}

	got, err := client.GetIssue(ctx, created.IssueID)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if got.Issue.Title != title {
		t.Fatalf("GetIssue title = %q, want %q", got.Issue.Title, title)
	}

	_, err = client.AddComment(ctx, &AddCommentRequest{
		IssueID: created.IssueID,
		Body:    "Integration test comment from HELM connector.",
	})
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
}

func TestIntegration_ListIssues(t *testing.T) {
	apiKey, teamID := skipIfNoIntegration(t)
	client := NewClientWithToken("", apiKey)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ListIssues(ctx, teamID, "")
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	for _, issue := range resp.Issues {
		if issue.ID == "" {
			t.Fatalf("ListIssues returned issue with empty ID: %+v", issue)
		}
	}
}

func TestIntegration_TokenlessReturnsSentinel(t *testing.T) {
	client := NewClient("")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := client.CreateIssue(ctx, &CreateIssueRequest{TeamID: "x", Title: "y"})
	if err == nil {
		t.Fatal("expected error for tokenless CreateIssue")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected 'not connected' sentinel, got: %v", err)
	}
}
