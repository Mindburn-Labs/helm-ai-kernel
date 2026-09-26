package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// TestQualificationLive runs the same suite against a real sandbox
// repository. It needs:
//
//	HELM_GITHUB_QUAL_REPO   owner/repo of a disposable sandbox repository
//	HELM_GITHUB_QUAL_TOKEN  a token that may push branches and open pull
//	                        requests there, such as a GitHub App installation
//	                        token (HELM-792)
//
// and optionally HELM_GITHUB_QUAL_API (default https://api.github.com) and
// HELM_GITHUB_QUAL_RECORD, a file for the records. Without the first two it
// skips. A skip is not a qualification: no record is produced, and nothing
// may read the skipped test as a pass.
func TestQualificationLive(t *testing.T) {
	repo, token := os.Getenv("HELM_GITHUB_QUAL_REPO"), os.Getenv("HELM_GITHUB_QUAL_TOKEN")
	if repo == "" || token == "" {
		t.Skip("LIVE GITHUB QUALIFICATION NOT RUN: HELM_GITHUB_QUAL_REPO and HELM_GITHUB_QUAL_TOKEN are unset. " +
			"This skip qualifies nothing; the adapter has only the fake-environment record.")
	}
	owner, name, ok := strings.Cut(repo, "/")
	if _, err := parseTarget("github.com/" + repo); !ok || err != nil {
		t.Fatalf("HELM_GITHUB_QUAL_REPO %q is not owner/repo", repo)
	}
	api := os.Getenv("HELM_GITHUB_QUAL_API")
	if api == "" {
		api = defaultBaseURL
	}
	live := liveAPI{base: api, token: token}
	var info repoInfo
	live.do(t, http.MethodGet, "/repos/"+repo, nil, &info)
	var ref gitRef
	live.do(t, http.MethodGet, "/repos/"+repo+"/git/ref/heads/"+info.DefaultBranch, nil, &ref)

	prefix := fmt.Sprintf("helm/qual-%d/", time.Now().Unix())
	// Deleting a pull request's head branch closes it, so deleting the run's
	// branches cleans up everything the suite created.
	t.Cleanup(func() {
		var refs []gitRef
		live.do(t, http.MethodGet, "/repos/"+repo+"/git/matching-refs/heads/"+prefix, nil, &refs)
		for _, r := range refs {
			live.do(t, http.MethodDelete, "/repos/"+repo+"/git/"+r.Ref, nil, nil)
		}
	})
	env := &qualEnv{
		name:    "live: github.com/" + repo + " via " + api,
		baseURL: api, owner: owner, repo: name, token: token,
		baseBranch: info.DefaultBranch, baseSHA: ref.Object.SHA, headPrefix: prefix,
		markReady: func(t *testing.T, pr *adapters.GitHubPullRequestResult) {
			live.do(t, http.MethodPost, "/graphql", map[string]any{
				"query":     "mutation($id: ID!) { markPullRequestReadyForReview(input: {pullRequestId: $id}) { clientMutationId } }",
				"variables": map[string]string{"id": pr.NodeID},
			}, nil)
		},
	}
	for _, record := range runQualification(t, env) {
		if !record.Qualified {
			t.Errorf("%s did not qualify against %s", record.Operation, env.name)
		}
	}
}

// liveAPI is the test's own GitHub client for setup and cleanup; the adapter
// is never used for either.
type liveAPI struct {
	base  string
	token string
}

func (l liveAPI) do(t *testing.T, method, path string, in, out any) {
	t.Helper()
	var body io.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, l.base+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+l.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
}
