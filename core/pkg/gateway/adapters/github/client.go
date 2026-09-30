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
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// providerError is a failed provider call, classified.
type providerError struct {
	Reason contracts.ReasonCode
	// Status is the HTTP status, or 0 when no answer was read.
	Status int
	// Refused is true when the provider answered with a definite refusal
	// (4xx), so a write it refused did not happen. Transport errors, 5xx,
	// oversized and unreadable answers are not definite.
	Refused bool
	Detail  string
}

func (e *providerError) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Detail)
}

// client makes one operation's GitHub REST calls with one token.
type client struct {
	a     *Adapter
	token string
	repo  repository
	// evidence collects every successful read-back body, for
	// Observation.evidence_digest.
	evidence [][]byte
}

func (a *Adapter) newClient(ctx context.Context, creds adapters.TokenSource, repo repository) (*client, error) {
	if creds == nil {
		return nil, &providerError{Reason: contracts.ReasonProviderCredentialRejected, Detail: "no credential source"}
	}
	token, err := creds.Token(ctx)
	if err != nil || strings.TrimSpace(token) == "" {
		return nil, &providerError{Reason: contracts.ReasonProviderCredentialRejected, Detail: "the credential source returned no token"}
	}
	return &client{a: a, token: token, repo: repo}, nil
}

// repoPath is /repos/{owner}/{repo} followed by suffix. The owner and name
// passed the target patterns, so they need no escaping.
func (c *client) repoPath(suffix string) string {
	return "/repos/" + c.repo.Owner + "/" + c.repo.Name + suffix
}

// call sends one request and decodes a 2xx JSON answer into out. limit bounds
// the bytes read from the answer, whatever its status (09-04).
func (c *client) call(ctx context.Context, method, path string, query url.Values, in, out any, limit int64) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	u := c.a.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", "helm-gateway-github-adapter/"+AdapterVersion)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.a.httpClient.Do(req)
	if err != nil {
		return &providerError{Reason: contracts.ReasonProviderError, Detail: fmt.Sprintf("%s %s: %v", method, path, err)}
	}
	defer resp.Body.Close()
	if resp.ContentLength > limit {
		return tooLarge(method, path, resp.StatusCode, limit)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return &providerError{Reason: contracts.ReasonProviderError, Status: resp.StatusCode, Detail: fmt.Sprintf("%s %s: reading the answer: %v", method, path, err)}
	}
	if int64(len(raw)) > limit {
		return tooLarge(method, path, resp.StatusCode, limit)
	}
	switch status := resp.StatusCode; {
	case status >= 200 && status < 300:
		if err := json.Unmarshal(raw, out); err != nil {
			return &providerError{Reason: contracts.ReasonConnectorContractDrift, Status: status, Detail: fmt.Sprintf("%s %s: the answer is not the expected JSON", method, path)}
		}
		if method == http.MethodGet {
			c.evidence = append(c.evidence, raw)
		}
		return nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &providerError{Reason: contracts.ReasonProviderCredentialRejected, Status: status, Refused: true, Detail: fmt.Sprintf("%s %s: %d %s", method, path, status, message(raw))}
	case status >= 400 && status < 500:
		return &providerError{Reason: contracts.ReasonProviderError, Status: status, Refused: true, Detail: fmt.Sprintf("%s %s: %d %s", method, path, status, message(raw))}
	default:
		return &providerError{Reason: contracts.ReasonProviderError, Status: status, Detail: fmt.Sprintf("%s %s: %d %s", method, path, status, message(raw))}
	}
}

func tooLarge(method, path string, status int, limit int64) error {
	return &providerError{Reason: contracts.ReasonProviderResponseTooLarge, Status: status, Detail: fmt.Sprintf("%s %s: the answer exceeds %d bytes", method, path, limit)}
}

// message extracts GitHub's error message, bounded, for a detail string.
func message(raw []byte) string {
	var body struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Message == "" {
		return "(no message)"
	}
	if len(body.Message) > 200 {
		return body.Message[:200]
	}
	return body.Message
}

func asProviderError(err error) *providerError {
	var pe *providerError
	if errors.As(err, &pe) {
		return pe
	}
	return &providerError{Reason: contracts.ReasonProviderError, Detail: err.Error()}
}

func isNotFound(err error) bool {
	var pe *providerError
	return errors.As(err, &pe) && pe.Status == http.StatusNotFound
}

// The GitHub objects the adapter reads. Only the fields it checks.

type repoInfo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

type gitRef struct {
	Ref    string `json:"ref"`
	Object struct {
		SHA  string `json:"sha"`
		Type string `json:"type"`
	} `json:"object"`
}

type gitCommit struct {
	SHA  string `json:"sha"`
	Tree struct {
		SHA string `json:"sha"`
	} `json:"tree"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
}

type gitObject struct {
	SHA string `json:"sha"`
}

type comparison struct {
	Files []struct {
		Filename string `json:"filename"`
		SHA      string `json:"sha"`
		Status   string `json:"status"`
	} `json:"files"`
}

type pullRequest struct {
	HTMLURL string `json:"html_url"`
	Number  int64  `json:"number"`
	NodeID  string `json:"node_id"`
	State   string `json:"state"`
	Title   string `json:"title"`
	Draft   bool   `json:"draft"`
	Head    struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo *struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

// getRepo reads the repository and refuses one GitHub answers for under
// another name: a renamed or transferred repository is a different target.
func (c *client) getRepo(ctx context.Context) (repoInfo, error) {
	var info repoInfo
	if err := c.call(ctx, http.MethodGet, c.repoPath(""), nil, nil, &info, c.a.maxResponseBytes); err != nil {
		return repoInfo{}, err
	}
	if !strings.EqualFold(info.FullName, c.repo.fullName()) || info.DefaultBranch == "" {
		return repoInfo{}, &providerError{Reason: contracts.ReasonConnectorContractDrift, Detail: fmt.Sprintf("the repository answered as %q with default branch %q", info.FullName, info.DefaultBranch)}
	}
	return info, nil
}

// getBranchHead reads refs/heads/{head}. GitHub's single-ref endpoint
// answers 404 for a missing ref.
func (c *client) getBranchHead(ctx context.Context, head string) (string, error) {
	var ref gitRef
	if err := c.call(ctx, http.MethodGet, c.repoPath("/git/ref/heads/"+head), nil, nil, &ref, c.a.maxResponseBytes); err != nil {
		return "", err
	}
	if ref.Ref != "refs/heads/"+head || ref.Object.Type != "commit" || !shaRE.MatchString(ref.Object.SHA) {
		return "", &providerError{Reason: contracts.ReasonConnectorContractDrift, Detail: fmt.Sprintf("refs/heads/%s answered as %q -> %s %q", head, ref.Ref, ref.Object.Type, ref.Object.SHA)}
	}
	return ref.Object.SHA, nil
}

func (c *client) getCommit(ctx context.Context, sha string) (gitCommit, error) {
	var commit gitCommit
	if err := c.call(ctx, http.MethodGet, c.repoPath("/git/commits/"+sha), nil, nil, &commit, c.a.maxResponseBytes); err != nil {
		return gitCommit{}, err
	}
	if commit.SHA != sha || !shaRE.MatchString(commit.Tree.SHA) {
		return gitCommit{}, &providerError{Reason: contracts.ReasonConnectorContractDrift, Detail: fmt.Sprintf("commit %s answered as %q", sha, commit.SHA)}
	}
	return commit, nil
}

func (c *client) post(ctx context.Context, path string, in any) (gitObject, error) {
	var out gitObject
	if err := c.call(ctx, http.MethodPost, c.repoPath(path), nil, in, &out, c.a.maxResponseBytes); err != nil {
		return gitObject{}, err
	}
	if !shaRE.MatchString(out.SHA) {
		return gitObject{}, &providerError{Reason: contracts.ReasonConnectorContractDrift, Detail: fmt.Sprintf("POST %s answered with object id %q", path, out.SHA)}
	}
	return out, nil
}

// listPulls lists the pull requests from head into base. GitHub filters head
// as "{owner}:{branch}".
func (c *client) listPulls(ctx context.Context, head, base, state string) ([]pullRequest, error) {
	query := url.Values{
		"head":     {c.repo.Owner + ":" + head},
		"base":     {base},
		"state":    {state},
		"per_page": {"10"},
	}
	var pulls []pullRequest
	if err := c.call(ctx, http.MethodGet, c.repoPath("/pulls"), query, nil, &pulls, c.a.maxResponseBytes); err != nil {
		return nil, err
	}
	return pulls, nil
}
