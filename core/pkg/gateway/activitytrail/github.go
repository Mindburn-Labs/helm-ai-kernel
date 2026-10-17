package activitytrail

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxProviderBody = 8 << 20

type githubClient struct {
	baseURL string
	http    *http.Client
}

func newGitHubClient(baseURL string, client *http.Client) (*githubClient, error) {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/" && u.Path != "/api/v3") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("GitHub API URL must be an absolute API root")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (ip == nil || !ip.IsLoopback()) && u.Hostname() != "localhost" {
			return nil, errors.New("GitHub API URL must use https, except for loopback tests")
		}
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	} else {
		copyClient := *client
		if copyClient.Timeout == 0 {
			copyClient.Timeout = 20 * time.Second
		}
		copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &copyClient
	}
	return &githubClient{baseURL: strings.TrimRight(baseURL, "/"), http: client}, nil
}

func (g *githubClient) get(ctx context.Context, token, path string, query url.Values, out any) ([32]byte, http.Header, error) {
	var zero [32]byte
	u := g.baseURL + path
	if len(query) != 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return zero, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "helm-gateway-activitytrail")
	resp, err := g.http.Do(req)
	if err != nil {
		return zero, nil, fmt.Errorf("GitHub GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.ContentLength > maxProviderBody {
		return zero, nil, fmt.Errorf("GitHub GET %s: response too large", path)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody+1))
	if err != nil {
		return zero, nil, err
	}
	if len(raw) > maxProviderBody {
		return zero, nil, fmt.Errorf("GitHub GET %s: response too large", path)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, nil, fmt.Errorf("GitHub GET %s: status %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return zero, nil, fmt.Errorf("GitHub GET %s: invalid JSON: %w", path, err)
	}
	return sha256.Sum256(raw), resp.Header, nil
}

func repoPath(repository string) (string, error) {
	owner, name, err := repositoryParts(repository)
	if err != nil {
		return "", err
	}
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name), nil
}

type repositoryInfo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

type referenceInfo struct {
	Ref    string `json:"ref"`
	Object struct {
		SHA  string `json:"sha"`
		Type string `json:"type"`
	} `json:"object"`
}

type snapshot struct {
	branch, head          string
	repoDigest, refDigest [32]byte
}

func (g *githubClient) snapshot(ctx context.Context, repository, token string) (snapshot, error) {
	path, err := repoPath(repository)
	if err != nil {
		return snapshot{}, err
	}
	var info repositoryInfo
	repoDigest, _, err := g.get(ctx, token, path, nil, &info)
	if err != nil {
		return snapshot{}, err
	}
	if !strings.EqualFold(info.FullName, strings.TrimPrefix(repository, "github.com/")) || info.DefaultBranch == "" || strings.Contains(info.DefaultBranch, "..") || strings.HasPrefix(info.DefaultBranch, "/") {
		return snapshot{}, errors.New("GitHub repository identity or default branch is invalid")
	}
	var ref referenceInfo
	refDigest, _, err := g.get(ctx, token, path+"/git/ref/heads/"+url.PathEscape(info.DefaultBranch), nil, &ref)
	if err != nil {
		return snapshot{}, err
	}
	if ref.Ref != "refs/heads/"+info.DefaultBranch || ref.Object.Type != "commit" || !validSHA(ref.Object.SHA) {
		return snapshot{}, errors.New("GitHub default-branch reference is invalid")
	}
	return snapshot{branch: info.DefaultBranch, head: strings.ToLower(ref.Object.SHA), repoDigest: repoDigest, refDigest: refDigest}, nil
}

// compareProof is typed provider evidence; a response body hash per page
// preserves the exact read identity without retaining provider file content.
type compareProof struct {
	Status      string   `json:"status"`
	AheadBy     int      `json:"ahead_by"`
	CommitSHAs  []string `json:"commit_shas"`
	PageDigests []string `json:"page_digests"`
	RepoDigest  string   `json:"repo_digest"`
	RefDigest   string   `json:"ref_digest"`
}

type comparisonResponse struct {
	Status     string `json:"status"`
	AheadBy    int    `json:"ahead_by"`
	BaseCommit struct {
		SHA string `json:"sha"`
	} `json:"base_commit"`
	Commits []struct {
		SHA string `json:"sha"`
	} `json:"commits"`
}

// compare pages until all commits are accounted for. A truncated comparison
// fails closed: the cursor is not advanced, so the next poll can retry.
func (g *githubClient) compare(ctx context.Context, repository, before, after, token string, snap snapshot) (compareProof, error) {
	path, err := repoPath(repository)
	if err != nil {
		return compareProof{}, err
	}
	path += "/compare/" + before + "..." + after
	proof := compareProof{RepoDigest: digestString(snap.repoDigest[:]), RefDigest: digestString(snap.refDigest[:])}
	for page := 1; page <= 100; page++ {
		var result comparisonResponse
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		bodyDigest, _, err := g.get(ctx, token, path, q, &result)
		if err != nil {
			return compareProof{}, err
		}
		if page == 1 {
			if !validSHA(result.BaseCommit.SHA) || !strings.EqualFold(result.BaseCommit.SHA, before) || result.AheadBy < 0 || result.AheadBy > 10000 {
				return compareProof{}, fmt.Errorf("%w: invalid base or count", ErrIncompleteCompare)
			}
			switch result.Status {
			case "ahead", "behind", "diverged":
			default:
				return compareProof{}, fmt.Errorf("%w: unexpected status %q", ErrIncompleteCompare, result.Status)
			}
			proof.Status, proof.AheadBy = result.Status, result.AheadBy
		} else if result.Status != proof.Status || result.AheadBy != proof.AheadBy || !strings.EqualFold(result.BaseCommit.SHA, before) {
			return compareProof{}, fmt.Errorf("%w: comparison changed between pages", ErrIncompleteCompare)
		}
		proof.PageDigests = append(proof.PageDigests, digestString(bodyDigest[:]))
		for _, commit := range result.Commits {
			if !validSHA(commit.SHA) {
				return compareProof{}, fmt.Errorf("%w: invalid commit SHA", ErrIncompleteCompare)
			}
			proof.CommitSHAs = append(proof.CommitSHAs, strings.ToLower(commit.SHA))
		}
		if len(proof.CommitSHAs) == proof.AheadBy {
			if len(proof.CommitSHAs) == 0 || !strings.EqualFold(proof.CommitSHAs[len(proof.CommitSHAs)-1], after) {
				return compareProof{}, fmt.Errorf("%w: final commit does not match the default-branch head", ErrIncompleteCompare)
			}
			return proof, nil
		}
		if len(result.Commits) == 0 || len(proof.CommitSHAs) > proof.AheadBy || len(result.Commits) != 100 {
			return compareProof{}, fmt.Errorf("%w: missing commits (%d of %d)", ErrIncompleteCompare, len(proof.CommitSHAs), proof.AheadBy)
		}
	}
	return compareProof{}, fmt.Errorf("%w: page limit", ErrIncompleteCompare)
}

type repositoryEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
	Actor     struct {
		Login string `json:"login"`
	} `json:"actor"`
	Repo struct {
		Name string `json:"name"`
	} `json:"repo"`
	Payload struct {
		Ref    string `json:"ref"`
		Before string `json:"before"`
		Head   string `json:"head"`
	} `json:"payload"`
}

// events reads GitHub's bounded, delayed repository timeline. Its timing is
// never treated as a real-time guarantee. An event ID is the delivery ID for
// deduplication in this read path.
func (g *githubClient) events(ctx context.Context, repository, token string) ([]repositoryEvent, int, bool, error) {
	path, err := repoPath(repository)
	if err != nil {
		return nil, 0, false, err
	}
	path += "/events"
	var all []repositoryEvent
	interval := 60
	for page := 1; page <= 3; page++ {
		var batch []repositoryEvent
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		_, header, err := g.get(ctx, token, path, q, &batch)
		if err != nil {
			return nil, 0, false, err
		}
		if raw := header.Get("X-Poll-Interval"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > interval && n <= 3600 {
				interval = n
			}
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return all, interval, len(all) == 300, nil
}
