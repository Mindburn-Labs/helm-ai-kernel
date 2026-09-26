package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// The §9.3 qualification suite. Every case runs the same way against the
// fake GitHub and against a live sandbox repository: faults are injected on
// the client side (a lost answer, an oversized answer, a rejected token, a
// small size limit), and read-back mismatches are produced by observing
// against a proposal that differs from what GitHub holds, or by a person's
// change (marking a draft ready). Nothing here needs the provider to
// misbehave on request.

// qualEnv is one provider environment.
type qualEnv struct {
	name        string
	baseURL     string
	owner, repo string
	token       string
	baseBranch  string
	baseSHA     string
	headPrefix  string
	limitations []string
	// markReady turns the draft pull request into a ready one.
	markReady func(t *testing.T, pr *adapters.GitHubPullRequestResult)
	seq       atomic.Int64
}

func (e *qualEnv) target() string { return "github.com/" + e.owner + "/" + e.repo }

// head returns a fresh branch name for one case.
func (e *qualEnv) head(label string) string {
	return fmt.Sprintf("%s%s-%d", e.headPrefix, label, e.seq.Add(1))
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

type failingToken struct{}

func (failingToken) Token(context.Context) (string, error) {
	return "", errors.New("connection custody could not mint a token")
}

// counter counts the requests an adapter sends.
type counter struct {
	base         http.RoundTripper
	all, nonRead atomic.Int64
}

func (c *counter) RoundTrip(r *http.Request) (*http.Response, error) {
	c.all.Add(1)
	if r.Method != http.MethodGet {
		c.nonRead.Add(1)
	}
	return c.base.RoundTrip(r)
}

// dropAnswer performs the matching request and then loses its answer.
type dropAnswer struct {
	base           http.RoundTripper
	method, suffix string
}

func (d dropAnswer) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := d.base.RoundTrip(r)
	if err == nil && r.Method == d.method && strings.HasSuffix(r.URL.Path, d.suffix) {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, errors.New("injected: the connection reset after the provider answered")
	}
	return resp, err
}

// padAnswer performs the matching request and pads its answer past size.
type padAnswer struct {
	base           http.RoundTripper
	method, suffix string
	size           int
}

func (p padAnswer) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := p.base.RoundTrip(r)
	if err == nil && r.Method == p.method && strings.HasSuffix(r.URL.Path, p.suffix) {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		raw = append(raw, bytes.Repeat([]byte(" "), p.size+1)...)
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	}
	return resp, err
}

// adapter builds an adapter against env through wrap, and returns the
// counter of what it sent.
func (e *qualEnv) adapter(wrap func(http.RoundTripper) http.RoundTripper, opts ...Option) (*Adapter, *counter) {
	var rt http.RoundTripper = http.DefaultTransport
	if wrap != nil {
		rt = wrap(rt)
	}
	c := &counter{base: rt}
	opts = append([]Option{WithBaseURL(e.baseURL), WithHTTPClient(&http.Client{Transport: c, Timeout: 30 * time.Second})}, opts...)
	return New(opts...), c
}

func (e *qualEnv) creds() adapters.TokenSource { return staticToken(e.token) }

type file struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Content string `json:"content_utf8"`
}

func (e *qualEnv) branchEffect(head, baseSHA string, files ...file) adapters.Effect {
	raw, _ := json.Marshal(map[string]any{
		"schema": "helm.github.branch.create_from_changes.v1", "base": e.baseBranch, "base_sha": baseSHA,
		"head": head, "message": "helm qualification: " + head, "files": files,
	})
	return adapters.Effect{EffectType: EffectBranchCreateFromChanges, Target: e.target(), Arguments: raw}
}

func (e *qualEnv) pullRequestEffect(head, headSHA, title string) adapters.Effect {
	raw, _ := json.Marshal(map[string]any{
		"schema": "helm.github.pull_request.create_draft.v1", "branch_attempt_id": "0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d",
		"base": e.baseBranch, "head": head, "head_sha": headSHA, "title": title, "body": "Opened by the HELM qualification suite.",
	})
	return adapters.Effect{EffectType: EffectPullRequestCreateDraft, Target: e.target(), Arguments: raw}
}

func (e *qualEnv) repositoryEffect(branch string) adapters.Effect {
	args := map[string]any{"schema": "helm.github.repository.get.v1"}
	if branch != "" {
		args["branch"] = branch
	}
	raw, _ := json.Marshal(args)
	return adapters.Effect{EffectType: EffectRepositoryGet, Target: e.target(), Arguments: raw}
}

func permit(effect adapters.Effect) []byte {
	sum := sha256.Sum256(effect.Arguments)
	return sum[:]
}

var skeletonFiles = []file{
	{Path: "docs/skeleton.md", Mode: "100644", Content: "# Skeleton\n"},
	{Path: "scripts/ok.sh", Mode: "100755", Content: "#!/bin/sh\necho ok\n"},
}

func wantDispatch(t *testing.T, got adapters.DispatchResult, status adapters.DispatchStatus, reason contracts.ReasonCode) {
	t.Helper()
	if got.Status != status || got.Reason != reason {
		t.Fatalf("Dispatch = %s %s (%s), want %s %s", got.Status, got.Reason, got.Detail, status, reason)
	}
}

func wantObserve(t *testing.T, got adapters.ObserveResult, outcome adapters.Outcome, reason contracts.ReasonCode) {
	t.Helper()
	if got.Outcome != outcome || got.Reason != reason {
		t.Fatalf("Observe = %s %s (%s), want %s %s", got.Outcome, got.Reason, got.Detail, outcome, reason)
	}
	if outcome == adapters.OutcomeUnknown {
		if got.Observation != nil {
			t.Fatal("an inconclusive read-back carries an observation")
		}
		return
	}
	obs := got.Observation
	if obs == nil || obs.Source != observationSource || obs.TrustClass != trustClass || len(obs.EvidenceDigest) != sha256.Size || obs.ObservedAt.IsZero() {
		t.Fatalf("Observe established %s without a complete observation: %+v", outcome, obs)
	}
}

// createBranch dispatches a branch and requires it to be observed.
func (e *qualEnv) createBranch(t *testing.T, head string, files ...file) (adapters.Effect, *adapters.GitHubBranchResult) {
	t.Helper()
	a, _ := e.adapter(nil)
	effect := e.branchEffect(head, e.baseSHA, files...)
	wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	got := a.Observe(context.Background(), e.creds(), effect)
	wantObserve(t, got, adapters.OutcomeSucceeded, "")
	return effect, got.Observation.GitHubBranch
}

// createPullRequest creates a branch and its draft pull request.
func (e *qualEnv) createPullRequest(t *testing.T, label string) (adapters.Effect, *adapters.GitHubPullRequestResult) {
	t.Helper()
	head := e.head(label)
	_, branch := e.createBranch(t, head, skeletonFiles...)
	a, _ := e.adapter(nil)
	effect := e.pullRequestEffect(head, branch.CommitSHA, "HELM qualification "+head)
	wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	got := a.Observe(context.Background(), e.creds(), effect)
	wantObserve(t, got, adapters.OutcomeSucceeded, "")
	return effect, got.Observation.GitHubPullRequest
}

// openPulls counts the open pull requests from head into the base branch.
func (e *qualEnv) openPulls(t *testing.T, head string) int {
	t.Helper()
	c := &client{a: New(WithBaseURL(e.baseURL)), token: e.token, repo: repository{Owner: e.owner, Name: e.repo}}
	pulls, err := c.listPulls(context.Background(), head, e.baseBranch, "open")
	if err != nil {
		t.Fatalf("list pull requests: %v", err)
	}
	return len(pulls)
}

type qualCase func(t *testing.T, env *qualEnv)

var qualCases = map[string]qualCase{
	"branch/happy-path": func(t *testing.T, env *qualEnv) {
		a, _ := env.adapter(nil)
		head := env.head("happy")
		effect := env.branchEffect(head, env.baseSHA, skeletonFiles...)
		prep, err := a.Prepare(context.Background(), env.creds(), effect)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		if prep.Resolved["default_branch"] != env.baseBranch || prep.Declaration.RiskClass != adapters.RiskMedium {
			t.Fatalf("Prepare resolved %+v", prep)
		}
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
		got := a.Observe(context.Background(), env.creds(), effect)
		wantObserve(t, got, adapters.OutcomeSucceeded, "")
		b := got.Observation.GitHubBranch
		if b.Ref != "refs/heads/"+head || !shaRE.MatchString(b.CommitSHA) || b.BaseSHA != env.baseSHA {
			t.Fatalf("branch result %+v", b)
		}
		if want := "c361fc7cce27fa9aa3f9e7ef1b275961a2418fff20e16fa1846e5bc50b43ec54"; fmt.Sprintf("%x", b.FilesDigest) != want {
			t.Fatalf("files_digest %x, want the contract vector %s", b.FilesDigest, want)
		}
	},
	"branch/duplicate-submission": func(t *testing.T, env *qualEnv) {
		effect, first := env.createBranch(t, env.head("dup"), skeletonFiles...)
		a, sent := env.adapter(nil)
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("the second dispatch sent %d writes", n)
		}
		got := a.Observe(context.Background(), env.creds(), effect)
		wantObserve(t, got, adapters.OutcomeSucceeded, "")
		if got.Observation.GitHubBranch.CommitSHA != first.CommitSHA {
			t.Fatalf("the branch moved from %s to %s", first.CommitSHA, got.Observation.GitHubBranch.CommitSHA)
		}
	},
	"branch/existing-ref-not-overwritten": func(t *testing.T, env *qualEnv) {
		head := env.head("exists")
		_, first := env.createBranch(t, head, skeletonFiles...)
		other := env.branchEffect(head, env.baseSHA, file{Path: "docs/other.md", Mode: "100644", Content: "other\n"})
		a, sent := env.adapter(nil)
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), other, permit(other)), adapters.DispatchSent, "")
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("the dispatch onto an existing ref sent %d writes", n)
		}
		got := a.Observe(context.Background(), env.creds(), other)
		wantObserve(t, got, adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
		if got.Observation.GitHubBranch.CommitSHA != first.CommitSHA {
			t.Fatalf("the existing ref was overwritten: %s, was %s", got.Observation.GitHubBranch.CommitSHA, first.CommitSHA)
		}
	},
	"branch/lost-response": func(t *testing.T, env *qualEnv) {
		lossy, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
			return dropAnswer{base: rt, method: http.MethodPost, suffix: "/git/refs"}
		})
		effect := env.branchEffect(env.head("lost"), env.baseSHA, skeletonFiles...)
		wantDispatch(t, lossy.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchIndefinite, contracts.ReasonProviderError)
		a, _ := env.adapter(nil)
		wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
	},
	"branch/revoked-credential": func(t *testing.T, env *qualEnv) {
		a, sent := env.adapter(nil)
		effect := env.branchEffect(env.head("revoked"), env.baseSHA, skeletonFiles...)
		wantDispatch(t, a.Dispatch(context.Background(), staticToken("ghs_revoked"), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected)
		wantDispatch(t, a.Dispatch(context.Background(), failingToken{}, effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected)
		if _, err := a.Prepare(context.Background(), staticToken("ghs_revoked"), effect); !refusedWith(err, contracts.ReasonProviderCredentialRejected) {
			t.Fatalf("Prepare with a revoked token: %v", err)
		}
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("a rejected credential sent %d writes", n)
		}
		created, _ := env.createBranch(t, env.head("revoked-observe"), skeletonFiles...)
		wantObserve(t, a.Observe(context.Background(), staticToken("ghs_revoked"), created), adapters.OutcomeUnknown, contracts.ReasonProviderCredentialRejected)
	},
	"branch/precondition-failed": func(t *testing.T, env *qualEnv) {
		a, sent := env.adapter(nil)
		onDefault := env.branchEffect(env.baseBranch, env.baseSHA, skeletonFiles...)
		if _, err := a.Prepare(context.Background(), env.creds(), onDefault); !refusedWith(err, contracts.ReasonPreconditionFailed) {
			t.Fatalf("Prepare on the default branch: %v", err)
		}
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), onDefault, permit(onDefault)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
		noBase := env.branchEffect(env.head("nobase"), strings.Repeat("0", 40), skeletonFiles...)
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), noBase, permit(noBase)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("a failed precondition sent %d writes", n)
		}
	},
	"branch/readback-mismatch": func(t *testing.T, env *qualEnv) {
		head := env.head("mismatch")
		_, created := env.createBranch(t, head, skeletonFiles...)
		a, _ := env.adapter(nil)
		for name, proposal := range map[string]adapters.Effect{
			"wrong parent": env.branchEffect(head, strings.Repeat("1", 40), skeletonFiles...),
			"extra file":   env.branchEffect(head, env.baseSHA, skeletonFiles[0]),
			"blob differs": env.branchEffect(head, env.baseSHA, skeletonFiles[0], file{Path: "scripts/ok.sh", Mode: "100755", Content: "#!/bin/sh\necho changed\n"}),
		} {
			got := a.Observe(context.Background(), env.creds(), proposal)
			wantObserve(t, got, adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
			if got.Observation.GitHubBranch.CommitSHA != created.CommitSHA {
				t.Fatalf("%s: the result does not record the commit found", name)
			}
		}
	},
	"branch/oversized-response": func(t *testing.T, env *qualEnv) {
		effect := env.branchEffect(env.head("oversized"), env.baseSHA, skeletonFiles...)
		tiny, sent := env.adapter(nil, WithMaxResponseBytes(64))
		wantDispatch(t, tiny.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderResponseTooLarge)
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("an oversized read sent %d writes", n)
		}
		padded, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
			return padAnswer{base: rt, method: http.MethodPost, suffix: "/git/refs", size: DefaultMaxResponseBytes}
		})
		wantDispatch(t, padded.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchIndefinite, contracts.ReasonProviderResponseTooLarge)
		a, _ := env.adapter(nil)
		wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
		wantObserve(t, tiny.Observe(context.Background(), env.creds(), effect), adapters.OutcomeUnknown, contracts.ReasonProviderResponseTooLarge)
	},
	"branch/permit-mismatch": func(t *testing.T, env *qualEnv) {
		a, sent := env.adapter(nil)
		effect := env.branchEffect(env.head("permit"), env.baseSHA, skeletonFiles...)
		other := env.branchEffect(env.head("permit-other"), env.baseSHA, skeletonFiles...)
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(other)), adapters.DispatchNotSent, contracts.ReasonPermitArgumentMismatch)
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, nil), adapters.DispatchNotSent, contracts.ReasonPermitArgumentMismatch)
		if n := sent.all.Load(); n != 0 {
			t.Fatalf("a permit mismatch sent %d requests", n)
		}
	},
	"branch/retarget": func(t *testing.T, env *qualEnv) {
		a, sent := env.adapter(nil)
		effect := env.branchEffect(env.head("retarget"), env.baseSHA, skeletonFiles...)
		withRepo := effect
		withRepo.Arguments = append(bytes.TrimSuffix(effect.Arguments, []byte("}")), []byte(`,"repo":"attacker/elsewhere"}`)...)
		cases := []adapters.Effect{withRepo}
		for _, target := range []string{
			env.target() + "#x", env.target() + "?ref=x", env.target() + "/extra", env.target() + "/",
			"github.com/" + env.owner + "/..", "gitlab.com/" + env.owner + "/" + env.repo, "https://" + env.target(),
		} {
			retargeted := effect
			retargeted.Target = target
			cases = append(cases, retargeted)
		}
		for _, c := range cases {
			if _, err := a.Prepare(context.Background(), env.creds(), c); !refusedWith(err, contracts.ReasonSchemaViolation) {
				t.Fatalf("Prepare(%s, %s): %v", c.Target, c.Arguments, err)
			}
			wantDispatch(t, a.Dispatch(context.Background(), env.creds(), c, permit(c)), adapters.DispatchNotSent, contracts.ReasonSchemaViolation)
		}
		if n := sent.all.Load(); n != 0 {
			t.Fatalf("a retarget attempt sent %d requests", n)
		}
	},
	"pull_request/happy-path": func(t *testing.T, env *qualEnv) {
		effect, pr := env.createPullRequest(t, "pr-happy")
		if !pr.Draft || pr.State != "open" || pr.Number <= 0 || !strings.HasPrefix(pr.URL, "https://github.com/"+env.owner+"/"+env.repo+"/pull/") || pr.BaseRef != env.baseBranch {
			t.Fatalf("pull request result %+v", pr)
		}
		a, _ := env.adapter(nil)
		if _, err := a.Prepare(context.Background(), env.creds(), effect); err != nil {
			t.Fatalf("Prepare after creation: %v", err)
		}
	},
	"pull_request/duplicate-submission": func(t *testing.T, env *qualEnv) {
		effect, first := env.createPullRequest(t, "pr-dup")
		a, sent := env.adapter(nil)
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("the second dispatch sent %d writes", n)
		}
		got := a.Observe(context.Background(), env.creds(), effect)
		wantObserve(t, got, adapters.OutcomeSucceeded, "")
		if got.Observation.GitHubPullRequest.Number != first.Number || env.openPulls(t, first.HeadRef) != 1 {
			t.Fatalf("a duplicate pull request was opened")
		}
	},
	"pull_request/lost-response": func(t *testing.T, env *qualEnv) {
		head := env.head("pr-lost")
		_, branch := env.createBranch(t, head, skeletonFiles...)
		lossy, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
			return dropAnswer{base: rt, method: http.MethodPost, suffix: "/pulls"}
		})
		effect := env.pullRequestEffect(head, branch.CommitSHA, "HELM qualification "+head)
		wantDispatch(t, lossy.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchIndefinite, contracts.ReasonProviderError)
		a, _ := env.adapter(nil)
		wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
	},
	"pull_request/revoked-credential": func(t *testing.T, env *qualEnv) {
		head := env.head("pr-revoked")
		_, branch := env.createBranch(t, head, skeletonFiles...)
		a, sent := env.adapter(nil)
		effect := env.pullRequestEffect(head, branch.CommitSHA, "HELM qualification "+head)
		wantDispatch(t, a.Dispatch(context.Background(), staticToken("ghs_revoked"), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected)
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("a rejected credential sent %d writes", n)
		}
		wantObserve(t, a.Observe(context.Background(), staticToken("ghs_revoked"), effect), adapters.OutcomeUnknown, contracts.ReasonProviderCredentialRejected)
		if env.openPulls(t, head) != 0 {
			t.Fatal("a pull request was opened with a rejected credential")
		}
	},
	"pull_request/head-moved": func(t *testing.T, env *qualEnv) {
		head := env.head("pr-moved")
		env.createBranch(t, head, skeletonFiles...)
		// The approver saw base_sha as the head; the branch is elsewhere.
		effect := env.pullRequestEffect(head, env.baseSHA, "HELM qualification "+head)
		a, sent := env.adapter(nil)
		if _, err := a.Prepare(context.Background(), env.creds(), effect); !refusedWith(err, contracts.ReasonPreconditionFailed) {
			t.Fatalf("Prepare with a moved head: %v", err)
		}
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
		if n := sent.nonRead.Load(); n != 0 || env.openPulls(t, head) != 0 {
			t.Fatalf("a moved head sent %d writes", n)
		}
	},
	"pull_request/readback-mismatch": func(t *testing.T, env *qualEnv) {
		effect, pr := env.createPullRequest(t, "pr-mismatch")
		a, _ := env.adapter(nil)
		var args pullRequestArgs
		args, _ = parsePullRequestArgs(effect.Arguments)
		retitled := env.pullRequestEffect(args.Head, args.HeadSHA, "another title")
		got := a.Observe(context.Background(), env.creds(), retitled)
		wantObserve(t, got, adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
		if got.Observation.GitHubPullRequest.URL != pr.URL {
			t.Fatalf("the mismatch does not record the URL: %+v", got.Observation.GitHubPullRequest)
		}
		env.markReady(t, pr)
		got = a.Observe(context.Background(), env.creds(), effect)
		wantObserve(t, got, adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
		if r := got.Observation.GitHubPullRequest; r.URL != pr.URL || r.Draft {
			t.Fatalf("a ready pull request read back as %+v", r)
		}
	},
	"pull_request/oversized-response": func(t *testing.T, env *qualEnv) {
		head := env.head("pr-oversized")
		_, branch := env.createBranch(t, head, skeletonFiles...)
		effect := env.pullRequestEffect(head, branch.CommitSHA, "HELM qualification "+head)
		padded, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
			return padAnswer{base: rt, method: http.MethodPost, suffix: "/pulls", size: DefaultMaxResponseBytes}
		})
		wantDispatch(t, padded.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchIndefinite, contracts.ReasonProviderResponseTooLarge)
		a, _ := env.adapter(nil)
		wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
		tiny, _ := env.adapter(nil, WithMaxResponseBytes(64))
		wantObserve(t, tiny.Observe(context.Background(), env.creds(), effect), adapters.OutcomeUnknown, contracts.ReasonProviderResponseTooLarge)
	},
	"pull_request/permit-mismatch": func(t *testing.T, env *qualEnv) {
		a, sent := env.adapter(nil)
		effect := env.pullRequestEffect(env.head("pr-permit"), env.baseSHA, "t")
		other := env.pullRequestEffect(env.head("pr-permit"), env.baseSHA, "u")
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(other)), adapters.DispatchNotSent, contracts.ReasonPermitArgumentMismatch)
		if n := sent.all.Load(); n != 0 {
			t.Fatalf("a permit mismatch sent %d requests", n)
		}
	},
	"repository/happy-path": func(t *testing.T, env *qualEnv) {
		head := env.head("repo-get")
		_, branch := env.createBranch(t, head, skeletonFiles...)
		a, sent := env.adapter(nil)
		for _, c := range []struct {
			branch string
			want   adapters.GitHubRepositoryResult
		}{
			{"", adapters.GitHubRepositoryResult{DefaultBranch: env.baseBranch, DefaultBranchSHA: env.baseSHA}},
			{head, adapters.GitHubRepositoryResult{DefaultBranch: env.baseBranch, DefaultBranchSHA: env.baseSHA,
				Branch: head, BranchSHA: branch.CommitSHA, BranchExists: true}},
			{head + "-absent", adapters.GitHubRepositoryResult{DefaultBranch: env.baseBranch, DefaultBranchSHA: env.baseSHA,
				Branch: head + "-absent"}},
		} {
			effect := env.repositoryEffect(c.branch)
			if prep, err := a.Prepare(context.Background(), env.creds(), effect); err != nil || prep.Declaration.RiskClass != adapters.RiskLow {
				t.Fatalf("Prepare: %+v %v", prep, err)
			}
			wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
			got := a.Observe(context.Background(), env.creds(), effect)
			wantObserve(t, got, adapters.OutcomeSucceeded, "")
			if *got.Observation.GitHubRepository != c.want {
				t.Fatalf("read %+v, want %+v", *got.Observation.GitHubRepository, c.want)
			}
		}
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("a read sent %d writes", n)
		}
	},
	"repository/revoked-credential": func(t *testing.T, env *qualEnv) {
		a, sent := env.adapter(nil)
		effect := env.repositoryEffect(env.baseBranch)
		wantDispatch(t, a.Dispatch(context.Background(), staticToken("ghs_revoked"), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected)
		wantDispatch(t, a.Dispatch(context.Background(), failingToken{}, effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected)
		wantObserve(t, a.Observe(context.Background(), staticToken("ghs_revoked"), effect), adapters.OutcomeUnknown, contracts.ReasonProviderCredentialRejected)
		if n := sent.nonRead.Load(); n != 0 {
			t.Fatalf("a read sent %d writes", n)
		}
	},
	"repository/oversized-response": func(t *testing.T, env *qualEnv) {
		tiny, _ := env.adapter(nil, WithMaxResponseBytes(64))
		effect := env.repositoryEffect("")
		wantDispatch(t, tiny.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderResponseTooLarge)
		wantObserve(t, tiny.Observe(context.Background(), env.creds(), effect), adapters.OutcomeUnknown, contracts.ReasonProviderResponseTooLarge)
		padded, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
			return padAnswer{base: rt, method: http.MethodGet, suffix: "/git/ref/heads/" + env.baseBranch, size: DefaultMaxResponseBytes}
		})
		wantObserve(t, padded.Observe(context.Background(), env.creds(), effect), adapters.OutcomeUnknown, contracts.ReasonProviderResponseTooLarge)
	},
	"repository/permit-mismatch": func(t *testing.T, env *qualEnv) {
		a, sent := env.adapter(nil)
		effect, other := env.repositoryEffect(""), env.repositoryEffect(env.baseBranch)
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(other)), adapters.DispatchNotSent, contracts.ReasonPermitArgumentMismatch)
		if n := sent.all.Load(); n != 0 {
			t.Fatalf("a permit mismatch sent %d requests", n)
		}
	},
}

func refusedWith(err error, reason contracts.ReasonCode) bool {
	var r *adapters.Refusal
	return errors.As(err, &r) && r.Reason == reason
}

// runQualification runs every suite case against env and returns the
// records. A case that fails or is skipped leaves its operation unqualified.
func runQualification(t *testing.T, env *qualEnv) []adapters.QualificationRecord {
	results := map[string]adapters.CheckStatus{}
	for _, c := range QualificationSuite.Cases {
		run, ok := qualCases[c.ID]
		if !ok {
			t.Errorf("suite case %s has no implementation", c.ID)
			continue
		}
		status := adapters.CheckFail
		t.Run(c.ID, func(t *testing.T) {
			defer func() {
				switch {
				case t.Skipped():
					status = adapters.CheckSkipped
				case !t.Failed():
					status = adapters.CheckPass
				}
			}()
			run(t, env)
		})
		results[c.ID] = status
	}
	records := QualificationSuite.Records(env.name, results, env.limitations)
	raw, _ := json.MarshalIndent(records, "", "  ")
	t.Logf("qualification records:\n%s", raw)
	if out := os.Getenv("HELM_GITHUB_QUAL_RECORD"); out != "" {
		if err := os.WriteFile(out, raw, 0o600); err != nil {
			t.Errorf("write %s: %v", out, err)
		}
	}
	return records
}

func TestQualificationSuiteIsImplemented(t *testing.T) {
	ids := map[string]bool{}
	for _, c := range QualificationSuite.Cases {
		if ids[c.ID] {
			t.Errorf("suite case %s is listed twice", c.ID)
		}
		ids[c.ID] = true
		if _, ok := qualCases[c.ID]; !ok {
			t.Errorf("suite case %s has no implementation", c.ID)
		}
	}
	for id := range qualCases {
		if !ids[id] {
			t.Errorf("implementation %s is not a suite case, so the suite digest does not cover it", id)
		}
	}
	// Every §9.3 failure case is covered for both writes. The read has no
	// write to duplicate, lose or read back, so it covers the other two.
	writeCases := []string{"duplicate submission", "lost response after success", "revoked credential",
		"precondition failure", "read-back mismatch", "response exceeding the size limit"}
	for op, categories := range map[string][]string{
		EffectBranchCreateFromChanges: writeCases,
		EffectPullRequestCreateDraft:  writeCases,
		EffectRepositoryGet:           {"revoked credential", "response exceeding the size limit"},
	} {
		covered := map[string]bool{}
		for _, c := range QualificationSuite.Cases {
			if c.Operation == op {
				covered[c.Category] = true
			}
		}
		for _, category := range categories {
			if !covered[category] {
				t.Errorf("%s has no case for %q", op, category)
			}
		}
	}
}

// TestQualificationFake runs the suite against the httptest GitHub. It is
// the qualification record for the environment "fake", and it must qualify.
func TestQualificationFake(t *testing.T) {
	fake := newFakeGitHub(t)
	env := &qualEnv{
		name:    "fake: httptest GitHub (core/pkg/gateway/adapters/github/fake_github_test.go)",
		baseURL: fake.server.URL, owner: fake.owner, repo: fake.name, token: fake.token,
		baseBranch: "main", baseSHA: fake.refs["heads/main"], headPrefix: "helm/qual/",
		limitations: []string{
			"The fake models the REST endpoints the adapter calls; it is not GitHub. Only a live run qualifies the adapter against the provider.",
		},
		markReady: func(t *testing.T, pr *adapters.GitHubPullRequestResult) { fake.markReady(pr.Number) },
	}
	for _, record := range runQualification(t, env) {
		if !record.Qualified {
			t.Errorf("%s did not qualify against the fake: %+v", record.Operation, record.Checks)
		}
	}
}
