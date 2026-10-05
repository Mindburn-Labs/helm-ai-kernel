package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github/githubtest"
)

func mergeFixture(t *testing.T) (*githubtest.GitHub, *qualEnv, adapters.Effect, int64) {
	t.Helper()
	f := githubtest.New(t)
	e := &qualEnv{baseURL: f.URL(), owner: f.Owner(), repo: f.Repository(), token: f.Token(), baseBranch: "main", baseSHA: f.Head("main"), headPrefix: "helm/merge/"}
	_, pr := e.createPullRequest(t, "approved")
	f.MarkReady(pr.Number)
	raw, err := json.Marshal(map[string]any{"schema": "helm.github.pull_request.merge.v1", "pull_number": pr.Number, "head_sha": pr.HeadSHA, "base": "main", "merge_method": "squash"})
	if err != nil {
		t.Fatal(err)
	}
	return f, e, adapters.Effect{EffectType: EffectPullRequestMerge, Target: e.target(), Arguments: raw}, pr.Number
}

func TestPullRequestMergeQueueAcknowledgementIsNotSuccess(t *testing.T) {
	for _, mode := range []string{"enqueued", "pending"} {
		t.Run(mode, func(t *testing.T) {
			f, e, effect, number := mergeFixture(t)
			f.SetMergeMode(mode)
			a, _ := e.adapter(nil)
			preparation, err := a.Prepare(context.Background(), e.creds(), effect)
			if err != nil || preparation == nil {
				t.Fatalf("prepare: %v", err)
			}
			wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchSent, "")
			pending := a.Observe(context.Background(), e.creds(), effect)
			wantObserve(t, pending, adapters.OutcomeUnknown, "")
			if pending.Absent || f.MergeRequests() != 1 {
				t.Fatal("queue acknowledgement must retain uncertainty without permission to resubmit")
			}
			f.CompleteMerge(number)
			got := a.Observe(context.Background(), e.creds(), effect)
			wantObserve(t, got, adapters.OutcomeSucceeded, "")
			if !got.Observation.GitHubPullRequest.Merged || got.Observation.GitHubPullRequest.MergeCommitSHA != f.Head("main") {
				t.Fatal("success must identify the actual merged commit")
			}
			wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchSent, "")
			if f.MergeRequests() != 1 {
				t.Fatal("retry of the observed merged effect issued another provider write")
			}
		})
	}
}

func TestPullRequestMergeLostOrOversizedAnswerReconcilesWithoutAnotherWrite(t *testing.T) {
	for _, fault := range []string{"lost", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			f, e, effect, _ := mergeFixture(t)
			f.SetMergeMode("merged")
			a, _ := e.adapter(func(base http.RoundTripper) http.RoundTripper {
				if fault == "lost" {
					return dropAnswer{base: base, method: http.MethodPut, suffix: "/merge-async"}
				}
				return padAnswer{base: base, method: http.MethodPut, suffix: "/merge-async", size: 4096}
			}, WithMaxResponseBytes(4096))
			got := a.Dispatch(context.Background(), e.creds(), effect, permit(effect))
			if got.Status != adapters.DispatchIndefinite {
				t.Fatalf("uncertain provider answer became a definite outcome: %+v", got)
			}
			clean, _ := e.adapter(nil)
			wantObserve(t, clean.Observe(context.Background(), e.creds(), effect), adapters.OutcomeSucceeded, "")
			wantDispatch(t, clean.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchSent, "")
			if f.MergeRequests() != 1 {
				t.Fatal("lost response caused a duplicate merge write")
			}
		})
	}
}

func TestPullRequestMergeScopeDriftNeverWrites(t *testing.T) {
	mutations := map[string]func(*githubtest.PullRequest){
		"head":            func(p *githubtest.PullRequest) { p.HeadSHA = strings.Repeat("a", 40) },
		"base":            func(p *githubtest.PullRequest) { p.Base = "other" },
		"draft":           func(p *githubtest.PullRequest) { p.Draft = true },
		"fork":            func(p *githubtest.PullRequest) { p.HeadRepository = "attacker/fork" },
		"base repository": func(p *githubtest.PullRequest) { p.BaseRepository = "other/repository" },
		"stack":           func(p *githubtest.PullRequest) { p.Stack = json.RawMessage(`{"count":2}`) },
		"malformed stack": func(p *githubtest.PullRequest) { p.Stack = json.RawMessage(`false`) },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			f, e, effect, number := mergeFixture(t)
			a, _ := e.adapter(nil)
			if _, err := a.Prepare(context.Background(), e.creds(), effect); err != nil {
				t.Fatal(err)
			}
			f.EditPull(number, change)
			wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
			wantObserve(t, a.Observe(context.Background(), e.creds(), effect), adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
			if f.MergeRequests() != 0 {
				t.Fatal("stale approval reached the provider write")
			}
		})
	}
}

func TestPullRequestMergeRefusesBadPermitAndRevokedCredential(t *testing.T) {
	f, e, effect, _ := mergeFixture(t)
	a, requests := e.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, nil), adapters.DispatchNotSent, contracts.ReasonPermitArgumentMismatch)
	if requests.all.Load() != 0 {
		t.Fatal("permit mismatch performed provider I/O")
	}
	wantDispatch(t, a.Dispatch(context.Background(), staticToken("revoked"), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected)
	if f.MergeRequests() != 0 {
		t.Fatal("revoked credential reached merge")
	}
}

type mergeReplyTransport struct {
	base   http.RoundTripper
	status int
	body   string
}

func (m mergeReplyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/merge-async") {
		return &http.Response{StatusCode: m.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(m.body)), Request: r}, nil
	}
	return m.base.RoundTrip(r)
}

func TestPullRequestMergeExistingPendingMustMatchApprovedOptions(t *testing.T) {
	for _, change := range []string{"same", "head", "bypass", "method", "malformed"} {
		t.Run(change, func(t *testing.T) {
			_, e, effect, _ := mergeFixture(t)
			args, err := parseMergeArgs(effect.Target, effect.Arguments)
			if err != nil {
				t.Fatal(err)
			}
			details := map[string]any{"message": "still pending", "uuid": "existing", "expected_head_sha": args.HeadSHA, "merge_method": "squash", "merge_action": "default", "bypass_rules": false}
			switch change {
			case "head":
				details["expected_head_sha"] = strings.Repeat("a", 40)
			case "bypass":
				details["bypass_rules"] = true
			case "method":
				details["merge_method"] = "merge"
			}
			raw, _ := json.Marshal(map[string]any{"status": "pending", "details": details})
			if change == "malformed" {
				raw = []byte(`{"message":"Conflict"}`)
			}
			a, _ := e.adapter(func(base http.RoundTripper) http.RoundTripper {
				return mergeReplyTransport{base: base, status: http.StatusConflict, body: string(raw)}
			})
			got := a.Dispatch(context.Background(), e.creds(), effect, permit(effect))
			if change == "same" {
				wantDispatch(t, got, adapters.DispatchSent, "")
			} else if got.Status != adapters.DispatchIndefinite || got.Reason != contracts.ReasonConnectorContractDrift {
				t.Fatalf("mismatched pending request: %+v", got)
			}
			wantObserve(t, a.Observe(context.Background(), e.creds(), effect), adapters.OutcomeUnknown, "")
		})
	}
}

func TestPullRequestMergeClosedWithoutMergeFails(t *testing.T) {
	f, e, effect, number := mergeFixture(t)
	f.EditPull(number, func(p *githubtest.PullRequest) { p.State = "closed" })
	a, _ := e.adapter(nil)
	wantObserve(t, a.Observe(context.Background(), e.creds(), effect), adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
	wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
	if f.MergeRequests() != 0 {
		t.Fatal("closed pull request was written")
	}
}

func TestReadyPullRequestIsDistinctAndReplaysWithoutDuplicate(t *testing.T) {
	f := githubtest.New(t)
	e := &qualEnv{baseURL: f.URL(), owner: f.Owner(), repo: f.Repository(), token: f.Token(), baseBranch: "main", baseSHA: f.Head("main"), headPrefix: "helm/create/"}
	head := e.head("ready")
	_, branch := e.createBranch(t, head, skeletonFiles...)
	effect := e.pullRequestEffect(head, branch.CommitSHA, "Ready pull request")
	effect.EffectType = EffectPullRequestCreate
	effect.Arguments = []byte(strings.Replace(string(effect.Arguments), "create_draft.v1", "create.v1", 1))
	a, requests := e.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	wantDispatch(t, a.Dispatch(context.Background(), e.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	got := a.Observe(context.Background(), e.creds(), effect)
	wantObserve(t, got, adapters.OutcomeSucceeded, "")
	if got.Observation.GitHubPullRequest.Draft || requests.nonRead.Load() != 1 {
		t.Fatal("ready creation was draft or duplicated")
	}
	if declaration, ok := declaration(EffectPullRequestMerge); !ok || declaration.RiskClass != adapters.RiskHigh {
		t.Fatal("merge risk floor missing")
	}
}
