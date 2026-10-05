package github

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// Ready creation has the same argument, replay and readback obligations as
// draft creation. Run the same cases with its own declaration and draft state.
func init() {
	QualificationSuite.SuiteVersion = "2"
	for _, c := range []struct{ id, category, description string }{
		{"happy-path", "baseline", "Create and read back a ready pull request at the approved head."},
		{"duplicate-submission", "duplicate submission", "A duplicate creates no second pull request."},
		{"lost-response", "lost response after success", "A lost create answer is indefinite and reconciled by authoritative readback."},
		{"revoked-credential", "revoked credential", "A revoked credential cannot create or establish a successful readback."},
		{"head-moved", "precondition failure", "A moved approved head causes no write."},
		{"readback-mismatch", "read-back mismatch", "A changed title or draft state fails readback with evidence."},
		{"oversized-response", "response exceeding the size limit", "Oversized answers preserve uncertainty until an actual bounded read succeeds."},
		{"permit-mismatch", "boundary", "A mismatched permit performs no provider I/O."},
	} {
		id, impl := "ready_pull_request/"+c.id, qualCases["pull_request/"+c.id]
		QualificationSuite.Cases = append(QualificationSuite.Cases, qcase(id, EffectPullRequestCreate, c.category, c.description))
		qualCases[id] = func(t *testing.T, env *qualEnv) {
			previous := env.readyPullRequests
			env.readyPullRequests = true
			defer func() { env.readyPullRequests = previous }()
			impl(t, env)
		}
	}
	for _, c := range []struct {
		id, category, description string
		run                       func(*testing.T, *qualEnv)
	}{
		{"happy-path", "baseline", "Merge only the approved PR/head/base and confirm the actual merged commit, not queue acceptance.", qualifyMergeHappy},
		{"duplicate-submission", "duplicate submission", "A retry after actual merged readback sends no further provider write.", qualifyMergeDuplicate},
		{"lost-response", "lost response after success", "The merge applies but its answer is lost; only readback establishes success.", qualifyMergeLost},
		{"revoked-credential", "revoked credential", "Rejected credentials cause no merge and establish no successful readback.", qualifyMergeRevoked},
		{"head-moved", "precondition failure", "A head different from the approved SHA causes no merge write.", qualifyMergeHeadMoved},
		{"readback-mismatch", "read-back mismatch", "An incompatible approved head is FAILED by actual readback, never inferred success.", qualifyMergeReadbackMismatch},
		{"oversized-response", "response exceeding the size limit", "Oversized reads cause no write; oversized write replies remain indefinite until bounded readback.", qualifyMergeOversized},
		{"permit-mismatch", "boundary", "A bad permit performs no provider I/O, including reads.", qualifyMergePermit},
	} {
		id := "merge/" + c.id
		QualificationSuite.Cases = append(QualificationSuite.Cases, qcase(id, EffectPullRequestMerge, c.category, c.description))
		qualCases[id] = c.run
	}
}

// Each merge uses its own disposable base branch. Adapter qualification never
// changes the sandbox's default branch; default-branch rules are a separate
// governed end-to-end gate. The live run must explicitly authorize merges.
func (e *qualEnv) mergeEffect(t *testing.T, label string) adapters.Effect {
	t.Helper()
	if !e.allowMerge {
		t.Skip("merge qualification requires explicit disposable-repository merge authorization; this is not a qualification")
	}
	base, head := e.head("merge-base-"+label), e.head("merge-head-"+label)
	e.createBranch(t, base, file{Path: "docs/merge-base.md", Mode: "100644", Content: label + "\n"})
	_, branch := e.createBranch(t, head, file{Path: "docs/merge-head.md", Mode: "100644", Content: label + "\n"})
	raw, _ := json.Marshal(map[string]any{
		"schema": "helm.github.pull_request.create.v1", "branch_attempt_id": "0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d",
		"base": base, "head": head, "head_sha": branch.CommitSHA, "title": "HELM merge qualification " + label,
		"body": "Opened by the HELM qualification suite.",
	})
	create := adapters.Effect{EffectType: EffectPullRequestCreate, Target: e.target(), Arguments: raw}
	a, _ := e.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), e.creds(), create, permit(create)), adapters.DispatchSent, "")
	created := a.Observe(context.Background(), e.creds(), create)
	wantObserve(t, created, adapters.OutcomeSucceeded, "")
	pr := created.Observation.GitHubPullRequest
	raw, _ = json.Marshal(map[string]any{"schema": "helm.github.pull_request.merge.v1", "pull_number": pr.Number,
		"head_sha": pr.HeadSHA, "base": base, "merge_method": "squash"})
	return adapters.Effect{EffectType: EffectPullRequestMerge, Target: e.target(), Arguments: raw}
}

func qualifyMergeHappy(t *testing.T, env *qualEnv) {
	effect := env.mergeEffect(t, "happy")
	a, _ := env.adapter(nil)
	prepared, err := a.Prepare(context.Background(), env.creds(), effect)
	if err != nil || prepared == nil || prepared.Declaration.RiskClass != adapters.RiskHigh {
		t.Fatalf("merge preparation: %+v %v", prepared, err)
	}
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	got := a.Observe(context.Background(), env.creds(), effect)
	wantObserve(t, got, adapters.OutcomeSucceeded, "")
	if pr := got.Observation.GitHubPullRequest; !pr.Merged || pr.State != "closed" || !shaRE.MatchString(pr.MergeCommitSHA) {
		t.Fatalf("no actual merged-commit readback: %+v", pr)
	}
}

func qualifyMergeDuplicate(t *testing.T, env *qualEnv) {
	effect := env.mergeEffect(t, "duplicate")
	a, _ := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	first := a.Observe(context.Background(), env.creds(), effect)
	wantObserve(t, first, adapters.OutcomeSucceeded, "")
	a, sent := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	got := a.Observe(context.Background(), env.creds(), effect)
	wantObserve(t, got, adapters.OutcomeSucceeded, "")
	if sent.nonRead.Load() != 0 || got.Observation.GitHubPullRequest.MergeCommitSHA != first.Observation.GitHubPullRequest.MergeCommitSHA {
		t.Fatal("merged retry wrote again or changed the observed commit")
	}
}

func qualifyMergeLost(t *testing.T, env *qualEnv) {
	effect := env.mergeEffect(t, "lost")
	lossy, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
		return dropAnswer{base: rt, method: http.MethodPut, suffix: "/merge-async"}
	})
	wantDispatch(t, lossy.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchIndefinite, contracts.ReasonProviderError)
	a, _ := env.adapter(nil)
	wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
}

func qualifyMergeRevoked(t *testing.T, env *qualEnv) {
	effect := env.mergeEffect(t, "revoked")
	a, sent := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), staticToken("revoked"), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected)
	wantObserve(t, a.Observe(context.Background(), staticToken("revoked"), effect), adapters.OutcomeUnknown, contracts.ReasonProviderCredentialRejected)
	if sent.nonRead.Load() != 0 {
		t.Fatal("rejected credentials reached a merge write")
	}
}

func changedMergeHead(t *testing.T, effect adapters.Effect) adapters.Effect {
	t.Helper()
	var args map[string]any
	if err := json.Unmarshal(effect.Arguments, &args); err != nil {
		t.Fatal(err)
	}
	args["head_sha"] = strings.Repeat("f", 40)
	effect.Arguments, _ = json.Marshal(args)
	return effect
}

func qualifyMergeHeadMoved(t *testing.T, env *qualEnv) {
	effect := changedMergeHead(t, env.mergeEffect(t, "head-moved"))
	a, sent := env.adapter(nil)
	if _, err := a.Prepare(context.Background(), env.creds(), effect); !refusedWith(err, contracts.ReasonPreconditionFailed) {
		t.Fatalf("Prepare with an unapproved head: %v", err)
	}
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
	if sent.nonRead.Load() != 0 {
		t.Fatal("head mismatch performed a merge write")
	}
}

func qualifyMergeReadbackMismatch(t *testing.T, env *qualEnv) {
	effect := changedMergeHead(t, env.mergeEffect(t, "readback"))
	a, _ := env.adapter(nil)
	got := a.Observe(context.Background(), env.creds(), effect)
	wantObserve(t, got, adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
	if got.Absent {
		t.Fatal("mismatched existing pull request reported absent")
	}
}

func qualifyMergeOversized(t *testing.T, env *qualEnv) {
	effect := env.mergeEffect(t, "oversized")
	tiny, sent := env.adapter(nil, WithMaxResponseBytes(64))
	wantDispatch(t, tiny.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderResponseTooLarge)
	if sent.nonRead.Load() != 0 {
		t.Fatal("oversized preflight caused a write")
	}
	padded, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
		return padAnswer{base: rt, method: http.MethodPut, suffix: "/merge-async", size: DefaultMaxResponseBytes}
	})
	wantDispatch(t, padded.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchIndefinite, contracts.ReasonProviderResponseTooLarge)
	wantObserve(t, tiny.Observe(context.Background(), env.creds(), effect), adapters.OutcomeUnknown, contracts.ReasonProviderResponseTooLarge)
	a, _ := env.adapter(nil)
	wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
}

func qualifyMergePermit(t *testing.T, env *qualEnv) {
	effect := env.mergeEffect(t, "permit")
	a, sent := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, nil), adapters.DispatchNotSent, contracts.ReasonPermitArgumentMismatch)
	if sent.all.Load() != 0 {
		t.Fatal("bad permit performed provider I/O")
	}
}
