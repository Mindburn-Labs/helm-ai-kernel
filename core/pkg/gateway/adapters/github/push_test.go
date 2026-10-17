package github

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

func pushFixture(t *testing.T) (*testkit.GitHub, *qualEnv, adapters.Effect) {
	t.Helper()
	fake := testkit.New(t)
	env := &qualEnv{baseURL: fake.URL(), owner: fake.Owner(), repo: fake.Repository(), token: fake.Token(), baseBranch: "main", baseSHA: fake.Head("main"), headPrefix: "helm/push/"}
	head := env.head("work")
	_, initial := env.createBranch(t, head, skeletonFiles...)
	return fake, env, pushEffect(t, env, head, initial.CommitSHA)
}

func pushEffect(t *testing.T, env *qualEnv, head, expected string) adapters.Effect {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema": "helm.github.git.push.v1", "base": env.baseBranch, "base_sha": expected,
		"head": head, "message": "governed push", "files": []file{{Path: "docs/push.md", Mode: "100644", Content: "bounded\n"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapters.Effect{EffectType: EffectGitPush, Target: env.target(), Arguments: raw}
}

func TestGitPushFastForwardReadbackAndReplay(t *testing.T) {
	fake, env, effect := pushFixture(t)
	a, _ := env.adapter(nil)
	prep, err := a.Prepare(context.Background(), env.creds(), effect)
	if err != nil || prep.Declaration.RiskClass != adapters.RiskMedium || len(prep.Quote) != 1 || prep.Quote[0].Amount != 1 {
		t.Fatalf("push preparation: %+v %v", prep, err)
	}
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	first := a.Observe(context.Background(), env.creds(), effect)
	wantObserve(t, first, adapters.OutcomeSucceeded, "")
	var args branchArgs
	args, err = parseBranchArgsFor(EffectGitPush, effect.Arguments)
	if err != nil || first.Observation.GitHubBranch.BaseSHA != args.BaseSHA || first.Observation.GitHubBranch.CommitSHA != fake.Head(args.Head) {
		t.Fatalf("push readback: %+v %v", first.Observation.GitHubBranch, err)
	}
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
	other := effect
	other.Arguments = []byte(strings.Replace(string(effect.Arguments), "governed push", "other message", 1))
	wantObserve(t, a.Observe(context.Background(), env.creds(), other), adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
	if fake.PushRequests() != 1 {
		t.Fatalf("replay performed %d ref writes, want one", fake.PushRequests())
	}
}

func TestGitPushMovedHeadAndDefaultBranchRefuseWithoutWrite(t *testing.T) {
	fake, env, effect := pushFixture(t)
	a, _ := env.adapter(nil)
	if _, err := a.Prepare(context.Background(), env.creds(), effect); err != nil {
		t.Fatal(err)
	}
	var args branchArgs
	args, _ = parseBranchArgsFor(EffectGitPush, effect.Arguments)
	moved := fake.AdvanceBranch(args.Head)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
	if fake.Head(args.Head) != moved || fake.PushRequests() != 0 {
		t.Fatal("stale push overwrote the provider head")
	}
	defaultEffect := pushEffect(t, env, "main", fake.Head("main"))
	// The base must differ from the head; the work branch is an existing base.
	var body map[string]any
	_ = json.Unmarshal(defaultEffect.Arguments, &body)
	body["base"] = args.Head
	defaultEffect.Arguments, _ = json.Marshal(body)
	if _, err := a.Prepare(context.Background(), env.creds(), defaultEffect); !refusedWith(err, contracts.ReasonPreconditionFailed) {
		t.Fatalf("default branch preparation: %v", err)
	}
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), defaultEffect, permit(defaultEffect)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
	if fake.PushRequests() != 0 {
		t.Fatal("default branch was written")
	}
}

func TestGitPushPermitMismatchAndLostAnswer(t *testing.T) {
	fake, env, effect := pushFixture(t)
	a, requests := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, nil), adapters.DispatchNotSent, contracts.ReasonPermitArgumentMismatch)
	if requests.all.Load() != 0 {
		t.Fatal("permit mismatch made a provider call")
	}
	lossy, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
		return dropAnswer{base: rt, method: http.MethodPost, suffix: "/graphql"}
	})
	wantDispatch(t, lossy.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchIndefinite, contracts.ReasonProviderError)
	wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	if fake.PushRequests() != 1 {
		t.Fatalf("lost answer caused %d ref writes", fake.PushRequests())
	}
}

type moveBeforeMutation struct {
	base   http.RoundTripper
	fake   *testkit.GitHub
	head   string
	rewind bool
}

func (m moveBeforeMutation) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && r.URL.Path == "/graphql" {
		if m.rewind {
			m.fake.RewindBranch(m.head)
		} else {
			m.fake.AdvanceBranch(m.head)
		}
	}
	return m.base.RoundTrip(r)
}

func TestGitPushConcurrentMoveCannotForceOverwrite(t *testing.T) {
	fake, env, effect := pushFixture(t)
	args, _ := parseBranchArgsFor(EffectGitPush, effect.Arguments)
	a, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
		return moveBeforeMutation{base: rt, fake: fake, head: args.Head}
	})
	got := a.Dispatch(context.Background(), env.creds(), effect, permit(effect))
	if got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonPreconditionFailed {
		t.Fatalf("concurrent ref move was not safely refused: %+v", got)
	}
	readback, _ := env.adapter(nil)
	wantObserve(t, readback.Observe(context.Background(), env.creds(), effect), adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
	if fake.PushRequests() != 1 || fake.Head(args.Head) == args.BaseSHA {
		t.Fatalf("concurrent update was not tested: writes=%d head=%s", fake.PushRequests(), fake.Head(args.Head))
	}
}

func TestGitPushConcurrentRewindRejectsExactHeadMismatch(t *testing.T) {
	fake, env, effect := pushFixture(t)
	args, _ := parseBranchArgsFor(EffectGitPush, effect.Arguments)
	a, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
		return moveBeforeMutation{base: rt, fake: fake, head: args.Head, rewind: true}
	})
	got := a.Dispatch(context.Background(), env.creds(), effect, permit(effect))
	if got.Status != adapters.DispatchNotSent || got.Reason != contracts.ReasonPreconditionFailed {
		t.Fatalf("concurrent rewind did not fail the beforeOid check: %+v", got)
	}
	if fake.PushRequests() != 1 || fake.Head(args.Head) != env.baseSHA {
		t.Fatalf("rewound branch was overwritten: writes=%d head=%s", fake.PushRequests(), fake.Head(args.Head))
	}
}

func TestGitPushClosedArgumentsRefuseBeforeCredentialOrProvider(t *testing.T) {
	fake, env, effect := pushFixture(t)
	cases := []string{
		strings.Replace(string(effect.Arguments), `"schema":"helm.github.git.push.v1"`, `"schema":"helm.github.branch.create_from_changes.v1"`, 1),
		strings.Replace(string(effect.Arguments), `"base_sha":`, `"repo":"other/repo","base_sha":`, 1),
		strings.Replace(string(effect.Arguments), `"head":"helm/push/work-1"`, `"head":"refs/heads/main"`, 1),
	}
	for _, raw := range cases {
		bad := effect
		bad.Arguments = []byte(raw)
		a, requests := env.adapter(nil)
		wantDispatch(t, a.Dispatch(context.Background(), env.creds(), bad, permit(bad)), adapters.DispatchNotSent, contracts.ReasonSchemaViolation)
		if requests.all.Load() != 0 {
			t.Fatal("invalid push arguments reached provider")
		}
	}
	if fake.PushRequests() != 0 {
		t.Fatal("invalid push reached ref update")
	}
}
