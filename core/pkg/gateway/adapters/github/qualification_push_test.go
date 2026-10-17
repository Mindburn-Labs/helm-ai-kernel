package github

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

func init() {
	QualificationSuite.SuiteVersion = "3"
	for _, c := range []struct {
		id, category, description string
		run                       qualCase
	}{
		{"happy-path", "baseline", "Push one fast-forward commit to an existing feature branch and read back its exact parent and files.", qualifyPushHappy},
		{"duplicate-submission", "duplicate submission", "A replay after the pushed commit is visible sends no second ref update.", qualifyPushDuplicate},
		{"lost-response", "lost response after success", "An applied ref update with a lost reply is reconciled by an independent read, not resent.", qualifyPushLost},
		{"revoked-credential", "revoked credential", "A revoked token cannot update the ref or establish successful readback.", qualifyPushRevoked},
		{"head-moved", "precondition failure", "A different commit at the approved head is refused before a ref write.", qualifyPushMoved},
		{"readback-mismatch", "read-back mismatch", "A commit with different proposed content is not mistaken for the approved push.", qualifyPushMismatch},
		{"oversized-response", "response exceeding the size limit", "An oversized preflight response refuses before a ref write.", qualifyPushOversized},
		{"permit-mismatch", "boundary", "A mismatched permit digest causes no provider I/O.", qualifyPushPermit},
	} {
		id := "git_push/" + c.id
		QualificationSuite.Cases = append(QualificationSuite.Cases, qcase(id, EffectGitPush, c.category, c.description))
		qualCases[id] = c.run
	}
}

func pushQualificationEffect(t *testing.T, env *qualEnv, label string) adapters.Effect {
	t.Helper()
	head := env.head("push-" + label)
	_, branch := env.createBranch(t, head, skeletonFiles...)
	return pushEffect(t, env, head, branch.CommitSHA)
}

func qualifyPushHappy(t *testing.T, env *qualEnv) {
	effect := pushQualificationEffect(t, env, "happy")
	a, _ := env.adapter(nil)
	if prep, err := a.Prepare(context.Background(), env.creds(), effect); err != nil || prep == nil || prep.Declaration.EffectType != EffectGitPush {
		t.Fatalf("push preparation: %+v %v", prep, err)
	}
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	got := a.Observe(context.Background(), env.creds(), effect)
	wantObserve(t, got, adapters.OutcomeSucceeded, "")
	args, _ := parseBranchArgsFor(EffectGitPush, effect.Arguments)
	if got.Observation.GitHubBranch.BaseSHA != args.BaseSHA || got.Observation.GitHubBranch.CommitSHA == args.BaseSHA {
		t.Fatalf("push did not advance from the approved parent: %+v", got.Observation.GitHubBranch)
	}
}

func qualifyPushDuplicate(t *testing.T, env *qualEnv) {
	effect := pushQualificationEffect(t, env, "duplicate")
	a, _ := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
	a, sent := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	if sent.nonRead.Load() != 0 {
		t.Fatal("replayed push sent another provider write")
	}
}

func qualifyPushLost(t *testing.T, env *qualEnv) {
	effect := pushQualificationEffect(t, env, "lost")
	lossy, _ := env.adapter(func(rt http.RoundTripper) http.RoundTripper {
		return dropAnswer{base: rt, method: http.MethodPost, suffix: "/graphql"}
	})
	wantDispatch(t, lossy.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchIndefinite, contracts.ReasonProviderError)
	a, _ := env.adapter(nil)
	wantObserve(t, a.Observe(context.Background(), env.creds(), effect), adapters.OutcomeSucceeded, "")
}

func qualifyPushRevoked(t *testing.T, env *qualEnv) {
	effect := pushQualificationEffect(t, env, "revoked")
	a, sent := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), staticToken("revoked"), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderCredentialRejected)
	wantObserve(t, a.Observe(context.Background(), staticToken("revoked"), effect), adapters.OutcomeUnknown, contracts.ReasonProviderCredentialRejected)
	if sent.nonRead.Load() != 0 {
		t.Fatal("revoked credential reached a ref write")
	}
}

func qualifyPushMoved(t *testing.T, env *qualEnv) {
	effect := pushQualificationEffect(t, env, "moved")
	a, _ := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	other := effect
	other.Arguments = []byte(strings.Replace(string(effect.Arguments), "bounded", "other writer", 1))
	a, sent := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), other, permit(other)), adapters.DispatchNotSent, contracts.ReasonPreconditionFailed)
	if sent.nonRead.Load() != 0 {
		t.Fatal("moved approved head reached a ref write")
	}
}

func qualifyPushMismatch(t *testing.T, env *qualEnv) {
	effect := pushQualificationEffect(t, env, "mismatch")
	a, _ := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchSent, "")
	other := effect
	other.Arguments = []byte(strings.Replace(string(effect.Arguments), "bounded", "other writer", 1))
	wantObserve(t, a.Observe(context.Background(), env.creds(), other), adapters.OutcomeFailed, contracts.ReasonReadbackMismatch)
}

func qualifyPushOversized(t *testing.T, env *qualEnv) {
	effect := pushQualificationEffect(t, env, "oversized")
	a, sent := env.adapter(nil, WithMaxResponseBytes(1))
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, permit(effect)), adapters.DispatchNotSent, contracts.ReasonProviderResponseTooLarge)
	if sent.nonRead.Load() != 0 {
		t.Fatal("oversized preflight answer reached a ref write")
	}
}

func qualifyPushPermit(t *testing.T, env *qualEnv) {
	effect := pushQualificationEffect(t, env, "permit")
	a, sent := env.adapter(nil)
	wantDispatch(t, a.Dispatch(context.Background(), env.creds(), effect, nil), adapters.DispatchNotSent, contracts.ReasonPermitArgumentMismatch)
	if sent.all.Load() != 0 {
		t.Fatal("bad permit reached provider I/O")
	}
}
