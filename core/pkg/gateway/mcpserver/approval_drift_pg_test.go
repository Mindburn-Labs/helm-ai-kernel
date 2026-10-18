package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	testkit "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	githubadapter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

type approvalDriftToken string

func (token approvalDriftToken) Token(context.Context) (string, error) { return string(token), nil }

// An approved GitHub write may use only the head and arguments that were
// reviewed. Provider drift fails before the write and releases its hold;
// changing the request requires a new attempt and its own human decision.
func TestPostgresApprovedPullWritesFailClosedOnHeadAndArgumentDrift(t *testing.T) {
	for _, tc := range []struct {
		name, effectType string
	}{
		{"draft", effectargs.GitHubPullRequestCreateDraft},
		{"merge", effectargs.GitHubPullRequestMerge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, fake := realGitHubEnv(t)
			head := "helm/approval-drift-" + tc.name
			s := setupGitHubWrite(t, e, fake, tc.effectType, head)
			usedBefore, heldBefore := counterTotals(t, e)
			first, failed := e.callTool(t, tokenSeat1Ep1, "drift-a1", s.tool, s.args).structured(t)
			if failed || first["status"] != "escalated" {
				t.Fatalf("the first request did not escalate: %v failed=%t", first, failed)
			}
			a1 := e.attempt(tenantA, first["attempt_id"].(string))
			if a1.Permit != nil || len(a1.ApprovalDigest) != 32 {
				t.Fatalf("unapproved write has a permit or no approval digest: %+v", a1)
			}

			approve := func(a admission.Attempt, key string) {
				t.Helper()
				input := admission.DecideInput{AttemptID: a.ID, ApprovalDigest: a.ApprovalDigest, Reason: "approved exact request"}
				if tc.effectType == effectargs.GitHubPullRequestMerge {
					input.StepUp = &admission.StepUp{Token: admission.Token{
						Issuer: "https://control-plane.test", ID: "stepup-" + key,
						Scope: "helm.gateway.stepup", ExpiresAt: time.Now().Add(time.Minute),
					}, Method: "webauthn", Raw: "verified-stepup-" + key}
				}
				got, existing, err := e.svc.Approve(context.Background(), admission.Caller{
					TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: cpActor,
				}, admission.Token{Issuer: "https://control-plane.test", ID: "decide-" + key,
					Scope: "helm.gateway.decide", ExpiresAt: time.Now().Add(time.Minute)}, input)
				must(t, err)
				if existing || got.State != "ADMITTED" || got.Permit == nil || !bytes.Equal(got.Permit.ArgumentDigest, a.ArgumentDigest) {
					t.Fatalf("approval did not bind the exact request: %+v existing=%t", got, existing)
				}
			}
			approve(a1, tc.name+"-a1")
			_, heldApproved := counterTotals(t, e)
			if heldApproved <= heldBefore {
				t.Fatalf("approval had no held exposure: before=%d after=%d", heldBefore, heldApproved)
			}

			if tc.effectType == effectargs.GitHubPullRequestMerge {
				fake.EditPull(fake.PullNumber(head), func(p *testkit.PullRequest) {
					p.HeadSHA = strings.Repeat("a", 40)
				})
			} else {
				fake.AdvanceBranch(head)
			}
			outcome, existing, err := e.svc.Dispatch(context.Background(), admission.Caller{
				TenantID: tenantA, WorkspaceID: workspace, PrincipalID: cpActor,
			}, a1.ID)
			must(t, err)
			if existing || outcome.State != "OBSERVED" || outcome.Outcome != "FAILED" ||
				outcome.ReasonCode != string(contracts.ReasonPreconditionFailed) || s.writeCount() != s.baseline {
				t.Fatalf("moved approved head sent a write or did not fail closed: %+v writes=%d baseline=%d", outcome, s.writeCount(), s.baseline)
			}
			if used, held := counterTotals(t, e); used != usedBefore || held != heldBefore {
				t.Fatalf("failed write did not release its hold: used=%d held=%d, want %d,%d", used, held, usedBefore, heldBefore)
			}

			rawChanged, err := json.Marshal(s.args)
			must(t, err)
			var changed map[string]any
			must(t, json.Unmarshal(rawChanged, &changed))
			args := changed["arguments"].(map[string]any)
			if tc.effectType == effectargs.GitHubPullRequestMerge {
				args["merge_method"] = "merge"
			} else {
				args["title"] = "Different reviewed title"
			}
			second, failed := e.callTool(t, tokenSeat1Ep1, "drift-a2", s.tool, changed).structured(t)
			if failed || second["status"] != "escalated" {
				t.Fatalf("changed request did not need its own approval: %v failed=%t", second, failed)
			}
			a2 := e.attempt(tenantA, second["attempt_id"].(string))
			if a2.ID == a1.ID || bytes.Equal(a2.ArgumentDigest, a1.ArgumentDigest) || bytes.Equal(a2.ApprovalDigest, a1.ApprovalDigest) {
				t.Fatal("changed arguments reused the approved attempt or either digest")
			}
			wrong := admission.DecideInput{AttemptID: a2.ID, ApprovalDigest: a1.ApprovalDigest, Reason: "stale decision"}
			_, _, err = e.svc.Approve(context.Background(), admission.Caller{
				TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: cpActor,
			}, admission.Token{Issuer: "https://control-plane.test", ID: "decide-stale-" + tc.name,
				Scope: "helm.gateway.decide", ExpiresAt: time.Now().Add(time.Minute)}, wrong)
			var refusal *admission.Error
			if !errors.As(err, &refusal) || refusal.Code != admission.CodeFailedPrecondition || e.attempt(tenantA, a2.ID).State != "ESCALATED" {
				t.Fatalf("stale approval changed the new attempt: refusal=%v attempt=%+v", err, e.attempt(tenantA, a2.ID))
			}

			effectArgs, err := json.Marshal(s.args["arguments"])
			must(t, err)
			adapter := githubadapter.New(githubadapter.WithBaseURL(fake.URL()))
			badPermit := adapter.Dispatch(context.Background(), approvalDriftToken(fake.Token()), adapters.Effect{
				EffectType: tc.effectType, Target: repoA, Arguments: effectArgs,
			}, []byte("not the argument digest"))
			if badPermit.Status != adapters.DispatchNotSent || badPermit.Reason != contracts.ReasonPermitArgumentMismatch || s.writeCount() != s.baseline {
				t.Fatalf("wrong permit reached provider or was not refused: %+v writes=%d", badPermit, s.writeCount())
			}
			approve(a2, tc.name+"-a2")
			if s.writeCount() != s.baseline {
				t.Fatal("a fresh approval sent the changed request before its Dispatch")
			}
		})

		t.Run(tc.name+"-unchanged-control", func(t *testing.T) {
			e, fake := realGitHubEnv(t)
			s := setupGitHubWrite(t, e, fake, tc.effectType, "helm/approval-control-"+tc.name)
			got := approveAndDispatch(t, e, s.tool, s.args, "drift-control")
			if got.State != "OBSERVED" || got.Outcome != "SUCCEEDED" || s.writeCount() != s.baseline+1 {
				t.Fatalf("unchanged approved request did not dispatch exactly once: %+v writes=%d", got, s.writeCount())
			}
		})
	}
}
