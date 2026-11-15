package admission

// T85: one approved merge and one provider write while two distinct humans
// approve and the workload dispatches the same attempt across several orders.
// The admission store is real PostgreSQL; the GitHub adapter uses its HTTP fake.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	githubfake "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	githubadapter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
)

type mergeRaceCredential string

func (c mergeRaceCredential) Token(context.Context, string, adapters.Effect) (string, error) {
	return string(c), nil
}

type mergeRaceToken string

func (c mergeRaceToken) Token(context.Context) (string, error) { return string(c), nil }

func mergeRaceArguments(t *testing.T, fake *githubfake.GitHub, adapter *githubadapter.Adapter, key string) []byte {
	t.Helper()
	ctx := context.Background()
	credentials := mergeRaceToken(fake.Token())
	encode := func(value any) []byte {
		t.Helper()
		body, err := json.Marshal(value)
		must(t, err)
		return body
	}
	apply := func(effect adapters.Effect) *adapters.GitHubPullRequestResult {
		t.Helper()
		digest := sha256.Sum256(effect.Arguments)
		result := adapter.Dispatch(ctx, credentials, effect, digest[:])
		if result.Status != adapters.DispatchSent {
			t.Fatalf("prepare %s: dispatch = %+v", effect.EffectType, result)
		}
		observed := adapter.Observe(ctx, credentials, effect)
		if observed.Outcome != adapters.OutcomeSucceeded || observed.Observation == nil {
			t.Fatalf("prepare %s: readback = %+v", effect.EffectType, observed)
		}
		return observed.Observation.GitHubPullRequest
	}
	head := "helm/g0-t85-" + key
	apply(adapters.Effect{EffectType: githubadapter.EffectBranchCreateFromChanges, Target: repo,
		Arguments: encode(map[string]any{
			"schema": "helm.github.branch.create_from_changes.v1", "base": "main", "base_sha": fake.BaseSHA(),
			"head": head, "message": "T85 merge approval race", "files": []map[string]string{{
				"path": "proof.txt", "mode": "100644", "content_utf8": key,
			}},
		})})
	pr := apply(adapters.Effect{EffectType: githubadapter.EffectPullRequestCreate, Target: repo,
		Arguments: encode(map[string]any{
			"schema": "helm.github.pull_request.create.v1", "branch_attempt_id": "0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d",
			"base": "main", "head": head, "head_sha": fake.Head(head), "title": "T85 merge approval race", "body": "",
		})})
	if pr == nil || pr.Draft || pr.HeadSHA != fake.Head(head) {
		t.Fatalf("ready pull request = %+v", pr)
	}
	return encode(map[string]any{
		"schema": "helm.github.pull_request.merge.v1", "pull_number": pr.Number,
		"head_sha": pr.HeadSHA, "base": "main", "merge_method": "squash",
	})
}

func TestPostgresMergeApprovalDispatchInterleavings(t *testing.T) {
	f := newFixture(t)
	requester := f.stepUpRequester() // human-c holds the merge mandate.
	fake := githubfake.NewFakeGitHubFor(t, "Mindburn-Labs", "example")
	fake.SetMergeMode("merged")
	adapter := githubadapter.New(githubadapter.WithBaseURL(fake.URL()))
	svc, err := New(f.runtime, Config{Adapters: []adapters.Adapter{adapter}, Credentials: mergeRaceCredential(fake.Token())})
	must(t, err)
	ctx := context.Background()

	for _, mode := range []string{"dispatch-before", "simultaneous", "approval-before", "single-approval-control"} {
		t.Run(mode, func(t *testing.T) {
			key := fmt.Sprintf("%s-%s", mode, decideToken("round").ID)
			arguments := mergeRaceArguments(t, fake, adapter, key)
			a := f.propose(requester, proposal(key, highType, repo, arguments))
			wantState(t, "merge requires approval", a, "ESCALATED", contracts.ReasonApprovalRequired)
			if a.Permit != nil {
				t.Fatal("escalated merge has a permit")
			}
			before := fake.MergeRequests()
			if mode == "dispatch-before" {
				_, _, err := svc.Dispatch(ctx, workload, a.ID)
				wantRefusal(t, "dispatch before approval", err, CodeFailedPrecondition, "")
				if fake.MergeRequests() != before {
					t.Fatal("pre-approval dispatch reached fake GitHub")
				}
			}

			approvers := []Caller{approverB, human} // Both differ from requester human-c.
			type decision struct {
				attempt  Attempt
				existing bool
				err      error
				proof    *StepUp
			}
			approvalCount := 2
			if mode == "single-approval-control" {
				approvalCount = 1
			}
			decisions := make([]decision, approvalCount)
			decide := func(start <-chan struct{}, done *sync.WaitGroup) {
				for i := range decisions {
					decisions[i].proof = stepUpProof()
					token := decideToken("helm.gateway.decide")
					done.Add(1)
					go func(i int) {
						defer done.Done()
						<-start
						decisions[i].attempt, decisions[i].existing, decisions[i].err = svc.Approve(
							ctx, approvers[i], token, withProof(approval(a, "approved exact merge"), decisions[i].proof))
					}(i)
				}
			}
			type dispatch struct {
				attempt  Attempt
				existing bool
				err      error
			}
			var calls []dispatch
			dispatchWave := func(start <-chan struct{}, done *sync.WaitGroup, n int) {
				for i := 0; i < n; i++ {
					calls = append(calls, dispatch{})
					index := len(calls) - 1
					done.Add(1)
					go func() {
						defer done.Done()
						<-start
						calls[index].attempt, calls[index].existing, calls[index].err = svc.Dispatch(ctx, workload, a.ID)
					}()
				}
			}
			var approveWG, dispatchWG sync.WaitGroup
			approvalsStart, dispatchStart := make(chan struct{}), make(chan struct{})
			decide(approvalsStart, &approveWG)
			if mode == "single-approval-control" {
				// A single approval followed by one dispatch is the control.
				close(approvalsStart)
				approveWG.Wait()
				dispatchWave(dispatchStart, &dispatchWG, 1)
				close(dispatchStart)
				dispatchWG.Wait()
			} else if mode == "approval-before" {
				close(approvalsStart)
				approveWG.Wait()
				dispatchWave(dispatchStart, &dispatchWG, 3)
				close(dispatchStart)
				dispatchWG.Wait()
			} else {
				// All five calls cross the same barrier. The early refusal
				// above makes dispatch-before distinct from this mixed wave.
				dispatchWave(approvalsStart, &dispatchWG, 3)
				close(approvalsStart)
				approveWG.Wait()
				dispatchWG.Wait()
			}

			freshApproval := -1
			for i, result := range decisions {
				must(t, result.err)
				if result.attempt.ID != a.ID || result.attempt.Permit == nil || result.attempt.Approval == nil {
					t.Fatalf("approval %d returned %+v", i, result.attempt)
				}
				if !result.existing {
					if freshApproval != -1 {
						t.Fatal("two approvals changed the merge")
					}
					freshApproval = i
				}
			}
			if freshApproval == -1 {
				t.Fatal("no approval admitted the merge")
			}
			if len(decisions) == 2 {
				winner, loser := decisions[freshApproval].attempt, decisions[1-freshApproval].attempt
				if loser.Permit.ID != winner.Permit.ID ||
					loser.Approval.ApproverPrincipalID != winner.Approval.ApproverPrincipalID {
					t.Fatal("existing approval changed the stored decision or permit")
				}
			}
			f.wantProofRecord(a.ID, decisions[freshApproval].proof)
			if len(decisions) == 2 {
				if n := f.count(tenantA, `SELECT count(*) FROM authority_token_replay WHERE jti = $1`, decisions[1-freshApproval].proof.Token.ID); n != 0 {
					t.Fatal("losing approval consumed its step-up proof")
				}
			}
			if n := f.count(tenantA, `SELECT count(*) FROM authority_approvals WHERE attempt_id = $1`, a.ID); n != 1 {
				t.Fatalf("%d approval rows", n)
			}
			if n := f.count(tenantA, `SELECT count(*) FROM authority_permits WHERE attempt_id = $1`, a.ID); n != 1 {
				t.Fatalf("%d permits", n)
			}
			freshDispatch := 0
			for _, call := range calls {
				if call.err != nil {
					wantRefusal(t, "dispatch before admission", call.err, CodeFailedPrecondition, "")
					continue
				}
				if call.attempt.ID != a.ID {
					t.Fatalf("dispatch returned attempt %s, want %s", call.attempt.ID, a.ID)
				}
				if !call.existing {
					freshDispatch++
				}
			}
			if freshDispatch == 0 {
				// The simultaneous wave can reach ESCALATED before either
				// approval. Retry a concurrent wave after admission.
				calls = nil
				start := make(chan struct{})
				dispatchWave(start, &dispatchWG, 3)
				close(start)
				dispatchWG.Wait()
				for _, call := range calls {
					must(t, call.err)
					if !call.existing {
						freshDispatch++
					}
				}
			}
			if freshDispatch != 1 {
				t.Fatalf("%d dispatches claimed a permit, want 1", freshDispatch)
			}
			got, err := svc.Get(ctx, requester, a.ID)
			must(t, err)
			wantOutcome(t, "merged and read back", got, "OBSERVED", "SUCCEEDED", "")
			if got.Permit == nil || got.Permit.ConsumedAt == nil || got.Approval == nil ||
				got.Approval.ApproverPrincipalID != approvers[freshApproval].PrincipalID {
				t.Fatalf("settled merge lost its approval or consumed permit: %+v", got)
			}
			if got.LatestObservation == nil || got.LatestObservation.GitHubPullRequest == nil ||
				!got.LatestObservation.GitHubPullRequest.Merged {
				t.Fatalf("merge lacks actual fake-GitHub readback: %+v", got.LatestObservation)
			}
			if merges := fake.MergeRequests() - before; merges != 1 {
				t.Fatalf("%d fake-GitHub merge calls for %s, want 1", merges, mode)
			}
			t.Logf("%s: one approval, one permit, one claim, one fake-GitHub merge", mode)
		})
	}
}
