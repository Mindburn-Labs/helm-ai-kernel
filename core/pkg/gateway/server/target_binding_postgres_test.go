package server

// Approval binding on the real Connect/JWKS/PostgreSQL path. The provider is
// shared repository-scoped HTTP GitHub double through the actual adapter and
// App custody. This makes no live provider or organization-acceptance claim.
// quantum_posture: classical SHA-256 approval bindings; no post-quantum claim.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func TestPostgresApprovalBindsRepositoryAndBranchBase(t *testing.T) {
	github := newBindingGitHub(t)
	client, iss, db := newWire(t, admission.Config{Adapters: []adapters.Adapter{github}, Credentials: github.credentials(t)})
	ctx := context.Background()
	rows, err := authorityrows.New(db)
	must(t, err)
	// newWire's baseline permits this branch without approval. Replace that
	// fixture grant through the canonical revoke path before adding the
	// approval-required grant; a second grant cannot narrow the first one.
	var baseline uuid.UUID
	must(t, db.QueryRow(`SELECT mandate_id FROM authority_mandates WHERE tenant_id = 'tenant-a' AND holder_id = 'human-a' AND status = 'active'`).Scan(&baseline))
	must(t, rows.Revoke(ctx, "tenant-a", baseline))
	now := time.Now()
	_, err = rows.CreateMandate(ctx, "tenant-a", "human-a", authorityrows.Terms{
		EffectTypes:      []string{effectargs.GitHubBranchCreateFromChanges},
		Targets:          []string{testRepo},
		Condition:        `input.args.head.startsWith("helm/")`,
		ApprovalRequired: []string{effectargs.GitHubBranchCreateFromChanges},
		ValidFrom:        now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"})
	must(t, err)

	proposer := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	bindingLimits(t, db, rows)
	reader := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead)
	executor := iss.token(t, testAudience, "tenant-a", testActor, ScopeExecute, func(c *tokenClaims) { c.Act = nil })
	propose := func(req *gatewayv1.ProposeRequest) *gatewayv1.EffectAttempt {
		t.Helper()
		response, err := client.Propose(ctx, withToken(req, proposer))
		must(t, err)
		if response.Msg.GetExisting() {
			t.Fatal("a fresh request replayed another attempt")
		}
		return response.Msg.GetAttempt()
	}
	approve := func(id string, digest []byte) (*connect.Response[gatewayv1.ApproveResponse], error) {
		t.Helper()
		token := iss.token(t, testAudience, "tenant-a", "human-b", ScopeDecide, decision(id, "approve"))
		return client.Approve(ctx, withToken(&gatewayv1.ApproveRequest{AttemptId: id, ApprovalDigest: digest, Reason: "reviewed these exact bytes"}, token))
	}

	firstRequest := github.branchRequest(t, "binding-first", "helm/binding", testRepo, "main")
	first := propose(firstRequest)
	wantAttempt(t, "the requested repository", first, "ESCALATED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonApprovalRequired)
	firstApproval := append([]byte(nil), first.GetPendingApproval().GetApprovalDigest()...)
	approved, err := approve(first.GetAttemptId(), firstApproval)
	must(t, err)
	wantAttempt(t, "a distinct human's approval", approved.Msg.GetAttempt(), "ADMITTED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, "")

	// Keep every argument byte, including the branch and commit message, but
	// name another owner's repository with the same short name.
	forkRequest := github.branchRequest(t, "binding-fork", "helm/binding", testRepo, "main")
	forkRequest.Effect.Target = "github.com/Another-Owner/example"
	if !bytes.Equal(forkRequest.Effect.Arguments, firstRequest.Effect.Arguments) {
		t.Fatal("the retarget control changed more than its repository")
	}
	fork := propose(forkRequest)
	wantAttempt(t, "another owner's same-named repository", fork, "DENIED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonEffectOutOfScope)
	if fork.GetAttemptId() == first.GetAttemptId() || bytes.Equal(fork.GetTargetDigest(), first.GetTargetDigest()) ||
		!bytes.Equal(fork.GetArgumentDigest(), first.GetArgumentDigest()) {
		t.Fatal("repository retargeting did not retain a distinct target-bound attempt")
	}
	_, err = client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: fork.GetAttemptId()}, executor))
	wantRPCError(t, "dispatching the denied fork", err, connect.CodeFailedPrecondition, "")

	// The repository target remains the same; the changed base belongs to
	// the raw argument digest. ApprovalDigestV1 binds both digests. Do not
	// silently migrate the signed target-digest protocol to hash arguments.
	baseRequest := github.branchRequest(t, "binding-base", "helm/binding", testRepo, "main")
	baseRequest.Effect.Arguments = []byte(strings.Replace(string(baseRequest.Effect.Arguments), `"base":"main"`, `"base":"release"`, 1))
	base := propose(baseRequest)
	wantAttempt(t, "a different base branch", base, "ESCALATED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonApprovalRequired)
	targetDigest := sha256.Sum256([]byte(testRepo))
	baseArgumentDigest := sha256.Sum256(baseRequest.Effect.Arguments)
	firstArgumentDigest := sha256.Sum256(firstRequest.Effect.Arguments)
	baseExpiry := base.GetPendingApproval().GetExpiresAt().AsTime()
	expectedApproval := admission.ApprovalDigestV1(base.GetAttemptId(), targetDigest[:], baseArgumentDigest[:], bindingQuote(), baseExpiry)
	if base.GetAttemptId() == first.GetAttemptId() || bytes.Equal(base.GetArgumentDigest(), first.GetArgumentDigest()) ||
		bytes.Equal(base.GetPendingApproval().GetApprovalDigest(), firstApproval) ||
		!bytes.Equal(base.GetTargetDigest(), targetDigest[:]) || !bytes.Equal(first.GetTargetDigest(), targetDigest[:]) ||
		!bytes.Equal(base.GetArgumentDigest(), baseArgumentDigest[:]) ||
		!bytes.Equal(base.GetPendingApproval().GetApprovalDigest(), expectedApproval) {
		t.Fatal("a changed base did not have its own argument and approval binding")
	}
	_, err = approve(base.GetAttemptId(), firstApproval)
	wantRPCError(t, "reusing the first approval digest for another base", err, connect.CodeFailedPrecondition, "")
	// Hold attempt ID, target, quote and expiry constant. Only the raw base
	// argument digest changes, so this control cannot pass merely because
	// ApprovalDigestV1 also includes a distinct attempt ID.
	wrongBaseApproval := admission.ApprovalDigestV1(base.GetAttemptId(), targetDigest[:], firstArgumentDigest[:], bindingQuote(), baseExpiry)
	_, err = approve(base.GetAttemptId(), wrongBaseApproval)
	wantRPCError(t, "the same attempt with another base's argument digest", err, connect.CodeFailedPrecondition, "")
	retained, err := client.GetAttempt(ctx, withToken(&gatewayv1.GetAttemptRequest{AttemptId: base.GetAttemptId()}, reader))
	must(t, err)
	wantAttempt(t, "the refused digest leaves the base request pending", retained.Msg.GetAttempt(), "ESCALATED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonApprovalRequired)
	if retained.Msg.GetAttempt().GetVersion() != base.GetVersion() {
		t.Fatal("a refused digest advanced the attempt")
	}
	var approvals int
	must(t, db.QueryRow(`SELECT count(*) FROM authority_approvals WHERE tenant_id = 'tenant-a' AND attempt_id = $1`, base.GetAttemptId()).Scan(&approvals))
	if approvals != 0 {
		t.Fatal("a refused digest wrote an approval")
	}
	_, err = client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: base.GetAttemptId()}, executor))
	wantRPCError(t, "dispatching the changed base without its own approval", err, connect.CodeFailedPrecondition, "")
	if github.dispatchCalls.Load() != 0 || github.observeCalls.Load() != 0 || github.credentialCalls.Load() != 0 || github.branchWrites("helm/binding") != 0 {
		t.Fatal("a retargeted or unapproved request reached the provider adapter")
	}

	// Positive control: the originally approved request still dispatches,
	// reads back successfully and is not dispatched a second time on retry.
	dispatched, err := client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: first.GetAttemptId()}, executor))
	must(t, err)
	wantAttempt(t, "the originally approved request dispatches", dispatched.Msg.GetAttempt(), "OBSERVED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED, "")
	if dispatched.Msg.GetExisting() || github.dispatchCalls.Load() != 1 || github.observeCalls.Load() != 1 || github.credentialCalls.Load() != 2 || github.branchWrites("helm/binding") != 1 {
		t.Fatalf("the original request did not dispatch exactly once: existing=%v dispatches=%d observations=%d credentials=%d writes=%d", dispatched.Msg.GetExisting(), github.dispatchCalls.Load(), github.observeCalls.Load(), github.credentialCalls.Load(), github.branchWrites("helm/binding"))
	}
	again, err := client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: first.GetAttemptId()}, executor))
	must(t, err)
	if !again.Msg.GetExisting() || github.dispatchCalls.Load() != 1 || github.observeCalls.Load() != 1 || github.credentialCalls.Load() != 2 || github.branchWrites("helm/binding") != 1 {
		t.Fatal("a retry dispatched the original request again")
	}
	baseApproved, err := approve(base.GetAttemptId(), base.GetPendingApproval().GetApprovalDigest())
	must(t, err)
	wantAttempt(t, "the changed base can receive its own approval", baseApproved.Msg.GetAttempt(), "ADMITTED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, "")
	if github.dispatchCalls.Load() != 1 || github.observeCalls.Load() != 1 || github.credentialCalls.Load() != 2 {
		t.Fatal("approving the changed base dispatched it")
	}
}

func TestPostgresDraftApprovalBindsReviewedDestination(t *testing.T) {
	const forkRepo = "github.com/Another-Owner/example"
	for _, variant := range []string{"base", "fork"} {
		t.Run(variant, func(t *testing.T) {
			github := newBindingGitHub(t)
			installations, err := json.Marshal(map[string]any{"installations": []map[string]any{
				{"tenant_id": "tenant-a", "owner": "Mindburn-Labs", "installation_id": 7, "repositories": []string{"Mindburn-Labs/example"}},
				{"tenant_id": "tenant-a", "owner": "Another-Owner", "installation_id": 8, "repositories": []string{"Another-Owner/example"}},
			}})
			must(t, err)
			client, iss, db := newWire(t, admission.Config{Adapters: []adapters.Adapter{github}, Credentials: github.credentials(t, installations)})
			ctx := context.Background()
			rows, err := authorityrows.New(db)
			must(t, err)
			must(t, rows.CreateEffectType(ctx, "tenant-a", effectargs.GitHubPullRequestCreateDraft, authorityrows.RiskMedium))
			now := time.Now()
			_, err = rows.CreateMandate(ctx, "tenant-a", "human-a", authorityrows.Terms{
				EffectTypes:      []string{effectargs.GitHubPullRequestCreateDraft},
				Targets:          []string{testRepo},
				ApprovalRequired: []string{effectargs.GitHubPullRequestCreateDraft},
				ValidFrom:        now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
			}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"})
			must(t, err)

			if variant == "fork" {
				// The setup may create a matching branch in the fork, but
				// this grant cannot authorize a draft pull request there.
				_, err = rows.CreateMandate(ctx, "tenant-a", "human-a", authorityrows.Terms{
					EffectTypes: []string{effectargs.GitHubBranchCreateFromChanges},
					Targets:     []string{forkRepo},
					ValidFrom:   now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
				}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"})
				must(t, err)
			}
			bindingLimits(t, db, rows)
			proposer := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
			executor := iss.token(t, testAudience, "tenant-a", testActor, ScopeExecute, func(c *tokenClaims) { c.Act = nil })
			propose := func(req *gatewayv1.ProposeRequest) *gatewayv1.EffectAttempt {
				t.Helper()
				resp, err := client.Propose(ctx, withToken(req, proposer))
				must(t, err)
				if resp.Msg.GetExisting() {
					t.Fatal("a fresh destination replayed an earlier attempt")
				}
				return resp.Msg.GetAttempt()
			}
			approve := func(id string, digest []byte) (*connect.Response[gatewayv1.ApproveResponse], error) {
				t.Helper()
				token := iss.token(t, testAudience, "tenant-a", "human-b", ScopeDecide, decision(id, "approve"))
				return client.Approve(ctx, withToken(&gatewayv1.ApproveRequest{
					AttemptId: id, ApprovalDigest: digest, Reason: "reviewed the exact destination",
				}, token))
			}
			counts := func() (attempts, contents int) {
				t.Helper()
				must(t, db.QueryRow("SELECT count(*) FROM authority_effect_attempts WHERE tenant_id='tenant-a'").Scan(&attempts))
				must(t, db.QueryRow("SELECT count(*) FROM authority_attempt_contents WHERE tenant_id='tenant-a'").Scan(&contents))
				return
			}
			makeBranch := func(key, target, base string) *gatewayv1.EffectAttempt {
				t.Helper()
				req := github.branchRequest(t, key, "helm/reviewed-destination", target, base)
				req.Effect.Target = target
				var args map[string]any
				must(t, json.Unmarshal(req.Effect.Arguments, &args))
				args["base"] = base
				req.Effect.Arguments, err = json.Marshal(args)
				must(t, err)
				branch := propose(req)
				wantAttempt(t, "prerequisite branch", branch, "ADMITTED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, "")
				dispatched, err := client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: branch.GetAttemptId()}, executor))
				must(t, err)
				wantAttempt(t, "observed prerequisite branch", dispatched.Msg.GetAttempt(), "OBSERVED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED, "")
				return dispatched.Msg.GetAttempt()
			}
			makeDraft := func(key, target, base string, branch *gatewayv1.EffectAttempt) *gatewayv1.ProposeRequest {
				t.Helper()
				args, err := json.Marshal(map[string]string{
					"schema":            "helm.github.pull_request.create_draft.v1",
					"branch_attempt_id": branch.GetAttemptId(),
					"base":              base, "head": "helm/reviewed-destination",
					"head_sha": branch.GetLatestObservation().GetGithubBranch().GetCommitSha(),
					"title":    "Review the same named change", "body": "",
				})
				must(t, err)
				req := skeletonRequest(key, effectargs.GitHubPullRequestCreateDraft, string(args))
				req.Quote = []*gatewayv1.ResourceAmount{{Unit: "count", Amount: 1}}
				req.Effect.Target = target
				return req
			}

			firstBranch := makeBranch("draft-binding-source-a", testRepo, "main")
			dispatches, observations, credentials := github.dispatchCalls.Load(), github.observeCalls.Load(), github.credentialCalls.Load()
			firstRequest := makeDraft("draft-binding-a", testRepo, "main", firstBranch)
			first := propose(firstRequest)
			wantAttempt(t, "original draft", first, "ESCALATED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonApprovalRequired)
			firstApproval := append([]byte(nil), first.GetPendingApproval().GetApprovalDigest()...)
			targetHash := sha256.Sum256([]byte(testRepo))
			forkHash := sha256.Sum256([]byte(forkRepo))
			firstArgsHash := sha256.Sum256(firstRequest.Effect.Arguments)
			firstExpiry := first.GetPendingApproval().GetExpiresAt().AsTime()
			wrongTarget := admission.ApprovalDigestV1(first.GetAttemptId(), forkHash[:], firstArgsHash[:], bindingQuote(), firstExpiry)
			_, err = approve(first.GetAttemptId(), wrongTarget)
			wantRPCError(t, "same draft attempt with another repository digest", err, connect.CodeFailedPrecondition, "")
			reader := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead)
			pending, err := client.GetAttempt(ctx, withToken(&gatewayv1.GetAttemptRequest{AttemptId: first.GetAttemptId()}, reader))
			must(t, err)
			wantAttempt(t, "wrong target digest leaves the original pending", pending.Msg.GetAttempt(), "ESCALATED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonApprovalRequired)
			var firstApprovals int
			must(t, db.QueryRow("SELECT count(*) FROM authority_approvals WHERE tenant_id='tenant-a' AND attempt_id=$1", first.GetAttemptId()).Scan(&firstApprovals))
			if firstApprovals != 0 || pending.Msg.GetAttempt().GetVersion() != first.GetVersion() || pending.Msg.GetAttempt().GetPermit() != nil {
				t.Fatal("a refused target digest persisted approval or advanced the attempt")
			}
			approved, err := approve(first.GetAttemptId(), firstApproval)
			must(t, err)
			wantAttempt(t, "reviewed original draft", approved.Msg.GetAttempt(), "ADMITTED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, "")
			if github.dispatchCalls.Load() != dispatches || github.observeCalls.Load() != observations || github.credentialCalls.Load() != credentials || github.pullWrites("helm/reviewed-destination") != 0 {
				t.Fatal("proposing or approving the original draft reached the provider")
			}

			target, base := testRepo, "release"
			if variant == "fork" {
				target, base = forkRepo, "main"
			}
			// A copied source reference is not a valid destination change.
			// It must fail before any effect-attempt/content row is stored.
			beforeAttempts, beforeContents := counts()
			_, err = client.Propose(ctx, withToken(makeDraft("draft-binding-bad-source", target, base, firstBranch), proposer))
			wantRPCError(t, "a source branch from another destination", err, connect.CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
			if a, c := counts(); a != beforeAttempts || c != beforeContents {
				t.Fatal("a refused branch-reference substitution persisted an attempt or content")
			}
			if github.dispatchCalls.Load() != dispatches || github.observeCalls.Load() != observations || github.credentialCalls.Load() != credentials {
				t.Fatal("a refused branch-reference substitution reached the provider")
			}
			secondBranch := makeBranch("draft-binding-source-b", target, base)
			// The destination's legitimate branch setup is now finished.
			// Nothing after this baseline may use the provider for a draft
			// until that draft has its own approval.
			dispatches, observations, credentials = github.dispatchCalls.Load(), github.observeCalls.Load(), github.credentialCalls.Load()
			secondRequest := makeDraft("draft-binding-b", target, base, secondBranch)
			second := propose(secondRequest)
			var firstArgs, secondArgs map[string]string
			must(t, json.Unmarshal(firstRequest.Effect.Arguments, &firstArgs))
			must(t, json.Unmarshal(secondRequest.Effect.Arguments, &secondArgs))
			if firstArgs["title"] != secondArgs["title"] || firstArgs["head"] != secondArgs["head"] ||
				firstArgs["branch_attempt_id"] == secondArgs["branch_attempt_id"] ||
				first.GetAttemptId() == second.GetAttemptId() {
				t.Fatal("the named destination controls did not keep title/head and use their own prerequisites")
			}
			if github.pullWrites("helm/reviewed-destination") != 0 {
				t.Fatal("a draft reached the provider during prerequisite setup")
			}
			if variant == "fork" {
				wantAttempt(t, "valid draft outside the mandate", second, "DENIED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonEffectOutOfScope)
				if bytes.Equal(first.GetTargetDigest(), second.GetTargetDigest()) {
					t.Fatal("the fork did not have a different repository digest")
				}
				retained, err := approve(second.GetAttemptId(), firstApproval)
				must(t, err)
				if !retained.Msg.GetExisting() || retained.Msg.GetAttempt().GetVersion() != second.GetVersion() {
					t.Fatal("deciding a terminal denied fork changed it")
				}
				wantAttempt(t, "old approval cannot admit a denied fork", retained.Msg.GetAttempt(), "DENIED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonEffectOutOfScope)
			} else {
				wantAttempt(t, "valid draft with a different base", second, "ESCALATED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonApprovalRequired)
				argumentHash := sha256.Sum256(secondRequest.Effect.Arguments)
				expiry := second.GetPendingApproval().GetExpiresAt().AsTime()
				expected := admission.ApprovalDigestV1(second.GetAttemptId(), targetHash[:], argumentHash[:], bindingQuote(), expiry)
				if !bytes.Equal(second.GetTargetDigest(), targetHash[:]) || bytes.Equal(first.GetArgumentDigest(), second.GetArgumentDigest()) ||
					!bytes.Equal(second.GetPendingApproval().GetApprovalDigest(), expected) {
					t.Fatal("the changed base was not independently bound to its raw arguments")
				}
				secondArgs["base"] = "main"
				wrongBaseBytes, err := json.Marshal(secondArgs)
				must(t, err)
				wrongBaseHash := sha256.Sum256(wrongBaseBytes)
				for _, digest := range [][]byte{
					firstApproval,
					admission.ApprovalDigestV1(second.GetAttemptId(), targetHash[:], wrongBaseHash[:], bindingQuote(), expiry),
					admission.ApprovalDigestV1(second.GetAttemptId(), forkHash[:], argumentHash[:], bindingQuote(), expiry),
				} {
					_, err = approve(second.GetAttemptId(), digest)
					wantRPCError(t, "an approval for other reviewed bytes", err, connect.CodeFailedPrecondition, "")
				}
			}
			beforeAttempts, beforeContents = counts()
			conflict := makeDraft(firstRequest.GetIdempotencyKey(), target, base, secondBranch)
			_, err = client.Propose(ctx, withToken(conflict, proposer))
			wantRPCError(t, "changed destination with the original idempotency key", err, connect.CodeAlreadyExists, contracts.ReasonIdempotencyConflict)
			if a, c := counts(); a != beforeAttempts || c != beforeContents {
				t.Fatal("an idempotency conflict persisted another attempt or content")
			}
			_, err = client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: second.GetAttemptId()}, executor))
			wantRPCError(t, "dispatch without this destination's approval", err, connect.CodeFailedPrecondition, "")
			observed, err := client.Observe(ctx, withToken(&gatewayv1.ObserveRequest{AttemptId: second.GetAttemptId()}, executor))
			must(t, err)
			if !observed.Msg.GetExisting() || observed.Msg.GetAttempt().GetVersion() != second.GetVersion() ||
				observed.Msg.GetAttempt().GetPermit() != nil || observed.Msg.GetAttempt().GetState() != second.GetState() ||
				observed.Msg.GetAttempt().GetReasonCode() != second.GetReasonCode() {
				t.Fatal("an unapproved or denied draft advanced on Observe")
			}
			var approvals int
			must(t, db.QueryRow("SELECT count(*) FROM authority_approvals WHERE tenant_id='tenant-a' AND attempt_id=$1", second.GetAttemptId()).Scan(&approvals))
			if approvals != 0 || github.dispatchCalls.Load() != dispatches || github.observeCalls.Load() != observations ||
				github.credentialCalls.Load() != credentials || github.pullWrites("helm/reviewed-destination") != 0 {
				t.Fatal("a changed destination used approval, provider dispatch, observation or credentials")
			}

			// Count from the prerequisite baseline: exactly one draft effect,
			// with no extra dispatch/readback on the original's retry.
			for call := 0; call < 2; call++ {
				result, err := client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: first.GetAttemptId()}, executor))
				must(t, err)
				wantAttempt(t, "original draft positive control", result.Msg.GetAttempt(), "OBSERVED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED, "")
				if result.Msg.GetExisting() != (call == 1) || github.dispatchCalls.Load() != dispatches+1 ||
					github.observeCalls.Load() != observations+1 || github.credentialCalls.Load() != credentials+2 || github.pullWrites("helm/reviewed-destination") != 1 {
					t.Fatal("the original reviewed draft did not execute exactly once")
				}
			}
			if variant == "base" {
				result, err := approve(second.GetAttemptId(), second.GetPendingApproval().GetApprovalDigest())
				must(t, err)
				wantAttempt(t, "the new base can receive its own approval", result.Msg.GetAttempt(), "ADMITTED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, "")
				if github.dispatchCalls.Load() != dispatches+1 || github.observeCalls.Load() != observations+1 {
					t.Fatal("approving the new base executed it")
				}
			}
		})
	}
}

func TestPostgresDraftPrerequisiteRejectsActualParentAndContentMismatch(t *testing.T) {
	for _, mismatch := range []string{"parent", "content"} {
		t.Run(mismatch, func(t *testing.T) {
			github := newBindingGitHub(t)
			const head = "helm/prerequisite-mismatch"
			github.afterDispatch = func(effect adapters.Effect) {
				if effect.EffectType != effectargs.GitHubBranchCreateFromChanges {
					return
				}
				if mismatch == "parent" {
					github.providers[testRepo].AdvanceBranch(head)
				} else {
					github.providers[testRepo].RewriteBranchFile(head, "docs/skeleton.md", "# Unreviewed content\n")
				}
			}
			client, iss, db := newWire(t, admission.Config{Adapters: []adapters.Adapter{github}, Credentials: github.credentials(t)})
			ctx := context.Background()
			rows, err := authorityrows.New(db)
			must(t, err)
			must(t, rows.CreateEffectType(ctx, "tenant-a", effectargs.GitHubPullRequestCreateDraft, authorityrows.RiskMedium))
			now := time.Now()
			_, err = rows.CreateMandate(ctx, "tenant-a", "human-a", authorityrows.Terms{
				EffectTypes: []string{effectargs.GitHubPullRequestCreateDraft}, Targets: []string{testRepo},
				ApprovalRequired: []string{effectargs.GitHubPullRequestCreateDraft},
				ValidFrom:        now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
			}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"})
			must(t, err)
			bindingLimits(t, db, rows)
			proposer := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
			executor := iss.token(t, testAudience, "tenant-a", testActor, ScopeExecute, func(c *tokenClaims) { c.Act = nil })
			proposed, err := client.Propose(ctx, withToken(github.branchRequest(t, "bad-prerequisite", head, testRepo, "main"), proposer))
			must(t, err)
			branch, err := client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: proposed.Msg.GetAttempt().GetAttemptId()}, executor))
			must(t, err)
			wantAttempt(t, "actual provider readback rejects the changed prerequisite", branch.Msg.GetAttempt(), "OBSERVED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_FAILED, contracts.ReasonReadbackMismatch)
			if github.providers[testRepo].AppliedRef("heads/"+head) != 1 || github.providers[testRepo].RefReads(head) == 0 {
				t.Fatal("the prerequisite did not execute and read the real HTTP GitHub state")
			}
			dispatches, observations, credentials := github.dispatchCalls.Load(), github.observeCalls.Load(), github.credentialCalls.Load()
			var before int
			must(t, db.QueryRow("SELECT count(*) FROM authority_effect_attempts WHERE tenant_id='tenant-a'").Scan(&before))
			args, err := json.Marshal(map[string]string{
				"schema": "helm.github.pull_request.create_draft.v1", "branch_attempt_id": branch.Msg.GetAttempt().GetAttemptId(),
				"base": "main", "head": head, "head_sha": github.providers[testRepo].Head(head), "title": "Changed prerequisite", "body": "",
			})
			must(t, err)
			draft := skeletonRequest("draft-after-bad-prerequisite", effectargs.GitHubPullRequestCreateDraft, string(args))
			draft.Quote = []*gatewayv1.ResourceAmount{{Unit: "count", Amount: 1}}
			_, err = client.Propose(ctx, withToken(draft, proposer))
			wantRPCError(t, "a failed prerequisite cannot become an approvable draft", err, connect.CodeFailedPrecondition, contracts.ReasonPreconditionFailed)
			var after int
			must(t, db.QueryRow("SELECT count(*) FROM authority_effect_attempts WHERE tenant_id='tenant-a'").Scan(&after))
			if before != after || github.dispatchCalls.Load() != dispatches || github.observeCalls.Load() != observations ||
				github.credentialCalls.Load() != credentials || github.pullWrites(head) != 0 {
				t.Fatal("the failed prerequisite created a draft attempt or reached the provider")
			}
		})
	}
}
