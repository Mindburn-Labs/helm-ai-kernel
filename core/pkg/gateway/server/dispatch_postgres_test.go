package server

// The HELM-789 walking skeleton on the wire, against real PostgreSQL 16
// (listed in scripts/ci/postgres-proofs.txt): Propose, Approve, Dispatch and
// Observe over Connect, with the GitHub App custody minting the credential
// and a fake GitHub adapter in place of github.com.
//
// quantum_posture: signs classical RS256 test tokens and a test GitHub App
// JWT, and computes SHA-256 and SHA-1 test digests; no post-quantum claim.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // made-up git object IDs for a fake GitHub
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

// fakeGitHub is a GitHub adapter over an in-memory repository: a default
// branch main, branches it creates and never overwrites, and draft pull
// requests. It checks the permit digest and asks for its credential on every
// call, as the real adapter does.
type fakeGitHub struct {
	mu       sync.Mutex
	mainSHA  string
	branches map[string]string // head -> commit
	pulls    map[string]*adapters.GitHubPullRequestResult
	tokens   []string
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{mainSHA: gitID("main"), branches: map[string]string{}, pulls: map[string]*adapters.GitHubPullRequestResult{}}
}

func gitID(parts ...string) string {
	h := sha1.New() //nolint:gosec // made-up object IDs
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type skeletonArgs struct {
	Head    string `json:"head"`
	HeadSHA string `json:"head_sha"`
	Base    string `json:"base"`
	BaseSHA string `json:"base_sha"`
	Title   string `json:"title"`
}

func (g *fakeGitHub) Declarations() []adapters.Declaration {
	var out []adapters.Declaration
	for _, t := range []string{effectargs.GitHubRepositoryGet, effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubPullRequestCreateDraft} {
		out = append(out, adapters.Declaration{EffectType: t, Idempotent: adapters.IdempotentConditional, Observable: adapters.ObservableYes})
	}
	return out
}

func (g *fakeGitHub) Prepare(context.Context, adapters.TokenSource, adapters.Effect) (*adapters.Preparation, error) {
	return nil, adapters.Refuse(contracts.ReasonSchemaViolation, "not used")
}

func (g *fakeGitHub) Dispatch(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect, digest []byte) adapters.DispatchResult {
	if r := adapters.CheckPermitDigest(effect.Arguments, digest); r != nil {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: r.Reason}
	}
	token, err := creds.Token(ctx)
	if err != nil {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonProviderCredentialRejected, Detail: err.Error()}
	}
	var args skeletonArgs
	_ = json.Unmarshal(effect.Arguments, &args)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tokens = append(g.tokens, token)
	switch effect.EffectType {
	case effectargs.GitHubBranchCreateFromChanges:
		if _, exists := g.branches[args.Head]; !exists {
			g.branches[args.Head] = gitID(args.BaseSHA, string(effect.Arguments))
		}
	case effectargs.GitHubPullRequestCreateDraft:
		if g.branches[args.Head] != args.HeadSHA {
			return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: contracts.ReasonPreconditionFailed, Detail: "the head moved"}
		}
		if g.pulls[args.Head] == nil {
			g.pulls[args.Head] = &adapters.GitHubPullRequestResult{URL: fmt.Sprintf("https://github.com/Mindburn-Labs/example/pull/%d", len(g.pulls)+1),
				Number: int64(len(g.pulls) + 1), HeadRef: args.Head, HeadSHA: args.HeadSHA, BaseRef: args.Base, Draft: true, State: "open"}
		}
	}
	return adapters.DispatchResult{Status: adapters.DispatchSent}
}

func (g *fakeGitHub) Observe(ctx context.Context, creds adapters.TokenSource, effect adapters.Effect) adapters.ObserveResult {
	if _, err := creds.Token(ctx); err != nil {
		return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Reason: contracts.ReasonProviderCredentialRejected}
	}
	var args skeletonArgs
	_ = json.Unmarshal(effect.Arguments, &args)
	g.mu.Lock()
	defer g.mu.Unlock()
	digest := make([]byte, 32)
	o := &adapters.Observation{Source: "fake.github.readback", TrustClass: "provider_readback", EvidenceDigest: digest, ObservedAt: time.Now()}
	switch effect.EffectType {
	case effectargs.GitHubRepositoryGet:
		o.GitHubRepository = &adapters.GitHubRepositoryResult{DefaultBranch: "main", DefaultBranchSHA: g.mainSHA}
	case effectargs.GitHubBranchCreateFromChanges:
		o.GitHubBranch = &adapters.GitHubBranchResult{Ref: "refs/heads/" + args.Head, CommitSHA: g.branches[args.Head], BaseSHA: args.BaseSHA}
		if o.GitHubBranch.CommitSHA == "" {
			return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch, Observation: o}
		}
	case effectargs.GitHubPullRequestCreateDraft:
		pr := g.pulls[args.Head]
		if pr == nil {
			o.GitHubPullRequest = &adapters.GitHubPullRequestResult{HeadRef: args.Head, BaseRef: args.Base}
			return adapters.ObserveResult{Outcome: adapters.OutcomeFailed, Reason: contracts.ReasonReadbackMismatch, Observation: o}
		}
		copied := *pr
		o.GitHubPullRequest = &copied
	}
	return adapters.ObserveResult{Outcome: adapters.OutcomeSucceeded, Observation: o}
}

// githubApp is the real custody against a fake GitHub App token endpoint.
func githubApp(t *testing.T) *custody.GitHubApp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	var mu sync.Mutex
	n := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !strings.HasSuffix(r.URL.Path, "/access_tokens") {
			http.Error(w, "{}", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		n++
		token := fmt.Sprintf("ghs_minted_%d", n)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).UTC()})
	}))
	t.Cleanup(api.Close)
	app, err := custody.NewGitHubApp("1234", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		[]byte(`{"installations":[{"tenant_id":"tenant-a","owner":"Mindburn-Labs","installation_id":7,"repositories":["Mindburn-Labs/example"]}]}`),
		api.URL)
	must(t, err)
	return app
}

func state(s string) gatewayv1.EffectAttemptState {
	return gatewayv1.EffectAttemptState(gatewayv1.EffectAttemptState_value["EFFECT_ATTEMPT_STATE_"+s])
}

func wantAttempt(t *testing.T, what string, a *gatewayv1.EffectAttempt, s string, outcome gatewayv1.EffectOutcome, reason contracts.ReasonCode) {
	t.Helper()
	if a.GetState() != state(s) || a.GetOutcome() != outcome || a.GetReasonCode() != string(reason) {
		t.Fatalf("%s: %s %s %q, want %s %s %q", what, a.GetState(), a.GetOutcome(), a.GetReasonCode(), s, outcome, reason)
	}
}

func skeletonRequest(key, effectType, args string) *gatewayv1.ProposeRequest {
	return &gatewayv1.ProposeRequest{
		IdempotencyKey: key,
		WorkRef:        &gatewayv1.ProposeRequest_CommitmentId{CommitmentId: "commitment-1"},
		Effect:         &gatewayv1.EffectDescriptor{EffectType: effectType, Target: testRepo, Arguments: []byte(args)},
	}
}

func TestPostgresWalkingSkeletonOnTheWire(t *testing.T) {
	github := newFakeGitHub()
	client, iss, db := newWire(t, admission.Config{Adapters: []adapters.Adapter{github}, Credentials: githubApp(t)})
	ctx := context.Background()

	// The skeleton's mandate for human-a: read the repository, create a
	// helm/ branch, and open a draft pull request that needs approval.
	rows, err := authorityrows.New(db)
	must(t, err)
	must(t, rows.CreateEffectType(ctx, "tenant-a", effectargs.GitHubRepositoryGet, authorityrows.RiskLow))
	must(t, rows.CreateEffectType(ctx, "tenant-a", effectargs.GitHubPullRequestCreateDraft, authorityrows.RiskMedium))
	now := time.Now()
	_, err = rows.CreateMandate(ctx, "tenant-a", "human-a", authorityrows.Terms{
		EffectTypes: []string{effectargs.GitHubRepositoryGet, effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubPullRequestCreateDraft},
		Targets:     []string{testRepo},
		Condition:   `input.effect_type == "github.repository.get" || input.args.head.startsWith("helm/")`,
		// The draft pull request is a medium effect the mandate escalates.
		ApprovalRequired: []string{effectargs.GitHubPullRequestCreateDraft},
		ValidFrom:        now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"})
	must(t, err)

	propose := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	// The Control Plane runner, which carried human-a's Propose (act.sub),
	// dispatches as itself: a workload principal, directly.
	execute := func() string {
		return iss.token(t, testAudience, "tenant-a", testActor, ScopeExecute, func(c *tokenClaims) { c.Act = nil })
	}
	dispatch := func(what, id string) *gatewayv1.EffectAttempt {
		t.Helper()
		resp, err := client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: id}, execute()))
		must(t, err)
		if resp.Msg.GetExisting() {
			t.Fatalf("%s: the first Dispatch answered existing", what)
		}
		return resp.Msg.GetAttempt()
	}
	proposeOK := func(req *gatewayv1.ProposeRequest) *gatewayv1.EffectAttempt {
		t.Helper()
		resp, err := client.Propose(ctx, withToken(req, propose))
		must(t, err)
		return resp.Msg.GetAttempt()
	}

	// 1. github.repository.get: ALLOW, dispatched and read back.
	read := proposeOK(skeletonRequest("repo-1", effectargs.GitHubRepositoryGet, `{"schema":"helm.github.repository.get.v1"}`))
	wantAttempt(t, "repository.get", read, "ADMITTED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, "")
	read = dispatch("repository.get", read.GetAttemptId())
	wantAttempt(t, "repository.get dispatched", read, "OBSERVED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED, "")
	repository := read.GetLatestObservation().GetGithubRepository()
	if repository.GetDefaultBranch() != "main" || repository.GetDefaultBranchSha() != github.mainSHA ||
		!strings.HasPrefix(read.GetLatestObservation().GetResultRef(), "sha256:") {
		t.Fatalf("repository result = %+v", read.GetLatestObservation())
	}

	// 2. The branch, based on what the read returned: ALLOW, dispatch,
	// observe.
	branchArgs := `{"schema":"helm.github.branch.create_from_changes.v1","base":"main","base_sha":"` + repository.GetDefaultBranchSha() +
		`","head":"helm/skeleton","message":"Add skeleton","files":[{"path":"docs/skeleton.md","mode":"100644","content_utf8":"# Skeleton\n"}]}`
	branch := proposeOK(skeletonRequest("branch-1", effectargs.GitHubBranchCreateFromChanges, branchArgs))
	wantAttempt(t, "branch", branch, "ADMITTED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, "")
	branch = dispatch("branch", branch.GetAttemptId())
	wantAttempt(t, "branch dispatched", branch, "OBSERVED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED, "")
	observed, err := client.Observe(ctx, withToken(&gatewayv1.ObserveRequest{AttemptId: branch.GetAttemptId()}, execute()))
	must(t, err)
	if !observed.Msg.GetExisting() || observed.Msg.GetAttempt().GetVersion() != branch.GetVersion() {
		t.Fatalf("Observe of an observed branch = %+v", observed.Msg)
	}
	commit := branch.GetLatestObservation().GetGithubBranch().GetCommitSha()
	if commit == "" || commit != github.branches["helm/skeleton"] || branch.GetPermit().GetConsumedAt() == nil {
		t.Fatalf("branch = %+v", branch)
	}

	// DENY: a branch on the default branch breaks the mandate's condition.
	denied := proposeOK(skeletonRequest("branch-main", effectargs.GitHubBranchCreateFromChanges, strings.Replace(branchArgs, `"head":"helm/skeleton"`, `"head":"main"`, 1)))
	wantAttempt(t, "a branch on main", denied, "DENIED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonMissingRequirement)
	_, err = client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: denied.GetAttemptId()}, execute()))
	wantRPCError(t, "dispatching a denied attempt", err, connect.CodeFailedPrecondition, "")

	// 3. The draft pull request over the observed branch: ESCALATED.
	prArgs := `{"schema":"helm.github.pull_request.create_draft.v1","branch_attempt_id":"` + branch.GetAttemptId() +
		`","base":"main","head":"helm/skeleton","head_sha":"` + commit + `","title":"Skeleton","body":""}`
	pr := proposeOK(skeletonRequest("pr-1", effectargs.GitHubPullRequestCreateDraft, prArgs))
	wantAttempt(t, "draft pull request", pr, "ESCALATED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, contracts.ReasonApprovalRequired)
	_, err = client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: pr.GetAttemptId()}, execute()))
	wantRPCError(t, "dispatching before the approval", err, connect.CodeFailedPrecondition, "")
	approve := func(principal string) (*connect.Response[gatewayv1.ApproveResponse], error) {
		token := iss.token(t, testAudience, "tenant-a", principal, ScopeDecide, decision(pr.GetAttemptId(), "approve"))
		return client.Approve(ctx, withToken(&gatewayv1.ApproveRequest{AttemptId: pr.GetAttemptId(),
			ApprovalDigest: pr.GetPendingApproval().GetApprovalDigest(), Reason: "ship it"}, token))
	}
	// 4. The requester cannot approve it; a distinct human can.
	_, err = approve("human-a")
	wantRPCError(t, "self-approval", err, connect.CodePermissionDenied, contracts.ReasonApproverNotDistinct)
	approved, err := approve("human-b")
	must(t, err)
	wantAttempt(t, "approved", approved.Msg.GetAttempt(), "ADMITTED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_UNSPECIFIED, "")

	// Only a workload dispatches: not the human's token, not a read token.
	for name, token := range map[string]string{
		"a human's execute token": iss.token(t, testAudience, "tenant-a", "human-b", ScopeExecute, func(c *tokenClaims) { c.Act = nil }),
		"a read token":            iss.token(t, testAudience, "tenant-a", testActor, ScopeRead, func(c *tokenClaims) { c.Act = nil }),
		"another workload":        iss.token(t, testAudience, "tenant-a", "agent-a", ScopeExecute, func(c *tokenClaims) { c.Act = nil }),
	} {
		_, err := client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: pr.GetAttemptId()}, token))
		wantRPCError(t, name, err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	otherTenant := iss.token(t, testAudience, "tenant-b", testActor, ScopeExecute, func(c *tokenClaims) { c.Act = nil })
	_, err = client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: pr.GetAttemptId()}, otherTenant))
	wantRPCError(t, "another tenant's workload", err, connect.CodeNotFound, "")

	// 5. Dispatch: OBSERVED(SUCCEEDED) with the pull request read back.
	opened := dispatch("draft pull request", pr.GetAttemptId())
	wantAttempt(t, "draft pull request dispatched", opened, "OBSERVED", gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED, "")
	result := opened.GetLatestObservation().GetGithubPullRequest()
	if !result.GetDraft() || result.GetHeadSha() != commit || result.GetUrl() == "" || opened.GetOutcomeBasis() != gatewayv1.OutcomeBasis_OUTCOME_BASIS_OBSERVED {
		t.Fatalf("pull request result = %+v", opened.GetLatestObservation())
	}
	again, err := client.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: pr.GetAttemptId()}, execute()))
	must(t, err)
	if !again.Msg.GetExisting() || len(github.pulls) != 1 {
		t.Fatalf("a second Dispatch = %+v; %d pull requests", again.Msg, len(github.pulls))
	}
	// Every provider call carried the installation token the custody minted.
	for _, token := range github.tokens {
		if !strings.HasPrefix(token, "ghs_minted_") {
			t.Fatalf("the adapter was handed %q, not a minted installation token", token)
		}
	}
	if len(github.tokens) != 3 {
		t.Fatalf("%d provider writes, want 3", len(github.tokens))
	}
}
