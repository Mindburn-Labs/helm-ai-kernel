package mcpserver

// Native lost-response proof: real gateway HTTP, restricted PostgreSQL role,
// and a GitHub HTTP fake that applies the visible write before dropping its
// connection. The fake is not a production-provider receipt.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/jobs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

type githubCredentials string

func (c githubCredentials) Token(context.Context, string, adapters.Effect) (string, error) {
	return string(c), nil
}

func realGitHubEnv(t *testing.T) (*env, *testkit.FakeGitHub) {
	t.Helper()
	e := newEnv(t)
	fake := testkit.NewFakeGitHubFor(t, "acme", "app")
	ctx := context.Background()
	var branchID string
	must(t, e.owner.QueryRow(`SELECT mandate_id::text FROM authority_mandates
		WHERE tenant_id = $1 AND holder_id = 'agt:seat-1'`, tenantA).Scan(&branchID))
	id, err := uuid.Parse(branchID)
	must(t, err)
	_, err = e.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{
		MandateID: &id, Unit: "count", Measure: "sum", Window: "day", Value: 100, Span: 1,
	})
	must(t, err)
	pr, err := e.rows.CreateMandate(ctx, tenantA, "agt:seat-1", authorityrows.Terms{
		EffectTypes: []string{effectargs.GitHubPullRequestCreateDraft},
		ValidFrom:   e.now.Add(-time.Hour), ValidUntil: e.now.Add(time.Hour),
		Targets: []string{repoA}, ApprovalRequired: []string{effectargs.GitHubPullRequestCreateDraft},
	}, authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"})
	must(t, err)
	_, err = e.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{
		MandateID: &pr.ID, Unit: "count", Measure: "sum", Window: "day", Value: 100, Span: 1,
	})
	must(t, err)
	for _, effectType := range []string{effectargs.GitHubGitPush, effectargs.GitHubPullRequestCreate, effectargs.GitHubPullRequestMerge} {
		risk := authorityrows.RiskMedium
		if effectType == effectargs.GitHubPullRequestMerge {
			risk = authorityrows.RiskHigh
		}
		must(t, e.rows.CreateEffectType(ctx, tenantA, effectType, risk))
	}
	extraTypes := []string{effectargs.GitHubGitPush, effectargs.GitHubPullRequestCreate, effectargs.GitHubPullRequestMerge}
	extra, err := e.rows.CreateMandate(ctx, tenantA, "agt:seat-1", authorityrows.Terms{
		EffectTypes: extraTypes, ValidFrom: e.now.Add(-time.Hour), ValidUntil: e.now.Add(time.Hour),
		Targets: []string{repoA}, ApprovalRequired: extraTypes,
	}, authorityrows.WideningApproval{RequesterID: "human-a", ApproverID: "human-b"})
	must(t, err)
	_, err = e.rows.CreateLimit(ctx, tenantA, authorityrows.LimitSpec{
		MandateID: &extra.ID, Unit: "count", Measure: "sum", Window: "day", Value: 100, Span: 1,
	})
	must(t, err)

	adapter := github.New(github.WithBaseURL(fake.URL()))
	svc, err := admission.New(e.runtime, admission.Config{
		Adapters: []adapters.Adapter{adapter}, Credentials: githubCredentials(fake.Token()),
	})
	must(t, err)
	gw, err := NewGateway(svc, []adapters.Adapter{adapter})
	must(t, err)
	e.srv.Close()
	e.svc, e.gw = svc, gw
	e.srv = httptest.NewServer(&Handler{Backend: gw, Version: "test", Authenticate: func(ctx context.Context, header http.Header) (Caller, error) {
		identity, err := e.auth.Authenticate(ctx, header, server.ScopePropose, server.ScopeRead)
		if err != nil {
			return Caller{}, err
		}
		return Caller{Caller: identity.Caller, Scope: identity.Scope}, nil
	}})
	t.Cleanup(e.srv.Close)
	return e, fake
}

func installRealGitHubJobs(t *testing.T, e *env, fake *testkit.FakeGitHub) func() {
	t.Helper()
	ctx := context.Background()
	must(t, jobs.Migrate(ctx, e.owner))
	var role, schema string
	must(t, e.runtime.QueryRow(`SELECT current_user`).Scan(&role))
	must(t, e.owner.QueryRow(`SELECT current_schema()`).Scan(&schema))
	for table, grant := range map[string]string{
		"river_job": "SELECT, INSERT, UPDATE, DELETE", "river_leader": "SELECT, INSERT, UPDATE, DELETE",
		"river_queue": "SELECT, INSERT, UPDATE, DELETE", "river_notification": "SELECT, INSERT, UPDATE, DELETE",
		"river_migration": "SELECT",
	} {
		_, err := e.owner.Exec(`GRANT ` + grant + ` ON ` + table + ` TO ` + pq.QuoteIdentifier(role))
		must(t, err)
	}
	seqs, err := e.owner.Query(`SELECT sequencename FROM pg_sequences WHERE schemaname = $1 AND sequencename LIKE 'river\_%'`, schema)
	must(t, err)
	for seqs.Next() {
		var name string
		must(t, seqs.Scan(&name))
		_, err = e.owner.Exec(`GRANT USAGE ON SEQUENCE ` + pq.QuoteIdentifier(name) + ` TO ` + pq.QuoteIdentifier(role))
		must(t, err)
	}
	must(t, seqs.Err())
	must(t, seqs.Close())
	runner, err := jobs.New(e.runtime, jobs.Config{
		FirstPoll: 300 * time.Millisecond, RetryBase: 70 * time.Millisecond,
		RetryMax: 140 * time.Millisecond, MaxAttempts: 12, PollInterval: 100 * time.Millisecond,
	})
	must(t, err)
	adapter := github.New(github.WithBaseURL(fake.URL()))
	svc, err := admission.New(e.runtime, admission.Config{
		Adapters: []adapters.Adapter{adapter}, Credentials: githubCredentials(fake.Token()), Jobs: runner,
	})
	must(t, err)
	runner.Bind(svc)
	e.srv.Close()
	gw, err := NewGateway(svc, []adapters.Adapter{adapter})
	must(t, err)
	e.svc, e.gw = svc, gw
	e.srv = httptest.NewServer(&Handler{Backend: gw, Version: "test", Authenticate: func(ctx context.Context, header http.Header) (Caller, error) {
		identity, err := e.auth.Authenticate(ctx, header, server.ScopePropose, server.ScopeRead)
		if err != nil {
			return Caller{}, err
		}
		return Caller{Caller: identity.Caller, Scope: identity.Scope}, nil
	}})
	t.Cleanup(e.srv.Close)
	// Enqueue the durable job during Dispatch, then start its worker only
	// after each case has established its provider read-back mode.
	return func() {
		runCtx, cancel := context.WithCancel(context.Background())
		must(t, runner.Start(runCtx))
		t.Cleanup(func() {
			cancel()
			stopCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			_ = runner.Stop(stopCtx)
		})
	}
}

func waitForGitHubAttempt(t *testing.T, e *env, id string, want func(admission.Attempt) bool) admission.Attempt {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		a := e.attempt(tenantA, id)
		if want(a) {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("attempt %s stayed %s(%s)", id, a.State, a.Outcome)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func waitForFakeRead(t *testing.T, count func() int, before int) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for count() <= before {
		if time.Now().After(deadline) {
			t.Fatalf("read-back did not run; reads stayed at %d", before)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func counterTotals(t *testing.T, e *env) (used, reserved int) {
	t.Helper()
	must(t, e.owner.QueryRow(`SELECT COALESCE(sum(used), 0)::int, COALESCE(sum(reserved), 0)::int
		FROM authority_counters WHERE tenant_id = $1`, tenantA).Scan(&used, &reserved))
	return used, reserved
}

func branchToolArgs(fake *testkit.FakeGitHub, head string) map[string]any {
	return map[string]any{"target": repoA, "arguments": map[string]any{
		"schema": "helm.github.branch.create_from_changes.v1", "base": "main", "base_sha": fake.BaseSHA(),
		"head": head, "message": "Add skeleton", "files": []any{map[string]any{
			"path": "docs/skeleton.md", "mode": "100644", "content_utf8": "# Skeleton\n",
		}},
	}}
}

func pullToolArgsFor(effectType, branchID, head, sha string) map[string]any {
	return map[string]any{"target": repoA, "arguments": map[string]any{
		"schema": "helm." + effectType + ".v1", "branch_attempt_id": branchID,
		"base": "main", "head": head, "head_sha": sha, "title": "Skeleton", "body": "",
	}}
}

func pullToolArgs(branchID, head, sha string) map[string]any {
	return pullToolArgsFor(effectargs.GitHubPullRequestCreateDraft, branchID, head, sha)
}

func pushToolArgs(fake *testkit.FakeGitHub, head string) map[string]any {
	return map[string]any{"target": repoA, "arguments": map[string]any{
		"schema": "helm.github.git.push.v1", "base": "main", "base_sha": fake.HeadSHA(head),
		"head": head, "message": "Advance skeleton", "files": []any{map[string]any{
			"path": "docs/skeleton.md", "mode": "100644", "content_utf8": "# Advanced skeleton\n",
		}},
	}}
}

func mergeToolArgs(fake *testkit.FakeGitHub, head string) map[string]any {
	return map[string]any{"target": repoA, "arguments": map[string]any{
		"schema": "helm.github.pull_request.merge.v1", "pull_number": fake.PullNumber(head),
		"head_sha": fake.HeadSHA(head), "base": "main", "merge_method": "squash",
	}}
}

func approveAndDispatch(t *testing.T, e *env, tool string, args map[string]any, key string) admission.Attempt {
	t.Helper()
	ctx := context.Background()
	first, failed := e.callTool(t, tokenSeat1Ep1, key, tool, args).structured(t)
	if failed || first["status"] != "escalated" {
		t.Fatalf("%s proposal = %v, error=%t", tool, first, failed)
	}
	id := first["attempt_id"].(string)
	a := e.attempt(tenantA, id)
	input := admission.DecideInput{AttemptID: id, ApprovalDigest: a.ApprovalDigest, Reason: "approved"}
	if tool == "github_pull_request_merge" {
		input.StepUp = &admission.StepUp{Token: admission.Token{
			Issuer: "https://control-plane.test", ID: "stepup-" + key,
			Scope: "helm.gateway.stepup", ExpiresAt: time.Now().Add(time.Minute),
		}, Method: "webauthn", Raw: "verified-stepup-" + key}
	}
	_, existing, err := e.svc.Approve(ctx, admission.Caller{
		TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: cpActor,
	}, admission.Token{Issuer: "https://control-plane.test", ID: "decide-" + key,
		Scope: "helm.gateway.decide", ExpiresAt: time.Now().Add(time.Minute)}, input)
	must(t, err)
	if existing {
		t.Fatal("the distinct human approval unexpectedly replayed")
	}
	dispatched, existing, err := e.svc.Dispatch(ctx, admission.Caller{
		TenantID: tenantA, WorkspaceID: workspace, PrincipalID: cpActor,
	}, id)
	must(t, err)
	if existing {
		t.Fatal("the first dispatch was already claimed")
	}
	return dispatched
}

func pullPrerequisite(t *testing.T, e *env, fake *testkit.FakeGitHub, head string) (string, string) {
	t.Helper()
	branch := approveAndDispatch(t, e, "github_branch_create_from_changes", branchToolArgs(fake, head), "prepare-branch")
	if branch.State != "OBSERVED" || branch.Outcome != "SUCCEEDED" || fake.AppliedRef("heads/"+head) != 1 {
		t.Fatalf("branch precondition = %s(%s), writes=%d", branch.State, branch.Outcome, fake.AppliedRef("heads/"+head))
	}
	return branch.ID, fake.HeadSHA(head)
}

type githubWriteScenario struct {
	tool       string
	args       map[string]any
	writeCount func() int
	readCount  func() int
	baseline   int
	refWrite   bool
}

func setupGitHubWrite(t *testing.T, e *env, fake *testkit.FakeGitHub, effectType, head string) githubWriteScenario {
	t.Helper()
	s := githubWriteScenario{refWrite: effectType == effectargs.GitHubBranchCreateFromChanges || effectType == effectargs.GitHubGitPush}
	switch effectType {
	case effectargs.GitHubBranchCreateFromChanges:
		s.tool, s.args = "github_branch_create_from_changes", branchToolArgs(fake, head)
	case effectargs.GitHubGitPush:
		pullPrerequisite(t, e, fake, head)
		s.tool, s.args = "github_git_push", pushToolArgs(fake, head)
	case effectargs.GitHubPullRequestCreateDraft, effectargs.GitHubPullRequestCreate:
		branchID, sha := pullPrerequisite(t, e, fake, head)
		s.tool, s.args = strings.ReplaceAll(effectType, ".", "_"), pullToolArgsFor(effectType, branchID, head, sha)
	case effectargs.GitHubPullRequestMerge:
		branchID, sha := pullPrerequisite(t, e, fake, head)
		ready := approveAndDispatch(t, e, "github_pull_request_create", pullToolArgsFor(effectargs.GitHubPullRequestCreate, branchID, head, sha), "prepare-pull")
		if ready.State != "OBSERVED" || ready.Outcome != "SUCCEEDED" || fake.AppliedPull(head) != 1 {
			t.Fatalf("ready pull prerequisite = %+v, writes=%d", ready, fake.AppliedPull(head))
		}
		fake.SetMergeMode("merged")
		s.tool, s.args = "github_pull_request_merge", mergeToolArgs(fake, head)
	default:
		t.Fatalf("unhandled GitHub write effect %s", effectType)
	}
	if s.refWrite {
		s.writeCount = func() int { return fake.AppliedRef("heads/" + head) }
		s.readCount = func() int { return fake.RefReads(head) }
	} else if effectType == effectargs.GitHubPullRequestMerge {
		s.writeCount = fake.MergeRequests
		s.readCount = fake.MergeReads
	} else {
		s.writeCount = func() int { return fake.AppliedPull(head) }
		s.readCount = func() int { return fake.PullReads(head) }
	}
	s.baseline = s.writeCount()
	return s
}

func setGitHubReadback(fake *testkit.FakeGitHub, refWrite bool, mode testkit.ReadbackMode) {
	if refWrite {
		fake.SetReadback(mode, testkit.ReadbackNormal)
	} else {
		fake.SetReadback(testkit.ReadbackNormal, mode)
	}
}

func newConnectionToolCall(t *testing.T, e *env, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	params := map[string]any{"name": tool, "arguments": args, "_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion":    ProtocolModern,
		"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "native-client", "version": "1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}}
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "fresh-connection", "method": "tools/call", "params": params})
	must(t, err)
	req, err := http.NewRequest(http.MethodPost, e.srv.URL, strings.NewReader(string(raw)))
	must(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+tokenSeat1Ep1)
	req.Header.Set("MCP-Protocol-Version", ProtocolModern)
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", tool)
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	must(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	must(t, err)
	var decoded map[string]any
	must(t, json.Unmarshal(body, &decoded))
	return (reply{Status: resp.StatusCode, Header: resp.Header, Body: decoded}).structured(t)
}

func TestPostgresGitHubApplyThenDropReplayAllDeclaredWrites(t *testing.T) {
	writeTypes := []string{}
	for _, d := range github.New().Declarations() {
		if d.Grantable && d.Reversible != adapters.ReversibleNotApplicable {
			writeTypes = append(writeTypes, d.EffectType)
		}
	}
	sort.Strings(writeTypes)
	covered := []string{effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubGitPush,
		effectargs.GitHubPullRequestCreateDraft, effectargs.GitHubPullRequestCreate, effectargs.GitHubPullRequestMerge}
	sort.Strings(covered)
	if !reflect.DeepEqual(writeTypes, covered) {
		t.Fatalf("GitHub write catalog %v is not covered by the apply-then-drop matrix %v", writeTypes, covered)
	}
	for _, effectType := range writeTypes {
		for _, drop := range []bool{true, false} {
			t.Run(effectType+"/drop="+map[bool]string{true: "yes", false: "no"}[drop], func(t *testing.T) {
				e, fake := realGitHubEnv(t)
				s := setupGitHubWrite(t, e, fake, effectType, "helm/native-branch")
				fake.SetApplyThenDrop(drop && s.refWrite, drop && !s.refWrite)
				got := approveAndDispatch(t, e, s.tool, s.args, "attempt-"+effectType)
				if len(got.Quote) != 1 || got.Quote[0].Unit != "count" || got.Quote[0].Amount != 1 {
					t.Fatalf("the adapter-owned fixed quote was not charged once: %+v", got.Quote)
				}
				if s.writeCount() != s.baseline+1 {
					t.Fatalf("provider applied %d visible writes after %d prerequisites, want one", s.writeCount(), s.baseline)
				}
				if drop {
					if got.State != "UNKNOWN" || got.Outcome != "" || got.ReasonCode != "PROVIDER_ERROR" ||
						len(got.Exposures) != 1 || got.Exposures[0].Kind != "held" || got.Exposures[0].Amount != 1 {
						t.Fatalf("lost response = %+v", got)
					}
				} else if got.State != "OBSERVED" || got.Outcome != "SUCCEEDED" || len(got.Exposures) != 1 || got.Exposures[0].Kind != "confirmed" {
					t.Fatalf("normal control = %+v", got)
				}
				ctx := context.Background()
				cp := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: cpActor}
				for range 3 {
					again, existing, err := e.svc.Dispatch(ctx, cp, got.ID)
					must(t, err)
					if !existing || again.Version != got.Version {
						t.Fatalf("repeated Dispatch = %+v existing=%t", again, existing)
					}
				}
				worker := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agt:seat-1", ActorID: cpActor,
					Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"}}
				rawArgs, err := json.Marshal(s.args["arguments"])
				must(t, err)
				for range 3 {
					again, existing, err := e.svc.ProposeWorkEffect(ctx, worker, admission.ProposeInput{
						EffectType: effectType, Target: repoA, Arguments: rawArgs, Quote: got.Quote,
					})
					must(t, err)
					if !existing || again.ID != got.ID || again.Version != got.Version {
						t.Fatalf("repeated Propose = %+v existing=%t", again, existing)
					}
				}
				replay, isError := newConnectionToolCall(t, e, s.tool, s.args)
				wantStatus := "reconciling"
				if !drop {
					wantStatus = "succeeded"
				}
				if isError || replay["status"] != wantStatus || replay["attempt_id"] != got.ID || s.writeCount() != s.baseline+1 {
					t.Fatalf("new-connection MCP replay = %v error=%t writes=%d", replay, isError, s.writeCount())
				}
				if n := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE effect_type = $1`, effectType); n != 1 {
					t.Fatalf("%d attempts for %s", n, effectType)
				}
				if drop {
					setGitHubReadback(fake, s.refWrite, testkit.ReadbackAbsent)
					early, _, err := e.svc.Observe(ctx, cp, got.ID)
					must(t, err)
					if early.State != "UNKNOWN" || early.Exposures[0].Kind != "held" || early.LatestObservation != nil {
						t.Fatalf("inside-fence absence settled attempt: %+v", early)
					}
				}
			})
		}
	}
}

func TestPostgresGitHubPushAttemptCanBackReadyPullRequest(t *testing.T) {
	e, fake := realGitHubEnv(t)
	head := "helm/push-backed-pull"
	s := setupGitHubWrite(t, e, fake, effectargs.GitHubGitPush, head)
	push := approveAndDispatch(t, e, s.tool, s.args, "push-before-ready-pull")
	if push.State != "OBSERVED" || push.Outcome != "SUCCEEDED" || s.writeCount() != s.baseline+1 {
		t.Fatalf("push prerequisite = %+v, ref writes=%d", push, s.writeCount())
	}
	var kind string
	must(t, e.owner.QueryRow(`SELECT result_kind FROM authority_observations
		WHERE tenant_id = $1 AND attempt_id = $2 AND outcome = 'SUCCEEDED'`, tenantA, push.ID).Scan(&kind))
	if kind != "github_branch" {
		t.Fatalf("push observation result kind = %q", kind)
	}
	ready := approveAndDispatch(t, e, "github_pull_request_create",
		pullToolArgsFor(effectargs.GitHubPullRequestCreate, push.ID, head, fake.HeadSHA(head)), "ready-after-push")
	if ready.State != "OBSERVED" || ready.Outcome != "SUCCEEDED" || fake.AppliedPull(head) != 1 {
		t.Fatalf("ready pull from observed push = %+v, pull writes=%d", ready, fake.AppliedPull(head))
	}
}

func TestPostgresGitHubMergeStepUpAndQueuedReadback(t *testing.T) {
	e, fake := realGitHubEnv(t)
	head := "helm/queued-merge"
	s := setupGitHubWrite(t, e, fake, effectargs.GitHubPullRequestMerge, head)
	fake.SetMergeMode("pending")
	first, failed := e.callTool(t, tokenSeat1Ep1, "queued-merge", s.tool, s.args).structured(t)
	if failed || first["status"] != "escalated" {
		t.Fatalf("merge proposal = %v, error=%t", first, failed)
	}
	id := first["attempt_id"].(string)
	attempt := e.attempt(tenantA, id)
	approver := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: cpActor}
	decide := admission.Token{Issuer: "https://control-plane.test", ID: "queued-merge-decide",
		Scope: "helm.gateway.decide", ExpiresAt: time.Now().Add(time.Minute)}
	decision := admission.DecideInput{AttemptID: id, ApprovalDigest: attempt.ApprovalDigest, Reason: "approved exact merge"}
	_, _, err := e.svc.Approve(context.Background(), approver, decide, decision)
	var refusal *admission.Error
	if !errors.As(err, &refusal) || refusal.Code != admission.CodePermissionDenied || refusal.Reason != "STEP_UP_REQUIRED" || fake.MergeRequests() != 0 {
		t.Fatalf("approval without step-up = %v; merge writes=%d", err, fake.MergeRequests())
	}
	decision.StepUp = &admission.StepUp{Token: admission.Token{Issuer: "https://control-plane.test",
		ID: "queued-merge-stepup", Scope: "helm.gateway.stepup", ExpiresAt: time.Now().Add(time.Minute)},
		Method: "webauthn", Raw: "verified-queued-merge-stepup"}
	approved, existing, err := e.svc.Approve(context.Background(), approver, decide, decision)
	must(t, err)
	if existing || approved.State != "ADMITTED" || fake.MergeRequests() != 0 {
		t.Fatalf("proof-bound approval = %+v, existing=%t, merge writes=%d", approved, existing, fake.MergeRequests())
	}
	if n := e.count(tenantA, `SELECT count(*) FROM authority_approvals WHERE attempt_id = $1
		AND step_up_method = 'webauthn' AND step_up_jti = 'queued-merge-stepup'`, id); n != 1 {
		t.Fatalf("merge approval has %d retained step-up proofs", n)
	}
	cp := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: cpActor}
	queued, existing, err := e.svc.Dispatch(context.Background(), cp, id)
	must(t, err)
	if existing || queued.State != "UNKNOWN" || queued.Outcome != "" || fake.MergeRequests() != 1 ||
		len(queued.Exposures) != 1 || queued.Exposures[0].Kind != "held" {
		t.Fatalf("queued merge was treated as complete: %+v, existing=%t, writes=%d", queued, existing, fake.MergeRequests())
	}
	fake.CompleteMerge(fake.PullNumber(head))
	settled, _, err := e.svc.Observe(context.Background(), cp, id)
	must(t, err)
	if settled.State != "RECONCILED" || settled.Outcome != "SUCCEEDED" || settled.Exposures[0].Kind != "confirmed" || fake.MergeRequests() != 1 {
		t.Fatalf("authoritative merge readback = %+v, writes=%d", settled, fake.MergeRequests())
	}
}

func TestPostgresGitHubFixedQuoteCannotBeUnderstatedByAPI(t *testing.T) {
	e, fake := realGitHubEnv(t)
	args := branchToolArgs(fake, "helm/quote")
	rawArgs, err := json.Marshal(args["arguments"])
	must(t, err)
	caller := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agt:seat-1", ActorID: cpActor,
		Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"}}
	before := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`)
	for _, tc := range []struct {
		name  string
		quote []admission.Amount
	}{
		{"omitted", nil},
		{"zero", []admission.Amount{{Unit: "count", Amount: 0}}},
		{"underquoted", []admission.Amount{{Unit: "count", Amount: 0}, {Unit: "usd_micros", Amount: 1}}},
		{"overquoted", []admission.Amount{{Unit: "count", Amount: 2}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := e.svc.Propose(context.Background(), caller, admission.ProposeInput{
				IdempotencyKey: "quote-" + tc.name, EffectType: effectargs.GitHubBranchCreateFromChanges,
				Target: repoA, Arguments: rawArgs, Quote: tc.quote,
			})
			var refusal *admission.Error
			if !errors.As(err, &refusal) || refusal.Code != admission.CodeInvalidArgument ||
				refusal.Reason != "SCHEMA_VIOLATION" {
				t.Fatalf("quote %v = %v, want invalid argument", tc.quote, err)
			}
			if got := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`); got != before {
				t.Fatalf("refused quote wrote %d attempts", got-before)
			}
		})
	}
	control, existing, err := e.svc.Propose(context.Background(), caller, admission.ProposeInput{
		IdempotencyKey: "quote-control", EffectType: effectargs.GitHubBranchCreateFromChanges,
		Target: repoA, Arguments: rawArgs, Quote: []admission.Amount{{Unit: "count", Amount: 1}},
	})
	must(t, err)
	if existing || control.State != "ESCALATED" {
		t.Fatalf("correct quote = %+v existing=%t", control, existing)
	}
	approved, _, err := e.svc.Approve(context.Background(), admission.Caller{
		TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: cpActor,
	}, admission.Token{Issuer: "https://control-plane.test", ID: "decide-quote",
		Scope: "helm.gateway.decide", ExpiresAt: time.Now().Add(time.Minute)}, admission.DecideInput{
		AttemptID: control.ID, ApprovalDigest: control.ApprovalDigest, Reason: "approved",
	})
	must(t, err)
	if approved.State != "ADMITTED" || len(approved.Exposures) != 1 ||
		approved.Exposures[0].Kind != "held" || approved.Exposures[0].Amount != 1 {
		t.Fatalf("the fitting API proposal did not hold its count: %+v", approved)
	}
}

func TestPostgresGitHubLateReconcileJobFourOutcomes(t *testing.T) {
	for _, effectType := range []string{effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubGitPush,
		effectargs.GitHubPullRequestCreateDraft, effectargs.GitHubPullRequestCreate, effectargs.GitHubPullRequestMerge} {
		for _, outcome := range []string{"matching", "mismatch", "inconclusive-12", "absent-after-fence"} {
			t.Run(fmt.Sprintf("%s/%s", effectType, outcome), func(t *testing.T) {
				e, fake := realGitHubEnv(t)
				startJobs := installRealGitHubJobs(t, e, fake)
				s := setupGitHubWrite(t, e, fake, effectType, "helm/late-branch")
				fake.SetApplyThenDrop(s.refWrite, !s.refWrite)
				got := approveAndDispatch(t, e, s.tool, s.args, "late-"+outcome)
				if got.State != "UNKNOWN" || s.writeCount() != s.baseline+1 || len(got.Exposures) != 1 || got.Exposures[0].Kind != "held" {
					t.Fatalf("initial indefinite write = %+v; applied=%d", got, s.writeCount())
				}
				usedBefore, reservedBefore := counterTotals(t, e)
				if reservedBefore != 1 {
					t.Fatalf("initial reserved = %d, want one held count", reservedBefore)
				}
				baselineReads := s.readCount()
				setMode := func(mode testkit.ReadbackMode) { setGitHubReadback(fake, s.refWrite, mode) }
				switch outcome {
				case "matching", "mismatch", "inconclusive-12":
					setMode(testkit.ReadbackInconclusive)
					startJobs()
					waitForFakeRead(t, s.readCount, baselineReads)
					if still := e.attempt(tenantA, got.ID); still.State != "UNKNOWN" || still.Exposures[0].Kind != "held" {
						t.Fatalf("first inconclusive job read = %+v", still)
					}
					if outcome == "matching" {
						setMode(testkit.ReadbackNormal)
					} else if outcome == "mismatch" {
						setMode(testkit.ReadbackMismatch)
					}
				case "absent-after-fence":
					setMode(testkit.ReadbackAbsent)
					cp := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: cpActor}
					early, _, err := e.svc.Observe(context.Background(), cp, got.ID)
					must(t, err)
					if early.State != "UNKNOWN" || early.Exposures[0].Kind != "held" || early.LatestObservation != nil {
						t.Fatalf("inside-fence absence = %+v", early)
					}
					_, err = e.owner.Exec(`UPDATE authority_effect_attempts SET dispatch_deadline = now() - interval '1 second'
						WHERE tenant_id = $1 AND attempt_id = $2`, tenantA, got.ID)
					must(t, err)
					startJobs()
				}
				final := waitForGitHubAttempt(t, e, got.ID, func(a admission.Attempt) bool { return a.State != "UNKNOWN" })
				wantState, wantOutcome, wantExposure, wantObservations := "RECONCILED", "SUCCEEDED", "confirmed", 1
				wantUsed, wantReserved := usedBefore+1, 0
				switch outcome {
				case "mismatch":
					wantOutcome = "FAILED"
				case "inconclusive-12":
					wantState, wantOutcome, wantExposure, wantObservations = "ESCALATED_TO_HUMAN", "", "held", 0
					wantUsed, wantReserved = usedBefore, 1
				case "absent-after-fence":
					if effectType == effectargs.GitHubPullRequestMerge {
						// A missing merge read is inconclusive: the async request may
						// still be queued, so it cannot release the held exposure.
						wantState, wantOutcome, wantExposure, wantObservations = "ESCALATED_TO_HUMAN", "", "held", 0
						wantUsed, wantReserved = usedBefore, 1
					} else {
						wantOutcome, wantExposure = "FAILED", "released"
						wantUsed = usedBefore
					}
				}
				if final.State != wantState || final.Outcome != wantOutcome || final.Exposures[0].Kind != wantExposure {
					t.Fatalf("%s result = %+v", outcome, final)
				}
				if wantState == "RECONCILED" && final.OutcomeBasis != "RECONCILED" {
					t.Fatalf("reconciled basis = %q", final.OutcomeBasis)
				}
				if outcome == "mismatch" && final.ReasonCode != "READBACK_MISMATCH" ||
					outcome == "absent-after-fence" && effectType != effectargs.GitHubPullRequestMerge && final.ReasonCode != "READBACK_MISMATCH" {
					t.Fatalf("%s reason = %q", outcome, final.ReasonCode)
				}
				if observations := e.count(tenantA, `SELECT count(*) FROM authority_observations WHERE attempt_id = $1`, got.ID); observations != wantObservations {
					t.Fatalf("%d observations, want %d", observations, wantObservations)
				}
				used, reserved := counterTotals(t, e)
				if used != wantUsed || reserved != wantReserved || s.writeCount() != s.baseline+1 {
					t.Fatalf("used/reserved %d/%d, applied writes %d; want %d/%d and one write", used, reserved, s.writeCount(), wantUsed, wantReserved)
				}
				var jobAttempt int
				must(t, e.owner.QueryRow(`SELECT attempt FROM river_job WHERE kind = 'helm_gateway_reconcile'
					AND args ->> 'attempt_id' = $1`, got.ID).Scan(&jobAttempt))
				if outcome == "inconclusive-12" || outcome == "absent-after-fence" && effectType == effectargs.GitHubPullRequestMerge {
					wantReads := 12
					if outcome == "absent-after-fence" {
						wantReads++ // the explicit inside-fence read precedes the twelve jobs
					}
					if jobAttempt != 12 || s.readCount()-baselineReads != wantReads {
						t.Fatalf("job attempts=%d read-backs=%d, want 12 jobs and %d reads", jobAttempt, s.readCount()-baselineReads, wantReads)
					}
				}
			})
		}
	}
}
