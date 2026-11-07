package mcpserver

// This proof uses real PostgreSQL and a fake GitHub HTTP provider. The
// continuation grant is carried by an RS256-signed executor token.

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

func TestPostgresSignedDraftContinuationAfterLostReply(t *testing.T) {
	e, fake := realGitHubEnv(t)
	head := "helm/signed-continuation-draft"
	s := setupGitHubWrite(t, e, fake, effectargs.GitHubPullRequestCreateDraft, head)
	if s.baseline != 0 {
		t.Fatalf("draft prerequisite already wrote %d pull requests", s.baseline)
	}

	issuer := newSignedContinuationIssuer(t)
	e.auth.Validator = issuer.validator
	oldExpiry := issuer.now.Add(time.Minute)
	oldToken := issuer.token(t, "ep-old", "claude-code", issuer.now, oldExpiry, nil)
	first, failed := e.callTool(t, oldToken, "draft-propose", s.tool, s.args).structured(t)
	if failed || first["status"] != "escalated" {
		t.Fatalf("original governed draft proposal = %v, error=%t", first, failed)
	}
	id := first["attempt_id"].(string)
	original := e.attempt(tenantA, id)
	if original.Episode == nil || original.Episode.EpisodeID != "ep-old" ||
		original.RequesterPrincipalID != "agt:seat-1" || len(original.ApprovalDigest) != 32 ||
		fake.AppliedPull(head) != 0 {
		t.Fatalf("original draft escalation = %+v, provider writes=%d", original, fake.AppliedPull(head))
	}

	// The previous executor bearer expires. A successor with the same work
	// item but no signed handoff cannot learn or re-propose that predecessor.
	issuer.now = oldExpiry.Add(40 * time.Second)
	if got := e.modern(t, oldToken, "expired", "tools/list", nil); got.Status != http.StatusUnauthorized {
		t.Fatalf("expired executor bearer was accepted: HTTP %d", got.Status)
	}
	plain := issuer.token(t, "ep-new", "codex", issuer.now, issuer.now.Add(5*time.Minute), nil)
	unproven, failed := e.callTool(t, plain, "unproven-draft", s.tool, s.args).structured(t)
	if !failed || unproven["status"] != "not_found" || fake.AppliedPull(head) != 0 {
		t.Fatalf("unproven cross-episode draft replay = %v, error=%t, writes=%d", unproven, failed, fake.AppliedPull(head))
	}

	grant := continuationGrant(issuer, id, oldExpiry)
	successor := issuer.token(t, "ep-new", "codex", issuer.now, issuer.now.Add(5*time.Minute), grant)
	escalated, failed := e.callTool(t, successor, "signed-escalation", s.tool, s.args).structured(t)
	if failed || escalated["status"] != "escalated" || escalated["attempt_id"] != id || fake.AppliedPull(head) != 0 {
		t.Fatalf("signed escalation recovery = %v, error=%t, writes=%d", escalated, failed, fake.AppliedPull(head))
	}
	if got := e.attempt(tenantA, id); !reflect.DeepEqual(got.ApprovalDigest, original.ApprovalDigest) ||
		got.Episode == nil || got.Episode.EpisodeID != "ep-old" || got.RequesterPrincipalID != original.RequesterPrincipalID {
		t.Fatalf("continuation changed the predecessor's approval or episode: %+v", got)
	}

	// The distinct human approves the predecessor. Worker replay can see the
	// admission, but the control plane alone resumes its retained permit.
	ctx := context.Background()
	cp := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: cpActor}
	_, existing, err := e.svc.Approve(ctx, admission.Caller{
		TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: cpActor,
	}, admission.Token{Issuer: "helm-continuation-proof", ID: "decide-signed-draft",
		Scope: "helm.gateway.decide", ExpiresAt: time.Now().Add(time.Minute)}, admission.DecideInput{
		AttemptID: id, ApprovalDigest: original.ApprovalDigest, Reason: "approved",
	})
	must(t, err)
	if existing {
		t.Fatal("original approval unexpectedly replayed")
	}
	approved, failed := e.callTool(t, successor, "signed-approved", s.tool, s.args).structured(t)
	if failed || approved["attempt_id"] != id || approved["state"] != "ADMITTED" ||
		fake.AppliedPull(head) != 0 {
		t.Fatalf("worker consumed the original resume permit: %v, error=%t, writes=%d", approved, failed, fake.AppliedPull(head))
	}
	if n := e.count(tenantA, `SELECT count(*) FROM authority_approvals WHERE attempt_id = $1`, id); n != 1 {
		t.Fatalf("predecessor has %d approvals, want one", n)
	}

	// GitHub applies the draft PR, then closes the response connection.
	// Dispatch records uncertainty; the successor must never send it again.
	fake.SetApplyThenDrop(false, true)
	lost, existing, err := e.svc.Dispatch(ctx, cp, id)
	must(t, err)
	if existing || lost.State != "UNKNOWN" || lost.ReasonCode != "PROVIDER_ERROR" ||
		fake.AppliedPull(head) != 1 {
		t.Fatalf("lost provider reply = %+v, existing=%t, writes=%d", lost, existing, fake.AppliedPull(head))
	}
	unknown, failed := e.callTool(t, successor, "signed-lost-reply", s.tool, s.args).structured(t)
	if failed || unknown["status"] != "reconciling" || unknown["attempt_id"] != id ||
		unknown["state"] != lost.State || fake.AppliedPull(head) != 1 {
		t.Fatalf("signed lost-reply replay = %v, error=%t, writes=%d", unknown, failed, fake.AppliedPull(head))
	}
	unproven, failed = e.callTool(t, plain, "unproven-lost-reply", s.tool, s.args).structured(t)
	if !failed || unproven["status"] != "not_found" || fake.AppliedPull(head) != 1 {
		t.Fatalf("unproven successor learned the applied draft: %v, error=%t, writes=%d", unproven, failed, fake.AppliedPull(head))
	}
	repeated, existing, err := e.svc.Dispatch(ctx, cp, id)
	must(t, err)
	if !existing || repeated.Version != lost.Version || fake.AppliedPull(head) != 1 {
		t.Fatalf("repeated dispatch = %+v, existing=%t, writes=%d", repeated, existing, fake.AppliedPull(head))
	}

	// An authoritative provider readback settles the one predecessor; the
	// signed successor receives that same typed draft result on fresh calls.
	settled, _, err := e.svc.Observe(ctx, cp, id)
	must(t, err)
	if settled.State != "RECONCILED" || settled.Outcome != "SUCCEEDED" {
		t.Fatalf("provider readback did not settle the original draft: %+v", settled)
	}
	result, failed := e.callTool(t, successor, "signed-result", s.tool, s.args).structured(t)
	if failed || result["status"] != "succeeded" || result["attempt_id"] != id ||
		result["result_kind"] != "github_pull_request" {
		t.Fatalf("signed draft result = %v, error=%t", result, failed)
	}
	pr, ok := result["result"].(map[string]any)
	if !ok || pr["draft"] != true || pr["number"] != float64(fake.PullNumber(head)) ||
		pr["url"] != "https://github.com/acme/app/pull/1" {
		t.Fatalf("recovered result was not the provider's draft PR: %v", result["result"])
	}
	again, failed := e.callTool(t, successor, "signed-result-again", s.tool, s.args).structured(t)
	if failed || !reflect.DeepEqual(again["result"], result["result"]) || again["attempt_id"] != id ||
		fake.AppliedPull(head) != 1 {
		t.Fatalf("later signed replay = %v, error=%t, writes=%d", again, failed, fake.AppliedPull(head))
	}
	if n := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE effect_type = $1`,
		effectargs.GitHubPullRequestCreateDraft); n != 1 {
		t.Fatalf("work item has %d draft attempts, want one", n)
	}
	if n := e.count(tenantA, `SELECT count(*) FROM authority_permits WHERE attempt_id = $1 AND consumed_at IS NOT NULL`, id); n != 1 {
		t.Fatalf("predecessor has %d consumed permits, want one", n)
	}
}
