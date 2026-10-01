package mcpserver

// The MCP endpoint end to end on real PostgreSQL 16 (HELM-751 K3, N1). Every
// request here is HTTP through the real handler and the real token check;
// direct ledger calls are limited to CP decisions/reads and an explicit
// negative check of the worker dispatch backstop.
//
// quantum_posture: fake token claims; nothing here signs or verifies, and no
// post-quantum claim is made.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func toolNames(t *testing.T, r reply) []string {
	t.Helper()
	var names []string
	for _, tool := range r.result(t)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	return names
}

func TestPostgresToolsListReflectsTheCallersMandates(t *testing.T) {
	e := newEnv(t)
	list := func(token string) []string { return toolNames(t, e.modern(t, token, 1, "tools/list", nil)) }

	// Each seat is offered what its mandates name, the gateway performs and its
	// tenant holds, in name order, and the attempt tool always.
	for token, want := range map[string][]string{
		tokenSeat1Ep1: {"github_branch_create_from_changes", "github_repository_get", "helm_attempt_get"},
		tokenSeat2:    {"github_repository_get", "helm_attempt_get"},
		tokenNoSeat:   {"helm_attempt_get"},
		tokenTenantB:  {"github_repository_get", "helm_attempt_get"},
		tokenSeat1Ro:  {"github_branch_create_from_changes", "github_repository_get", "helm_attempt_get"},
	} {
		if got := list(token); !reflect.DeepEqual(got, want) {
			t.Errorf("%s lists %v, want %v", token, got, want)
		}
	}

	// Each tool is the effect type with its dots as underscores, its target
	// apart from its arguments, and the published argument schema.
	seat1 := e.modern(t, tokenSeat1Ep1, 2, "tools/list", nil).result(t)
	if seat1["cacheScope"] != "private" || seat1["resultType"] != "complete" || seat1["ttlMs"].(float64) < 0 {
		t.Fatalf("the list is not private to its credential: %v", seat1)
	}
	for _, raw := range seat1["tools"].([]any) {
		tool := raw.(map[string]any)
		if tool["name"] != "github_repository_get" {
			continue
		}
		schema := tool["inputSchema"].(map[string]any)
		props := schema["properties"].(map[string]any)
		args := props["arguments"].(map[string]any)["properties"].(map[string]any)
		if schema["type"] != "object" || !reflect.DeepEqual(schema["required"], []any{"target", "arguments"}) ||
			args["schema"].(map[string]any)["const"] != "helm.github.repository.get.v1" ||
			props["target"].(map[string]any)["type"] != "string" {
			t.Fatalf("github_repository_get input = %v", schema)
		}
		if _, ok := props["arguments"].(map[string]any)["$id"]; ok {
			t.Fatal("the embedded schema kept its $id")
		}
	}

	// The initialization-based revisions reach the same tools through their
	// handshake, in their own result shape.
	init := e.legacy(t, tokenSeat1Ep1, "", 1, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "sdk", "version": "1"}}).result(t)
	if init["protocolVersion"] != "2025-11-25" {
		t.Fatalf("initialize = %v", init)
	}
	old := e.legacy(t, tokenSeat1Ep1, "2025-11-25", 2, "tools/list", nil).result(t)
	if _, ok := old["resultType"]; ok || len(old["tools"].([]any)) != 3 {
		t.Fatalf("legacy tools/list = %v", old)
	}
	if got := e.modern(t, tokenSeat1Ep1, "d", "server/discover", nil).result(t); got["cacheScope"] != "public" {
		t.Fatalf("discover = %v", got)
	}

	// The list follows the mandates: revoking seat 2's takes its tool away.
	var id string
	must(t, e.owner.QueryRow(`SELECT mandate_id::text FROM authority_mandates WHERE tenant_id = $1 AND holder_id = 'agt:seat-2'`, tenantA).Scan(&id))
	mandate, err := uuid.Parse(id)
	must(t, err)
	must(t, e.rows.Revoke(context.Background(), tenantA, mandate))
	if got := list(tokenSeat2); !reflect.DeepEqual(got, []string{"helm_attempt_get"}) {
		t.Fatalf("after the revocation seat 2 lists %v", got)
	}

	// Only agents are served, whatever they hold, and only on a valid token of
	// an episode.
	for token, status := range map[string]int{tokenService: 403, tokenHuman: 403, tokenNoEp: 403, "": 401, "not-a-token": 401} {
		r := e.modern(t, token, 3, "tools/list", nil)
		if r.Status != status {
			t.Errorf("token %q: HTTP %d, want %d", token, r.Status, status)
		}
		if status == 401 && r.Header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("token %q: no bearer challenge", token)
		}
	}
}

func TestPostgresAnAllowedCallIsDispatchedAndObservedInTheSameCall(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	got := e.callTool(t, tokenSeat1Ep1, "call-1", "github_repository_get", getArgs(repoA))
	content, isError := got.structured(t)
	if isError || content["status"] != "succeeded" || content["outcome"] != "SUCCEEDED" || content["effect_type"] != "github.repository.get" ||
		content["target"] != repoA || content["result_kind"] != "github_repository" {
		t.Fatalf("call = %v (error %v)", content, isError)
	}
	if result := content["result"].(map[string]any); result["default_branch"] != "main" || result["default_branch_sha"] != commitSHA {
		t.Fatalf("typed result = %v", result)
	}

	// One call: proposed, admitted, sent once and read back, by the worker's
	// own identity, which records who claimed the permit.
	a := e.attempt(tenantA, content["attempt_id"].(string))
	if a.State != "OBSERVED" || a.Outcome != "SUCCEEDED" || a.RequesterPrincipalID != "agt:seat-1" || a.RequesterActorID != cpActor ||
		a.Permit == nil || a.Permit.ConsumedAt == nil {
		t.Fatalf("attempt = %+v", a)
	}
	var by, byActor string
	must(t, e.owner.QueryRow(`SELECT claimed_by_principal_id, claimed_by_actor_id FROM authority_permits WHERE tenant_id = $1 AND attempt_id = $2`,
		tenantA, a.ID).Scan(&by, &byActor))
	if by != "agt:seat-1" || byActor != cpActor {
		t.Fatalf("the permit was claimed by %q for %q, want the worker and its carrier", by, byActor)
	}
	if e.adapter.dispatched.Load() != 1 {
		t.Fatalf("the provider was sent %d effects", e.adapter.dispatched.Load())
	}

	// The worker's token has no execute scope, and the effect API's Dispatch and
	// Observe still ask for it: the same token is refused there.
	api := &server.Server{Admission: e.svc, Auth: e.auth}
	for name, call := range map[string]func(*http.Header) error{
		"Dispatch": func(h *http.Header) error {
			req := connect.NewRequest(&gatewayv1.DispatchRequest{AttemptId: a.ID})
			req.Header().Set("Authorization", h.Get("Authorization"))
			_, err := api.Dispatch(ctx, req)
			return err
		},
		"Observe": func(h *http.Header) error {
			req := connect.NewRequest(&gatewayv1.ObserveRequest{AttemptId: a.ID})
			req.Header().Set("Authorization", h.Get("Authorization"))
			_, err := api.Observe(ctx, req)
			return err
		},
	} {
		h := http.Header{"Authorization": []string{"Bearer " + tokenSeat1Ep1}}
		if err := call(&h); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s with a worker token = %v, want permission denied", name, err)
		}
	}

	// The initialization-based revisions make the same call the same way.
	old := e.legacy(t, tokenSeat1Ep1, "2025-11-25", 2, "tools/call", map[string]any{"name": "github_repository_get", "arguments": getArgs(repoA)})
	oldContent, isError := old.structured(t)
	if isError || oldContent["status"] != "succeeded" || oldContent["attempt_id"] == content["attempt_id"] || e.adapter.dispatched.Load() != 2 {
		t.Fatalf("legacy call = %v", oldContent)
	}
	if _, ok := old.result(t)["resultType"]; ok {
		t.Fatal("a legacy result carries resultType")
	}
}

func TestPostgresAnEscalatedCallIsAStructuredResultAndContinuesAfterApproval(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	got := e.callTool(t, tokenSeat1Ep1, "b-1", "github_branch_create_from_changes", branchCall(repoA, "helm/skeleton"))
	content, isError := got.structured(t)
	if isError || content["status"] != "escalated" || content["attempt_id"] == "" {
		t.Fatalf("an escalation must be a successful result: %v (error %v)", content, isError)
	}
	id := content["attempt_id"].(string)
	a := e.attempt(tenantA, id)
	if a.State != "ESCALATED" || a.Permit != nil || len(a.ApprovalDigest) != 32 || e.adapter.dispatched.Load() != 0 {
		t.Fatalf("an escalated attempt = %+v, %d dispatched", a, e.adapter.dispatched.Load())
	}
	if a.Episode == nil || a.Episode.EpisodeID != "ep-1" || a.CaseID != "work-ep-1" {
		t.Fatalf("the escalation is not tied to the episode: %+v", a.Episode)
	}

	// A human decides. A worker retry may read the approved attempt but must
	// leave the single-use permit to the CP's authenticated resume path.
	approver := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: cpActor}
	_, _, err := e.svc.Approve(ctx, approver, admission.Token{Issuer: "https://control-plane.test", ID: "jti-1", Scope: "helm.gateway.decide",
		ExpiresAt: time.Now().Add(time.Minute)}, admission.DecideInput{AttemptID: id, ApprovalDigest: a.ApprovalDigest, Reason: "ok"})
	must(t, err)
	if e.adapter.dispatched.Load() != 0 {
		t.Fatal("the approval dispatched by itself")
	}
	again, isError := e.callTool(t, tokenSeat1Ep1, "b-1", "github_branch_create_from_changes", branchCall(repoA, "helm/skeleton")).structured(t)
	if isError || again["status"] != "reconciling" || again["state"] != "ADMITTED" || again["attempt_id"] != id || e.adapter.dispatched.Load() != 0 {
		t.Fatalf("the replay after the approval = %v, %d dispatched", again, e.adapter.dispatched.Load())
	}
	worker := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "agt:seat-1", ActorID: cpActor,
		Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"}}
	_, _, err = e.svc.Dispatch(ctx, worker, id)
	var refusal *admission.Error
	if !errors.As(err, &refusal) || refusal.Code != admission.CodePermissionDenied || e.adapter.dispatched.Load() != 0 {
		t.Fatalf("worker claimed an approved escalation: %v, %d dispatched", err, e.adapter.dispatched.Load())
	}
	if unused := e.count(tenantA, `SELECT count(*) FROM authority_permits WHERE consumed_at IS NULL AND voided_at IS NULL`); unused != 1 {
		t.Fatalf("worker replay changed the CP resume permit: %d unused", unused)
	}
	cpAPI := &server.Server{Admission: e.svc, Auth: &server.Authenticator{Actor: cpActor,
		Validator: testValidator{"cp-execute": claims(tenantA, cpActor, server.ScopeExecute, nil)}}}
	dispatch := connect.NewRequest(&gatewayv1.DispatchRequest{AttemptId: id})
	dispatch.Header().Set("Authorization", "Bearer cp-execute")
	_, err = cpAPI.Dispatch(ctx, dispatch)
	must(t, err)
	again, isError = e.callTool(t, tokenSeat1Ep1, "b-1", "github_branch_create_from_changes", branchCall(repoA, "helm/skeleton")).structured(t)
	if isError || again["status"] != "succeeded" || again["attempt_id"] != id || again["result_kind"] != "github_branch" || e.adapter.dispatched.Load() != 1 {
		t.Fatalf("replay after CP resume = %v, %d dispatched", again, e.adapter.dispatched.Load())
	}
	var by string
	must(t, e.owner.QueryRow(`SELECT claimed_by_principal_id FROM authority_permits WHERE tenant_id = $1 AND attempt_id = $2`, tenantA, id).Scan(&by))
	if by != cpActor {
		t.Fatalf("the permit was claimed by %q", by)
	}
	// And once more: nothing is sent twice.
	e.callTool(t, tokenSeat1Ep1, "b-1", "github_branch_create_from_changes", branchCall(repoA, "helm/skeleton")).structured(t)
	if e.adapter.dispatched.Load() != 1 {
		t.Fatalf("the provider was sent %d effects", e.adapter.dispatched.Load())
	}

	// A human who rejects it makes the same call an error the worker can read.
	other := e.callTool(t, tokenSeat1Ep1, "b-2", "github_branch_create_from_changes", branchCall(repoA, "helm/other"))
	otherContent, _ := other.structured(t)
	otherAttempt := e.attempt(tenantA, otherContent["attempt_id"].(string))
	_, _, err = e.svc.Reject(ctx, approver, admission.Token{Issuer: "https://control-plane.test", ID: "jti-2", Scope: "helm.gateway.decide",
		ExpiresAt: time.Now().Add(time.Minute)}, admission.DecideInput{AttemptID: otherAttempt.ID, ApprovalDigest: otherAttempt.ApprovalDigest, Reason: "no"})
	must(t, err)
	rejected, isError := e.callTool(t, tokenSeat1Ep1, "b-2", "github_branch_create_from_changes", branchCall(repoA, "helm/other")).structured(t)
	if !isError || rejected["status"] != "rejected" || rejected["reason_code"] != "APPROVAL_REJECTED" || e.adapter.dispatched.Load() != 1 {
		t.Fatalf("a rejected call = %v", rejected)
	}
}

func TestPostgresADeniedCallIsAToolErrorWithItsReasonCode(t *testing.T) {
	e := newEnv(t)
	denied := func(token, tool string, args map[string]any) map[string]any {
		t.Helper()
		content, isError := e.callTool(t, token, tool+token, tool, args).structured(t)
		if !isError || content["status"] != "denied" || content["reason_code"] == nil || content["attempt_id"] == nil {
			t.Fatalf("%s by %s = %v (error %v), want a denial with its reason", tool, token, content, isError)
		}
		return content
	}
	// A target the mandate does not allow, an effect type it does not name, and
	// a seat that holds no mandate at all.
	if c := denied(tokenSeat1Ep1, "github_repository_get", getArgs(repoB)); c["reason_code"] != "EFFECT_OUT_OF_SCOPE" {
		t.Fatalf("an unlisted target: %v", c)
	}
	unnamed := denied(tokenSeat2, "github_branch_create_from_changes", branchCall(repoA, "helm/x"))
	none := denied(tokenNoSeat, "github_repository_get", getArgs(repoA))
	for _, c := range []map[string]any{unnamed, none} {
		if c["message"] == nil || c["message"] == "" {
			t.Fatalf("a denial says nothing a worker can act on: %v", c)
		}
	}
	// Neither a seat whose mandates name another effect type nor a seat with no
	// mandate has an active mandate for the effect.
	if unnamed["reason_code"] != "MANDATE_INACTIVE" || none["reason_code"] != "MANDATE_INACTIVE" {
		t.Fatalf("reasons: an unnamed effect type %v, no mandate %v", unnamed["reason_code"], none["reason_code"])
	}
	if e.adapter.dispatched.Load() != 0 || e.count(tenantA, `SELECT count(*) FROM authority_permits`) != 0 {
		t.Fatal("a denied call reached the provider or left a permit")
	}
	if n := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts WHERE state = 'DENIED' AND episode_id = 'ep-1'`); n != 3 {
		t.Fatalf("%d denied attempts recorded in the episode, want 3", n)
	}

	// Arguments that break the tool's schema never become an attempt: they are a
	// tool error the model can correct, not a denial.
	before := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`)
	for name, args := range map[string]map[string]any{
		"a missing schema constant": {"target": repoA, "arguments": map[string]any{}},
		"an unknown argument":       {"target": repoA, "arguments": map[string]any{"schema": "helm.github.repository.get.v1", "branch": "main", "repo": repoB}},
		"a target outside GitHub":   {"target": "gitlab.com/acme/app", "arguments": map[string]any{"schema": "helm.github.repository.get.v1"}},
		"no target":                 {"arguments": map[string]any{"schema": "helm.github.repository.get.v1"}},
	} {
		content, isError := e.callTool(t, tokenSeat1Ep1, "bad-"+name, "github_repository_get", args).structured(t)
		if !isError || content["status"] != "invalid" || content["attempt_id"] != nil {
			t.Errorf("%s: %v (error %v)", name, content, isError)
		}
	}
	if after := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`); after != before {
		t.Fatalf("invalid calls left %d attempts", after-before)
	}

	// An unknown tool is the protocol's error, not a tool's.
	e.callTool(t, tokenSeat1Ep1, "x", "github_nothing", map[string]any{}).rpcError(t, http.StatusOK, codeInvalidParams)
	// A disabled seat is denied like any attempt.
	must(t, e.rows.InTenant(context.Background(), tenantA, func(tx *authorityrows.Tx) error {
		_, err := tx.DisablePrincipal(context.Background(), "agt:seat-2")
		return err
	}))
	content, isError := e.callTool(t, tokenSeat2, "after-disable", "github_repository_get", getArgs(repoA)).structured(t)
	if !isError || content["status"] != "denied" || content["reason_code"] != "PRINCIPAL_INACTIVE" {
		t.Fatalf("a disabled seat = %v", content)
	}
}

func TestPostgresAnUnknownOutcomeIsReconcilingUntilItIsKnown(t *testing.T) {
	e := newEnv(t)
	e.adapter.script(
		func(adapters.Effect) adapters.DispatchResult {
			return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: "PROVIDER_ERROR"}
		},
		func(adapters.Effect) adapters.ObserveResult {
			return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
		})
	content, isError := e.callTool(t, tokenSeat1Ep1, "u-1", "github_repository_get", getArgs(repoA)).structured(t)
	if isError || content["status"] != "reconciling" || content["state"] != "UNKNOWN" || content["attempt_id"] == "" {
		t.Fatalf("an unknown outcome = %v (error %v)", content, isError)
	}
	id := content["attempt_id"].(string)
	// It is not a failure, and it is readable by the episode that made it.
	read, isError := e.callTool(t, tokenSeat1Ep1, "g-1", AttemptGetTool, map[string]any{"attempt_id": id}).structured(t)
	if isError || read["status"] != "reconciling" || read["attempt_id"] != id {
		t.Fatalf("helm_attempt_get = %v (error %v)", read, isError)
	}
	// The provider answers; the same call finds the outcome, and nothing is sent again.
	e.adapter.script(nil, nil)
	done, isError := e.callTool(t, tokenSeat1Ep1, "u-1", "github_repository_get", getArgs(repoA)).structured(t)
	if isError || done["status"] != "succeeded" || done["attempt_id"] != id || done["state"] != "RECONCILED" || e.adapter.dispatched.Load() != 1 {
		t.Fatalf("the reconciled call = %v, %d dispatched", done, e.adapter.dispatched.Load())
	}
	// A dispatch the provider refuses outright is an error with its reason.
	e.adapter.script(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: "PRECONDITION_FAILED", Detail: "no"}
	}, nil)
	failed, isError := e.callTool(t, tokenSeat1Ep1, "f-1", "github_repository_get", getArgs(repoA)).structured(t)
	if !isError || failed["status"] != "failed" || failed["reason_code"] != "PRECONDITION_FAILED" {
		t.Fatalf("a refused dispatch = %v", failed)
	}
}

func TestPostgresATokenOfAnotherTenantReachesNothingOfThisOne(t *testing.T) {
	e := newEnv(t)
	made, _ := e.callTool(t, tokenSeat1Ep1, "call-1", "github_repository_get", getArgs(repoA)).structured(t)
	id := made["attempt_id"].(string)

	// The same seat name, episode and request id under another tenant's token is
	// its own call: it cannot read the attempt, and does not replay it.
	foreign, isError := e.callTool(t, tokenTenantB, "g-1", AttemptGetTool, map[string]any{"attempt_id": id}).structured(t)
	never, _ := e.callTool(t, tokenTenantB, "g-2", AttemptGetTool, map[string]any{"attempt_id": "00000000-0000-7000-8000-000000000000"}).structured(t)
	if !isError || foreign["status"] != "not_found" || !reflect.DeepEqual(foreign, never) {
		t.Fatalf("another tenant's read = %v, want what no attempt at all gets: %v", foreign, never)
	}
	theirs, isError := e.callTool(t, tokenTenantB, "call-1", "github_repository_get", getArgs(repoA)).structured(t)
	if !isError || theirs["status"] != "denied" || theirs["attempt_id"] == id {
		t.Fatalf("another tenant's call = %v", theirs)
	}
	own, isError := e.callTool(t, tokenTenantB, "call-2", "github_repository_get", getArgs(repoB)).structured(t)
	if isError || own["status"] != "succeeded" || own["attempt_id"] == id {
		t.Fatalf("another tenant's own call = %v", own)
	}
	if a, b := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`), e.count(tenantB, `SELECT count(*) FROM authority_effect_attempts`); a != 1 || b != 2 {
		t.Fatalf("attempts: tenant A %d, tenant B %d", a, b)
	}
	if n := e.count(tenantB, `SELECT count(*) FROM authority_effect_attempts WHERE attempt_id = $1`, id); n != 0 {
		t.Fatal("tenant B sees tenant A's attempt")
	}
	// A token whose tenant has no authority rows at all is refused as a tenant
	// with nothing to act under, and leaves nothing.
	bare := admission.Caller{TenantID: "tenant-without-rows", WorkspaceID: workspace, PrincipalID: "agt:seat-1",
		Episode: &admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1"}}
	_, _, err := e.svc.Propose(context.Background(), bare, admission.ProposeInput{IdempotencyKey: "k", EffectType: effectargs.GitHubRepositoryGet,
		Target: repoA, Arguments: []byte(`{"schema":"helm.github.repository.get.v1"}`)})
	if err == nil {
		t.Fatal("a tenant with no authority rows proposed")
	}
}

func TestPostgresAnotherEpisodesAttemptIsNotFound(t *testing.T) {
	e := newEnv(t)
	first, _ := e.callTool(t, tokenSeat1Ep1, "call-1", "github_repository_get", getArgs(repoA)).structured(t)
	id := first["attempt_id"].(string)

	// Its own episode reads it, with either scope; another episode of the same
	// seat finds nothing, the same nothing an attempt that was never made gives.
	for _, token := range []string{tokenSeat1Ep1, tokenSeat1Ro} {
		got, isError := e.callTool(t, token, "g", AttemptGetTool, map[string]any{"attempt_id": id}).structured(t)
		if isError || got["status"] != "succeeded" || got["attempt_id"] != id {
			t.Fatalf("%s reading its own attempt: %v", token, got)
		}
	}
	other, isError := e.callTool(t, tokenSeat1Ep2, "g", AttemptGetTool, map[string]any{"attempt_id": id}).structured(t)
	never, _ := e.callTool(t, tokenSeat1Ep2, "g2", AttemptGetTool, map[string]any{"attempt_id": "00000000-0000-7000-8000-000000000000"}).structured(t)
	if !isError || other["status"] != "not_found" || !reflect.DeepEqual(other, never) {
		t.Fatalf("another episode's read = %v, want %v", other, never)
	}
	// Another seat of the same episode id has a different principal and reads none either.
	if got, isError := e.callTool(t, tokenSeat2, "g", AttemptGetTool, map[string]any{"attempt_id": id}).structured(t); !isError || got["status"] != "not_found" {
		t.Fatalf("another seat's read = %v", got)
	}

	// The same call id in another episode is another call, not a replay.
	second, _ := e.callTool(t, tokenSeat1Ep2, "call-1", "github_repository_get", getArgs(repoA)).structured(t)
	if second["attempt_id"] == id || second["status"] != "succeeded" {
		t.Fatalf("episode 2's call-1 = %v, episode 1's attempt was %s", second, id)
	}
	a2 := e.attempt(tenantA, second["attempt_id"].(string))
	if a2.IdempotencyKey == e.attempt(tenantA, id).IdempotencyKey || a2.Episode == nil || a2.Episode.EpisodeID != "ep-2" || a2.CaseID != "work-ep-2" {
		t.Fatalf("episode 2's attempt = %+v", a2)
	}
	if got, isError := e.callTool(t, tokenSeat1Ep1, "g", AttemptGetTool, map[string]any{"attempt_id": a2.ID}).structured(t); !isError || got["status"] != "not_found" {
		t.Fatalf("episode 1 reading episode 2's attempt = %v", got)
	}

	// A token that only reads cannot propose.
	denied, isError := e.callTool(t, tokenSeat1Ro, "p", "github_repository_get", getArgs(repoA)).structured(t)
	if !isError || denied["status"] != "denied" || denied["reason_code"] != "INSUFFICIENT_PRIVILEGE" || denied["attempt_id"] != nil {
		t.Fatalf("a read token proposing = %v", denied)
	}

	// The Control Plane, a service principal with read and no episode, sees both
	// episodes and can list either.
	cp := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: cpActor}
	for _, want := range []struct {
		episode string
		ids     []string
	}{{"ep-1", []string{id}}, {"ep-2", []string{a2.ID}}} {
		page, err := e.svc.List(context.Background(), cp, admission.ListInput{EpisodeID: want.episode, PageSize: 50})
		must(t, err)
		var got []string
		for _, a := range page.Attempts {
			got = append(got, a.ID)
		}
		if !reflect.DeepEqual(got, want.ids) {
			t.Fatalf("episode %s lists %v, want %v", want.episode, got, want.ids)
		}
	}
	if page, err := e.svc.List(context.Background(), cp, admission.ListInput{PageSize: 50}); err != nil || len(page.Attempts) != 2 {
		t.Fatalf("the Control Plane lists %d attempts, %v", len(page.Attempts), err)
	}
}

func TestPostgresAReplayedCallIsTheSameAttempt(t *testing.T) {
	e := newEnv(t)
	call := func(id any, args map[string]any) map[string]any {
		content, _ := e.callTool(t, tokenSeat1Ep1, id, "github_repository_get", args).structured(t)
		return content
	}
	first := call("r-1", getArgs(repoA))
	for i := 0; i < 3; i++ {
		if again := call("r-1", getArgs(repoA)); again["attempt_id"] != first["attempt_id"] || again["status"] != "succeeded" {
			t.Fatalf("replay %d = %v, want attempt %v", i, again, first["attempt_id"])
		}
	}
	if e.adapter.dispatched.Load() != 1 || e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != 1 {
		t.Fatalf("%d sent, %d attempts", e.adapter.dispatched.Load(), e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`))
	}

	// Clients may reuse ids after a completed request. Different content is a
	// new call, never a replay of the earlier effect.
	changed := call("r-1", map[string]any{"target": repoA, "arguments": map[string]any{"schema": "helm.github.repository.get.v1", "branch": "main"}})
	if changed["status"] != "succeeded" || changed["attempt_id"] == first["attempt_id"] {
		t.Fatalf("a changed request under the same id = %v", changed)
	}
	// Another id, the same request, is another call; so is the integer 1 against
	// the string "1".
	ids := map[any]bool{first["attempt_id"]: true, changed["attempt_id"]: true}
	for _, id := range []any{"r-2", 1, "1", -1} {
		content := call(id, getArgs(repoA))
		if content["status"] != "succeeded" || ids[content["attempt_id"]] {
			t.Fatalf("id %v = %v, want a new attempt", id, content)
		}
		ids[content["attempt_id"]] = true
	}
	if e.adapter.dispatched.Load() != 6 {
		t.Fatalf("%d sent, want 6", e.adapter.dispatched.Load())
	}

	// Concurrent replays of one call are one attempt sent once.
	var wg sync.WaitGroup
	results := make(chan map[string]any, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- call("race", getArgs(repoA))
		}()
	}
	wg.Wait()
	close(results)
	var attempt any
	for r := range results {
		if attempt == nil {
			attempt = r["attempt_id"]
		}
		if r["attempt_id"] != attempt || (r["status"] != "succeeded" && r["status"] != "reconciling") {
			t.Fatalf("a concurrent replay = %v", r)
		}
	}
	if e.adapter.dispatched.Load() != 7 {
		t.Fatalf("%d sent after the race, want 7", e.adapter.dispatched.Load())
	}
}

func TestPostgresTheEpisodeComesFromTheClaimNotTheBody(t *testing.T) {
	e := newEnv(t)
	before := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`)
	// Nothing a request says names an episode, a work item or a case: a field
	// for one is a malformed call, in the params, the tool arguments or the
	// effect's own arguments.
	params := func(args any, extra map[string]any) map[string]any {
		p := map[string]any{"name": "github_repository_get", "arguments": args}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	for name, p := range map[string]map[string]any{
		"an episode in the params":   params(getArgs(repoA), map[string]any{"episode_id": "ep-evil"}),
		"a work_ref in the params":   params(getArgs(repoA), map[string]any{"work_ref": map[string]any{"case_id": "work-evil"}}),
		"a case beside the target":   params(map[string]any{"target": repoA, "case_id": "work-evil", "arguments": map[string]any{"schema": "helm.github.repository.get.v1"}}, nil),
		"an episode beside it":       params(map[string]any{"target": repoA, "episode_id": "ep-evil", "arguments": map[string]any{"schema": "helm.github.repository.get.v1"}}, nil),
		"a case in the arguments":    params(map[string]any{"target": repoA, "arguments": map[string]any{"schema": "helm.github.repository.get.v1", "case_id": "work-evil"}}, nil),
		"a commitment in the params": params(getArgs(repoA), map[string]any{"commitment_id": "c-evil"}),
	} {
		r := e.modern(t, tokenSeat1Ep1, "x-"+name, "tools/call", p)
		rejected := r.Body["error"] != nil || (r.Body["result"] != nil && r.result(t)["isError"] == true)
		if !rejected {
			t.Errorf("%s was accepted: %v", name, r.Body)
		}
	}
	if after := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`); after != before {
		t.Fatalf("a malformed call left %d attempts", after-before)
	}

	// _meta is the client's own: what it says about an episode changes nothing.
	good := e.modern(t, tokenSeat1Ep1, "good", "tools/call", map[string]any{"name": "github_repository_get", "arguments": getArgs(repoA),
		"_extra_meta": map[string]any{"episode_id": "ep-evil", "work_item_id": "work-evil", "helm_episode": map[string]any{"episode_id": "ep-evil"}}})
	content, isError := good.structured(t)
	if isError || content["status"] != "succeeded" {
		t.Fatalf("call = %v", content)
	}
	a := e.attempt(tenantA, content["attempt_id"].(string))
	if a.Episode == nil || *a.Episode != (admission.Episode{EpisodeID: "ep-1", WorkItemID: "work-ep-1", OrganizationVersionID: "ver-1"}) ||
		a.CaseID != "work-ep-1" || a.CommitmentID != "" {
		t.Fatalf("the attempt records %+v, case %q: not the token's claim", a.Episode, a.CaseID)
	}
	var episode, version, caseID sql.NullString
	must(t, e.owner.QueryRow(`SELECT episode_id, organization_version_id, case_id FROM authority_effect_attempts WHERE attempt_id = $1`, a.ID).
		Scan(&episode, &version, &caseID))
	if episode.String != "ep-1" || version.String != "ver-1" || caseID.String != "work-ep-1" {
		t.Fatalf("row = %v %v %v", episode, version, caseID)
	}
	// Every attempt of the episode says so, whichever listing finds it.
	other := e.callTool(t, tokenSeat1Ep2, "good", "github_repository_get", getArgs(repoA))
	otherContent, _ := other.structured(t)
	if b := e.attempt(tenantA, otherContent["attempt_id"].(string)); b.Episode == nil || b.Episode.EpisodeID != "ep-2" || b.CaseID != "work-ep-2" {
		t.Fatalf("episode 2's attempt = %+v", b.Episode)
	}
	var attempts []string
	rows, err := e.owner.Query(`SELECT episode_id FROM authority_effect_attempts WHERE tenant_id = $1 ORDER BY episode_id`, tenantA)
	must(t, err)
	for rows.Next() {
		var id string
		must(t, rows.Scan(&id))
		attempts = append(attempts, id)
	}
	must(t, rows.Close())
	if !sort.StringsAreSorted(attempts) || !reflect.DeepEqual(attempts, []string{"ep-1", "ep-2"}) {
		t.Fatalf("episodes on the attempts = %v", attempts)
	}
}

func TestPostgresTheEndpointServesOnlyAgentsOfAnEpisode(t *testing.T) {
	e := newEnv(t)
	// A service principal or a human with an episode token is refused the tools
	// and the attempt reader alike, and leaves no attempt.
	for _, token := range []string{tokenService, tokenHuman} {
		for _, r := range []reply{
			e.callTool(t, token, 1, "github_repository_get", getArgs(repoA)),
			e.callTool(t, token, 2, AttemptGetTool, map[string]any{"attempt_id": "00000000-0000-7000-8000-000000000000"}),
		} {
			if r.Status != http.StatusForbidden {
				t.Errorf("%s: HTTP %d %v, want 403", token, r.Status, r.Body)
			}
		}
	}
	if e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != 0 || e.adapter.dispatched.Load() != 0 {
		t.Fatal("a principal that is not an agent made an attempt")
	}
	// The native client's probe without credentials learns to send them; a
	// token of the wrong kind learns nothing more.
	if r := e.modern(t, "", 1, "server/discover", nil); r.Status != http.StatusUnauthorized || r.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("an unauthenticated probe: HTTP %d", r.Status)
	}
	if r := e.post(t, tokenSeat1Ep1, nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); r.Status != http.StatusOK {
		t.Fatalf("a request with no version header is the oldest revision's: HTTP %d %v", r.Status, r.Body)
	}
}
