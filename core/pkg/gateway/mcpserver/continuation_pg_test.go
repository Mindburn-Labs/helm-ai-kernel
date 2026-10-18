package mcpserver

// quantum_posture: proof tokens use classical RS256 signatures; no
// post-quantum signature is claimed.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

type signedContinuationIssuer struct {
	key       *rsa.PrivateKey
	keysURL   string
	now       time.Time
	validator *jwks.JWKSValidator
}

func newSignedContinuationIssuer(t *testing.T) *signedContinuationIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "kid-continuation", Use: "sig", Algorithm: "RS256"}}})
	must(t, err)
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(keys.Close)
	i := &signedContinuationIssuer{key: key, keysURL: keys.URL, now: time.Now().UTC().Truncate(time.Second)}
	i.validator = jwks.NewJWKSValidator(jwks.JWKSConfig{
		JWKSURL: keys.URL, Issuer: "helm-continuation-proof", Audience: "helm-gateway-executor:proof",
		Algorithms: []string{"RS256"}, RequiredActor: cpActor, RequireExecutor: true,
		MaxTokenTTL: 15 * time.Minute, AllowInsecureLoopback: true, Now: func() time.Time { return i.now },
	})
	return i
}

func (i *signedContinuationIssuer) token(t *testing.T, episodeID, client string, issued, expires time.Time, grant any) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": "helm-continuation-proof", "aud": "helm-gateway-executor:proof", "sub": "agt:seat-1",
		"tenant_id": tenantA, "workspace_id": workspace, "act": map[string]string{"sub": cpActor},
		"scope": "helm.gateway.propose helm.gateway.read", "jti": "jti-" + episodeID,
		"iat": issued.Unix(), "exp": expires.Unix(),
		"helm_executor": map[string]string{"client": client},
		"helm_episode":  map[string]string{"episode_id": episodeID, "work_item_id": "work-ep-1", "organization_version_id": "ver-1"},
	}
	if grant != nil {
		claims["helm_continuation"] = grant
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "kid-continuation"
	raw, err := token.SignedString(i.key)
	must(t, err)
	if len(raw) > 8192 {
		t.Fatalf("signed executor token exceeds the issuer's 8192-byte cap: %d", len(raw))
	}
	return raw
}

func continuationGrant(i *signedContinuationIssuer, id string, oldExpiry time.Time) map[string]any {
	return map[string]any{
		"version": "helm.continuation.v1", "handoff_ref": "cp:executor-continuation:00000000-0000-7000-8000-000000000010",
		"receipt_digest": "sha256:" + strings.Repeat("a", 64), "commitment_id": "commit-1",
		"plan_digest": strings.Repeat("b", 64), "authority_revision": 1, "terms_digest": "sha256:" + strings.Repeat("c", 64),
		"handoff_recorded_at": i.now.Format(time.RFC3339Nano),
		"tenant_id":           tenantA, "workspace_id": workspace, "organization_id": "org-1",
		"work_item_id": "work-ep-1", "organization_version_id": "ver-1",
		"successor": map[string]string{"episode_id": "ep-new", "seat_id": "seat-1", "principal_id": "agt:seat-1", "actor_id": cpActor},
		"sources": []any{map[string]any{"episode_id": "ep-old", "seat_id": "seat-1", "principal_id": "agt:seat-1", "actor_id": cpActor,
			"admissible_until": oldExpiry.Add(30 * time.Second).Format(time.RFC3339),
			"settled_before":   oldExpiry.Add(35 * time.Second).Format(time.RFC3339), "attempt_ids": []string{id}}},
	}
}

// The signed successor sees only the exact old attempt, never acquires its
// permit, and can recover it after a new gateway instance starts on the same
// database. The proof uses a logical JWT clock to make the old bearer expire.
func TestPostgresSignedContinuationReplaysOnlyCommittedAttempts(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "observed", true: "unknown"}[pending], func(t *testing.T) {
			e := newEnv(t)
			i := newSignedContinuationIssuer(t)
			e.auth.Validator = i.validator
			oldExpiry := i.now.Add(time.Minute)
			old := i.token(t, "ep-old", "claude-code", i.now, oldExpiry, nil)
			if pending {
				e.adapter.script(func(adapters.Effect) adapters.DispatchResult {
					return adapters.DispatchResult{Status: adapters.DispatchIndefinite}
				},
					func(adapters.Effect) adapters.ObserveResult {
						return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
					})
			}
			first, failed := e.callTool(t, old, "old-call", "github_repository_get", getArgs(repoA)).structured(t)
			if failed {
				t.Fatalf("old call = %v", first)
			}
			id := first["attempt_id"].(string)
			otherArgs := map[string]any{"target": repoA, "arguments": map[string]any{"schema": "helm.github.repository.get.v1", "branch": "other"}}
			other, failed := e.callTool(t, old, "other-call", "github_repository_get", otherArgs).structured(t)
			if failed || other["attempt_id"] == id {
				t.Fatalf("separate old intent = %v", other)
			}
			dispatches, observes := e.adapter.dispatched.Load(), e.adapter.observed.Load()
			i.now = oldExpiry.Add(40 * time.Second)
			if got := e.modern(t, old, "expired", "tools/list", nil); got.Status != http.StatusUnauthorized {
				t.Fatalf("old bearer remained valid: %d %v", got.Status, got.Body)
			}
			plain := i.token(t, "ep-new", "codex", i.now, i.now.Add(5*time.Minute), nil)
			denied, failed := e.callTool(t, plain, "unproven", "github_repository_get", getArgs(repoA)).structured(t)
			if !failed || denied["status"] != "not_found" {
				t.Fatalf("unproven replay exposed old attempt: %v", denied)
			}
			grant := continuationGrant(i, id, oldExpiry)
			newToken := i.token(t, "ep-new", "codex", i.now, i.now.Add(5*time.Minute), grant)
			got, failed := e.callTool(t, newToken, "new-call", "github_repository_get", getArgs(repoA)).structured(t)
			if failed || got["attempt_id"] != id || got["status"] != first["status"] {
				t.Fatalf("signed replay = %v, first = %v", got, first)
			}
			unlisted, failed := e.callTool(t, newToken, "unlisted", "github_repository_get", otherArgs).structured(t)
			if !failed || unlisted["status"] != "not_found" {
				t.Fatalf("unlisted predecessor was exposed: %v", unlisted)
			}
			wrongActor := continuationGrant(i, id, oldExpiry)
			wrongActor["sources"].([]any)[0].(map[string]any)["actor_id"] = "spiffe://other"
			wrongActorToken := i.token(t, "ep-new", "codex", i.now, i.now.Add(5*time.Minute), wrongActor)
			actorLeak, failed := e.callTool(t, wrongActorToken, "wrong-actor", "github_repository_get", getArgs(repoA)).structured(t)
			if !failed || actorLeak["status"] != "not_found" {
				t.Fatalf("wrong source actor reached an attempt: %v", actorLeak)
			}
			read, failed := e.callTool(t, newToken, "read", AttemptGetTool, map[string]any{"attempt_id": id}).structured(t)
			if failed || read["attempt_id"] != id {
				t.Fatalf("listed predecessor read = %v", read)
			}
			head := http.Header{"Authorization": []string{"Bearer " + newToken}}
			identity, err := e.auth.Authenticate(context.Background(), head, server.ScopePropose)
			must(t, err)
			if _, err := e.svc.Get(context.Background(), identity.Caller, id); err == nil {
				t.Fatal("ordinary Get widened to a predecessor")
			}
			if _, err := e.svc.GetContent(context.Background(), identity.Caller, id); err == nil {
				t.Fatal("ordinary GetContent widened to a predecessor")
			}
			content, err := e.svc.GetContentContinuation(context.Background(), identity.Caller, id)
			if err != nil || !strings.Contains(string(content), "helm.github.repository.get.v1") {
				t.Fatalf("bounded content recovery: %s %v", content, err)
			}
			api := &server.Server{Admission: e.svc, Auth: e.auth}
			attemptReq := connect.NewRequest(&gatewayv1.GetAttemptRequest{AttemptId: id})
			attemptReq.Header().Set("Authorization", "Bearer "+newToken)
			attemptResp, err := api.GetAttempt(context.Background(), attemptReq)
			if err != nil || attemptResp.Msg.GetAttempt().GetAttemptId() != id {
				t.Fatalf("signed Connect predecessor read: %+v %v", attemptResp, err)
			}
			contentReq := connect.NewRequest(&gatewayv1.GetAttemptContentRequest{AttemptId: id})
			contentReq.Header().Set("Authorization", "Bearer "+newToken)
			contentResp, err := api.GetAttemptContent(context.Background(), contentReq)
			if err != nil || string(contentResp.Msg.GetArguments()) != string(content) {
				t.Fatalf("signed Connect predecessor content: %+v %v", contentResp, err)
			}
			unlistedContent := connect.NewRequest(&gatewayv1.GetAttemptContentRequest{AttemptId: other["attempt_id"].(string)})
			unlistedContent.Header().Set("Authorization", "Bearer "+newToken)
			if _, err := api.GetAttemptContent(context.Background(), unlistedContent); connect.CodeOf(err) != connect.CodeNotFound {
				t.Fatalf("unlisted predecessor reached Connect content: %v", err)
			}
			if _, err := e.svc.GetContentContinuation(context.Background(), identity.Caller, other["attempt_id"].(string)); err == nil {
				t.Fatal("an unlisted predecessor's content was exposed")
			}
			_, _, err = e.svc.ProposeWorkEffect(context.Background(), identity.Caller, admission.ProposeInput{
				EffectType: "github.repository.get", Target: repoA, Arguments: []byte(`{"schema":"helm.github.repository.get.v1"}`),
				Quote: []admission.Amount{{Unit: "usd_micros", Amount: 1}},
			})
			var refusal *admission.Error
			if !errors.As(err, &refusal) || refusal.Code != admission.CodeNotFound {
				t.Fatalf("changed quote replay = %v, want a hidden predecessor", err)
			}
			if e.adapter.dispatched.Load() != dispatches || e.adapter.observed.Load() != observes ||
				e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != 2 {
				t.Fatal("replay created an attempt or reached the adapter")
			}
			// A fresh admission service over the same PostgreSQL state recovers
			// the same immutable attempt without any process-local handoff map.
			restarted, err := admission.New(e.runtime, admission.Config{Adapters: []adapters.Adapter{e.adapter}, Credentials: fakeCredentials{}})
			must(t, err)
			e.svc = restarted
			e.srv.Close()
			gw, err := NewGateway(restarted, []adapters.Adapter{e.adapter})
			must(t, err)
			e.srv = httptest.NewServer(&Handler{Backend: gw, Version: "test", Authenticate: func(ctx context.Context, header http.Header) (Caller, error) {
				id, err := e.auth.Authenticate(ctx, header, server.ScopePropose, server.ScopeRead)
				if err != nil {
					return Caller{}, err
				}
				return Caller{Caller: id.Caller, Scope: id.Scope}, nil
			}})
			t.Cleanup(e.srv.Close)
			again, failed := e.callTool(t, newToken, "after-restart", "github_repository_get", getArgs(repoA)).structured(t)
			if failed || again["attempt_id"] != id || e.adapter.dispatched.Load() != dispatches {
				t.Fatalf("restart replay = %v", again)
			}
			freshArgs := map[string]any{"target": repoA, "arguments": map[string]any{"schema": "helm.github.repository.get.v1", "branch": "fresh"}}
			fresh, failed := e.callTool(t, newToken, "fresh-intent", "github_repository_get", freshArgs).structured(t)
			if failed || fresh["attempt_id"] == id || e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != 3 {
				t.Fatalf("a new successor intent did not create a new attempt: %v", fresh)
			}
			must(t, e.rows.InTenant(context.Background(), tenantA, func(tx *authorityrows.Tx) error {
				_, err := tx.DisablePrincipal(context.Background(), "agt:seat-1")
				return err
			}))
			if _, err := e.svc.GetContinuation(context.Background(), identity.Caller, id); !errors.As(err, &refusal) || refusal.Code != admission.CodePermissionDenied {
				t.Fatalf("disabled seat kept its continuation read: %v", err)
			}
		})
	}
}

func TestPostgresSignedContinuationKeepsTheOriginalEscalation(t *testing.T) {
	e := newEnv(t)
	i := newSignedContinuationIssuer(t)
	e.auth.Validator = i.validator
	oldExpiry := i.now.Add(time.Minute)
	old := i.token(t, "ep-old", "claude-code", i.now, oldExpiry, nil)
	first, failed := e.callTool(t, old, "old-approval", "github_branch_create_from_changes", branchCall(repoA, "helm/one")).structured(t)
	if failed || first["status"] != "escalated" {
		t.Fatalf("original escalation = %v", first)
	}
	id := first["attempt_id"].(string)
	original := e.attempt(tenantA, id)
	if len(original.ApprovalDigest) == 0 || original.Episode == nil || original.Episode.EpisodeID != "ep-old" {
		t.Fatalf("original escalation binding = %+v", original)
	}
	i.now = oldExpiry.Add(40 * time.Second)
	newToken := i.token(t, "ep-new", "codex", i.now, i.now.Add(5*time.Minute), continuationGrant(i, id, oldExpiry))
	again, failed := e.callTool(t, newToken, "new-approval", "github_branch_create_from_changes", branchCall(repoA, "helm/one")).structured(t)
	if failed || again["status"] != "escalated" || again["attempt_id"] != id {
		t.Fatalf("signed escalation replay = %v", again)
	}
	if e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != 1 ||
		e.count(tenantA, `SELECT count(*) FROM authority_approvals`) != 0 || e.adapter.dispatched.Load() != 0 {
		t.Fatal("replay duplicated or dispatched the original escalation")
	}
	approver := admission.Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "human-b", ActorID: cpActor}
	_, _, err := e.svc.Approve(context.Background(), approver, admission.Token{
		Issuer: "helm-continuation-proof", ID: "jti-original-approval", Scope: server.ScopeDecide,
		ExpiresAt: time.Now().Add(time.Minute),
	}, admission.DecideInput{AttemptID: id, ApprovalDigest: original.ApprovalDigest, Reason: "ok"})
	must(t, err)
	after, failed := e.callTool(t, newToken, "after-approval", "github_branch_create_from_changes", branchCall(repoA, "helm/one")).structured(t)
	if failed || after["state"] != "ADMITTED" || after["attempt_id"] != id || e.adapter.dispatched.Load() != 0 {
		t.Fatalf("replay consumed the original CP resume permit: %v", after)
	}
	if e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != 1 ||
		e.count(tenantA, `SELECT count(*) FROM authority_approvals`) != 1 ||
		e.count(tenantA, `SELECT count(*) FROM authority_permits`) != 1 {
		t.Fatal("the original approval or hold was duplicated")
	}
	newIntent, failed := e.callTool(t, newToken, "distinct-intent", "github_branch_create_from_changes", branchCall(repoA, "helm/two")).structured(t)
	if failed || newIntent["attempt_id"] == id || e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != 2 {
		t.Fatalf("a distinct successor intent did not enter new admission: %v", newIntent)
	}
}
