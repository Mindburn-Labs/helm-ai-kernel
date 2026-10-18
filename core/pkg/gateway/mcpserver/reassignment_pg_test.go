package mcpserver

// The signed executor token reaches the real MCP handler and PostgreSQL
// ledger. The grant installer sees native attempts and a native approval row;
// the Control Plane producer that prepares that row has its own integration.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/reassignment"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func signedReassignmentToken(t *testing.T, i *signedContinuationIssuer, seat, episode, profile, client string, claim map[string]any) string {
	t.Helper()
	audience := "helm-gateway-worker:proof"
	if profile == "executor" {
		audience = "helm-gateway-executor:proof"
	}
	claims := jwt.MapClaims{
		"iss": "helm-continuation-proof", "aud": audience, "sub": "agt:" + seat,
		"tenant_id": tenantA, "workspace_id": workspace, "act": map[string]string{"sub": cpActor},
		"scope": "helm.gateway.propose helm.gateway.read", "jti": "reassigned-" + uuid.NewString(),
		"iat": i.now.Unix(), "exp": i.now.Add(5 * time.Minute).Unix(),
		"helm_episode": map[string]string{"episode_id": episode, "work_item_id": "work-ep-1", "organization_version_id": "ver-1"},
	}
	if profile == "executor" {
		claims["helm_executor"] = map[string]string{"client": client}
	}
	if claim != nil {
		claims["helm_reassignment"] = claim
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "kid-continuation"
	raw, err := token.SignedString(i.key)
	must(t, err)
	return raw
}

func signedReassignmentServiceToken(t *testing.T, i *signedContinuationIssuer, subject, tenant, workspaceID, scope string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": "helm-continuation-proof", "aud": "helm-gateway-admin:proof", "sub": subject,
		"tenant_id": tenant, "workspace_id": workspaceID, "act": map[string]string{"sub": cpActor},
		"scope": scope, "jti": "reassignment-admin-" + uuid.NewString(),
		"iat": i.now.Unix(), "exp": i.now.Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "kid-continuation"
	raw, err := token.SignedString(i.key)
	must(t, err)
	return raw
}

func signedGrantManifest(t *testing.T, ids []string, now time.Time, profile, client, sourceActor string) ([]byte, map[string]any) {
	t.Helper()
	grant := map[string]any{
		"schema": effectargs.WorkReassignmentManifest, "reassignment_id": uuid.NewString(),
		"drain_digest": "sha256:" + strings.Repeat("a", 64), "org_ref": "org:one",
		"work_item_id": "work-ep-1", "organization_version_id": "ver-1", "commitment_id": "commit-1",
		"terms_digest": "sha256:" + strings.Repeat("c", 64), "plan_digest": strings.Repeat("b", 64),
		"authority_revision": 1, "expected_generation": 0, "generation": 1,
		"expires_at": now.Add(15 * time.Minute).UTC().Format(time.RFC3339Nano),
		"recipient": map[string]any{"episode_id": "ep-seat-2", "seat_id": "seat-2", "principal_id": "agt:seat-2",
			"actor_id": cpActor, "profile": profile, "client": client},
		"sources": []any{map[string]any{"episode_id": "ep-seat-1", "seat_id": "seat-1", "principal_id": "agt:seat-1",
			"actor_id": sourceActor, "profile": profile, "attempt_ids": ids}},
	}
	return encodeReassignmentManifest(t, grant), grant
}

func encodeReassignmentManifest(t *testing.T, grant map[string]any) []byte {
	t.Helper()
	delete(grant, "manifest_digest")
	raw, err := json.Marshal(grant)
	must(t, err)
	canonical, err := canonicalize.JCS(raw)
	must(t, err)
	sum := sha256.Sum256(canonical)
	grant["manifest_digest"] = "sha256:" + hex.EncodeToString(sum[:])
	raw, err = json.Marshal(grant)
	must(t, err)
	return raw
}

func seedReassignmentApproval(t *testing.T, e *env, raw []byte) adapters.Effect {
	t.Helper()
	ctx := context.Background()
	anchorID, grantAttemptID := uuid.NewString(), uuid.NewString()
	digest := sha256.Sum256(raw)
	var hasProvision bool
	must(t, e.owner.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM authority_provisions WHERE tenant_id = $1 AND org_ref = 'org:one')`, tenantA).Scan(&hasProvision))
	rows := []struct{ id, key, effect string }{{grantAttemptID, "approved-grant-" + grantAttemptID, effectargs.AuthorityWorkReassignmentGrant}}
	if !hasProvision {
		rows = append([]struct{ id, key, effect string }{{anchorID, "provision-anchor", effectargs.AuthorityProvision}}, rows...)
	}
	for _, row := range rows {
		_, err := e.owner.ExecContext(ctx, `INSERT INTO authority_effect_attempts
			(tenant_id, attempt_id, workspace_id, idempotency_key, request_digest, requester_principal_id,
			 requester_actor_id, effect_type, target, target_digest, argument_digest, state)
			VALUES ($1,$2,$3,$4,$5,'svc:compiler',$6,$7,'org:one',$5,$5,'DISPATCHING')`,
			tenantA, row.id, workspace, row.key, digest[:], cpActor, row.effect)
		must(t, err)
	}
	if !hasProvision {
		_, err := e.owner.ExecContext(ctx, `INSERT INTO authority_provisions
			(tenant_id, org_ref, plan_digest, version_ref, stage, nodes, principals, requested_by, attempt_id, revision)
			VALUES ($1,'org:one',$2,'ver-1','constrained-live','[]','[]','svc:compiler',$3,1)`,
			tenantA, strings.Repeat("b", 64), anchorID)
		must(t, err)
	}
	_, err := e.owner.ExecContext(ctx, `INSERT INTO authority_approvals
		(tenant_id, attempt_id, approver_principal_id, decision, approval_digest,
		 step_up_issuer, step_up_jti, step_up_method, step_up_proof)
		VALUES ($1,$2,'human-b','APPROVED',$3,'cp','stepup-grant','webauthn','signed-proof')`,
		tenantA, grantAttemptID, digest[:])
	must(t, err)
	return adapters.Effect{EffectType: effectargs.AuthorityWorkReassignmentGrant, Target: "org:one", Arguments: raw,
		Invocation: &adapters.Invocation{TenantID: tenantA, WorkspaceID: workspace,
			AttemptID: grantAttemptID, RequesterPrincipalID: "svc:compiler"}}
}

// A replay must not change the original attempt or any of its financial and
// authority rows. Compare full native rows so an UPDATE is caught as well as
// an unexpected INSERT.
func reassignmentLedgerSnapshot(t *testing.T, e *env) map[string]string {
	t.Helper()
	tables := []string{
		"authority_effect_attempts", "authority_permits", "authority_approvals",
		"authority_exposures", "authority_counters", "authority_postings",
		"authority_observations", "authority_reassignment_work",
		"authority_reassignment_grants", "authority_reassignment_members",
	}
	rows := make(map[string]string, len(tables))
	for _, table := range tables {
		query := `SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text)::text, '[]') FROM ` + table + ` x WHERE tenant_id = $1`
		var snapshot string
		must(t, e.owner.QueryRowContext(context.Background(), query, tenantA).Scan(&snapshot))
		rows[table] = snapshot
	}
	return rows
}

func TestPostgresSignedCrossSeatGrantReplaysOnlyNativeMembers(t *testing.T) {
	for _, profile := range []string{"worker", "executor"} {
		t.Run(profile, func(t *testing.T) { runPostgresSignedCrossSeatGrant(t, profile) })
	}
}

func runPostgresSignedCrossSeatGrant(t *testing.T, profile string) {
	e := newEnv(t)
	i := newSignedContinuationIssuer(t)
	client := ""
	if profile == "worker" {
		i.validator = jwks.NewJWKSValidator(jwks.JWKSConfig{
			JWKSURL: i.keysURL, Issuer: "helm-continuation-proof", Audience: "helm-gateway-worker:proof",
			Algorithms: []string{"RS256"}, RequiredActor: cpActor, RejectExecutor: true,
			MaxTokenTTL: 15 * time.Minute, AllowInsecureLoopback: true, Now: func() time.Time { return i.now },
		})
	} else {
		client = "codex"
	}
	e.auth.Validator = i.validator
	old := signedReassignmentToken(t, i, "seat-1", "ep-seat-1", profile, client, nil)
	first, failed := e.callTool(t, old, "first", "github_repository_get", getArgs(repoA)).structured(t)
	if failed {
		t.Fatalf("original call: %v", first)
	}
	otherArgs := map[string]any{"target": repoA, "arguments": map[string]any{"schema": "helm.github.repository.get.v1", "branch": "other"}}
	second, failed := e.callTool(t, old, "second", "github_repository_get", otherArgs).structured(t)
	if failed {
		t.Fatalf("second original call: %v", second)
	}
	firstID, secondID := first["attempt_id"].(string), second["attempt_id"].(string)
	installer, err := reassignment.New(e.runtime)
	must(t, err)

	// A manifest that omits one native work attempt cannot drain the source.
	omitted, _ := signedGrantManifest(t, []string{firstID}, i.now, profile, client, cpActor)
	omittedEffect := seedReassignmentApproval(t, e, omitted)
	d := sha256.Sum256(omitted)
	if got := installer.Dispatch(context.Background(), nil, omittedEffect, d[:]); got.Status != adapters.DispatchNotSent {
		t.Fatalf("incomplete native drain installed a grant: %+v", got)
	}

	raw, grant := signedGrantManifest(t, []string{firstID, secondID}, i.now, profile, client, cpActor)
	effect := seedReassignmentApproval(t, e, raw)
	admin := &server.AdminServer{Admission: e.svc, Auth: &server.Authenticator{
		Validator: jwks.NewJWKSValidator(jwks.JWKSConfig{
			JWKSURL: i.keysURL, Issuer: "helm-continuation-proof", Audience: "helm-gateway-admin:proof",
			Algorithms: []string{"RS256"}, RequiredActor: cpActor,
			MaxTokenTTL: 15 * time.Minute, AllowInsecureLoopback: true, Now: func() time.Time { return i.now },
		}), Actor: cpActor,
	}}
	serviceToken := signedReassignmentServiceToken(t, i, "svc:compiler", tenantA, workspace, "helm.gateway.read")
	readFence := func(token string) (*gatewayv1.GetCurrentWorkReassignmentResponse, error) {
		req := connect.NewRequest(&gatewayv1.GetCurrentWorkReassignmentRequest{OrgRef: "org:one", WorkItemId: "work-ep-1"})
		req.Header().Set("Authorization", "Bearer "+token)
		response, err := admin.GetCurrentWorkReassignment(context.Background(), req)
		if err != nil {
			return nil, err
		}
		return response.Msg, nil
	}
	beforeGrant, err := readFence(serviceToken)
	if err != nil || beforeGrant.GetPresent() || beforeGrant.GetGeneration() != 0 {
		t.Fatalf("native zero-generation read: %+v %v", beforeGrant, err)
	}
	d = sha256.Sum256(raw)
	if got := installer.Dispatch(context.Background(), nil, effect, d[:]); got.Status != adapters.DispatchSent {
		t.Fatalf("approved complete grant was not installed: %+v", got)
	}
	if got := installer.Observe(context.Background(), nil, effect); got.Outcome != adapters.OutcomeSucceeded {
		t.Fatalf("native grant readback: %+v", got)
	}
	current, err := readFence(serviceToken)
	if err != nil || !current.GetPresent() || current.GetGeneration() != 1 ||
		current.GetGrantId() != grant["reassignment_id"] || current.GetManifestDigest() != grant["manifest_digest"] ||
		current.GetGrantAttemptId() != effect.Invocation.AttemptID || current.GetRevoked() ||
		current.GetRecipientEpisodeId() != "ep-seat-2" || current.GetRecipientProfile() != profile {
		t.Fatalf("native current-generation read: %+v %v", current, err)
	}
	for _, refused := range []struct{ name, subject, tenant, workspaceID, scope string }{
		{"agent", "agt:seat-2", tenantA, workspace, "helm.gateway.read"},
		{"wrong scope", "svc:compiler", tenantA, workspace, "helm.gateway.propose"},
		{"foreign tenant", "svc:compiler", "tenant-b", workspace, "helm.gateway.read"},
	} {
		t.Run("fence read "+refused.name, func(t *testing.T) {
			token := signedReassignmentServiceToken(t, i, refused.subject, refused.tenant, refused.workspaceID, refused.scope)
			if result, err := readFence(token); err == nil || result != nil {
				t.Fatalf("unauthorized current fence read: %+v %v", result, err)
			}
		})
	}
	wrongWorkspace := signedReassignmentServiceToken(t, i, "svc:compiler", tenantA, "ws-b", "helm.gateway.read")
	isolated, err := readFence(wrongWorkspace)
	if err != nil || isolated.GetPresent() || isolated.GetGeneration() != 0 {
		t.Fatalf("another workspace saw this native fence: %+v %v", isolated, err)
	}
	oldIdentity, err := e.auth.Authenticate(context.Background(), http.Header{"Authorization": {"Bearer " + old}}, server.ScopePropose)
	must(t, err)
	beforeSourceRetry := e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`)
	_, _, err = e.svc.ProposeWorkEffect(context.Background(), oldIdentity.Caller, admission.ProposeInput{
		EffectType: effectargs.GitHubRepositoryGet, Target: repoA,
		Arguments: []byte(`{"schema":"helm.github.repository.get.v1","branch":"after-reassignment"}`),
	})
	if err == nil ||
		e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != beforeSourceRetry {
		t.Fatalf("the old seat admitted a new effect after the native grant: %v", err)
	}
	oldReplay, failed := e.callTool(t, old, "old-replay", "github_repository_get", getArgs(repoA)).structured(t)
	if !failed || oldReplay["status"] != "not_found" ||
		e.count(tenantA, `SELECT count(*) FROM authority_effect_attempts`) != beforeSourceRetry {
		t.Fatalf("the old seat replayed its original effect after reassignment: %v", oldReplay)
	}
	claim := map[string]any{
		"version": "helm.reassignment.v1", "grant_id": grant["reassignment_id"], "generation": 1,
		"manifest_digest": grant["manifest_digest"], "application_digest": "sha256:" + strings.Repeat("d", 64),
		"work_item_id": "work-ep-1", "recipient": grant["recipient"],
	}
	for _, forged := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"manifest digest", func(c map[string]any) { c["manifest_digest"] = "sha256:" + strings.Repeat("0", 64) }},
		{"generation", func(c map[string]any) { c["generation"] = 2 }},
	} {
		t.Run("forged "+forged.name, func(t *testing.T) {
			wrong := make(map[string]any, len(claim))
			for key, value := range claim {
				wrong[key] = value
			}
			forged.edit(wrong)
			token := signedReassignmentToken(t, i, "seat-2", "ep-seat-2", profile, client, wrong)
			got, failed := e.callTool(t, token, "wrong-grant", AttemptGetTool,
				map[string]any{"attempt_id": firstID}).structured(t)
			if !failed || got["status"] != "not_found" {
				t.Fatalf("signed but incorrect %s reached a retained result: %v", forged.name, got)
			}
		})
	}
	newToken := signedReassignmentToken(t, i, "seat-2", "ep-seat-2", profile, client, claim)
	beforeReplay := reassignmentLedgerSnapshot(t, e)
	oldDispatches := e.adapter.dispatched.Load()
	replayed, failed := e.callTool(t, newToken, "replay", "github_repository_get", getArgs(repoA)).structured(t)
	if failed || replayed["attempt_id"] != firstID || e.adapter.dispatched.Load() != oldDispatches {
		t.Fatalf("cross-seat replay did not return the old result without dispatch: %v", replayed)
	}
	initialized := e.legacy(t, newToken, "", "legacy-init", "initialize", map[string]any{
		"protocolVersion": "2025-11-25", "capabilities": map[string]any{},
		"clientInfo": map[string]string{"name": "recipient", "version": "1"},
	})
	if initialized.Status != http.StatusOK {
		t.Fatalf("legacy recipient initialization: %d %v", initialized.Status, initialized.Body)
	}
	legacy, failed := e.legacy(t, newToken, "2025-11-25", "legacy-replay", "tools/call",
		map[string]any{"name": "github_repository_get", "arguments": getArgs(repoA)}).structured(t)
	if failed || legacy["attempt_id"] != firstID || e.adapter.dispatched.Load() != oldDispatches {
		t.Fatalf("legacy cross-seat replay dispatched or changed the attempt: %v", legacy)
	}
	if afterReplay := reassignmentLedgerSnapshot(t, e); !reflect.DeepEqual(beforeReplay, afterReplay) {
		for table, before := range beforeReplay {
			if afterReplay[table] != before {
				t.Errorf("cross-seat replay changed native %s rows", table)
			}
		}
		t.FailNow()
	}
	changed, _ := e.callTool(t, newToken, "changed-intent", "github_repository_get",
		map[string]any{"target": repoA, "arguments": map[string]any{
			"schema": "helm.github.repository.get.v1", "branch": "changed"}}).structured(t)
	if changed["attempt_id"] == firstID || changed["attempt_id"] == secondID {
		t.Fatalf("changed intent reused an original attempt: %v", changed)
	}
	missing, failed := e.callTool(t, newToken, "unlisted", AttemptGetTool,
		map[string]any{"attempt_id": uuid.NewString()}).structured(t)
	if !failed || missing["status"] != "not_found" {
		t.Fatalf("an unlisted attempt was exposed: %v", missing)
	}
	identity, err := e.auth.Authenticate(context.Background(), http.Header{"Authorization": {"Bearer " + newToken}}, server.ScopeRead)
	must(t, err)
	missingProfile := identity.Caller
	episodeCopy := *missingProfile.Episode
	episodeCopy.Profile = ""
	missingProfile.Episode = &episodeCopy
	if _, err := e.svc.GetReassignment(context.Background(), missingProfile, firstID); err == nil {
		t.Fatal("a reassignment caller without the exact verified listener profile read history")
	}
	if _, err := e.svc.Get(context.Background(), identity.Caller, firstID); err == nil {
		t.Fatal("ordinary Get widened across seats")
	}
	if _, err := e.svc.GetContent(context.Background(), identity.Caller, firstID); err == nil {
		t.Fatal("ordinary GetContent widened across seats")
	}
	api := &server.Server{Admission: e.svc, Auth: e.auth}
	attemptReq := connect.NewRequest(&gatewayv1.GetAttemptRequest{AttemptId: firstID})
	attemptReq.Header().Set("Authorization", "Bearer "+newToken)
	attemptResp, err := api.GetAttempt(context.Background(), attemptReq)
	if err != nil || attemptResp.Msg.GetAttempt().GetAttemptId() != firstID {
		t.Fatalf("signed Connect status read: %+v %v", attemptResp, err)
	}
	contentReq := connect.NewRequest(&gatewayv1.GetAttemptContentRequest{AttemptId: firstID})
	contentReq.Header().Set("Authorization", "Bearer "+newToken)
	if _, err := api.GetAttemptContent(context.Background(), contentReq); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("reassignment exposed content: %v", err)
	}
	_, err = e.owner.Exec(`UPDATE authority_provisions SET revision = 2 WHERE tenant_id = $1 AND org_ref = 'org:one'`, tenantA)
	must(t, err)
	stale, failed := e.callTool(t, newToken, "stale-plan", "github_repository_get", getArgs(repoA)).structured(t)
	if !failed || stale["status"] != "not_found" {
		t.Fatalf("a stale organization binding retained access: %v", stale)
	}
	_, err = e.owner.Exec(`UPDATE authority_provisions SET revision = 1 WHERE tenant_id = $1 AND org_ref = 'org:one'`, tenantA)
	must(t, err)
	stopID := uuid.NewString()
	_, err = e.owner.Exec(`INSERT INTO authority_stops
		(tenant_id, stop_id, scope_kind, scope_key, reason, issued_by)
		VALUES ($1,$2,'principal','agt:seat-2','reassignment proof','human-a')`, tenantA, stopID)
	must(t, err)
	stopped, failed := e.callTool(t, newToken, "stopped", "github_repository_get", getArgs(repoA)).structured(t)
	if !failed || stopped["reason_code"] != "EMERGENCY_STOP_FENCED" {
		t.Fatalf("a stopped recipient retained access: %v", stopped)
	}
	_, err = e.owner.Exec(`UPDATE authority_stops
		SET lifted_at = now(), lift_requested_by = 'human-a', lift_approved_by = 'human-b'
		WHERE tenant_id = $1 AND stop_id = $2`, tenantA, stopID)
	must(t, err)

	revoke := map[string]any{"schema": effectargs.AuthorityWorkReassignmentRevoke, "org_ref": "org:one",
		"grant_id": grant["reassignment_id"], "generation": 1, "reason": "source drain closed"}
	revokeRaw, err := json.Marshal(revoke)
	must(t, err)
	revokeAttemptID := uuid.NewString()
	revokeEffect := adapters.Effect{EffectType: effectargs.AuthorityWorkReassignmentRevoke, Target: "org:one", Arguments: revokeRaw,
		Invocation: &adapters.Invocation{TenantID: tenantA, WorkspaceID: workspace,
			AttemptID: revokeAttemptID, RequesterPrincipalID: "svc:compiler"}}
	d = sha256.Sum256(revokeRaw)
	if got := installer.Dispatch(context.Background(), nil, revokeEffect, d[:]); got.Status != adapters.DispatchSent {
		t.Fatalf("revocation was not committed: %+v", got)
	}
	if got := installer.Observe(context.Background(), nil, revokeEffect); got.Outcome != adapters.OutcomeSucceeded {
		t.Fatalf("revocation readback: %+v", got)
	}
	revokedFence, err := readFence(serviceToken)
	if err != nil || !revokedFence.GetPresent() || revokedFence.GetGeneration() != 1 ||
		revokedFence.GetGrantId() != grant["reassignment_id"] || !revokedFence.GetRevoked() ||
		revokedFence.GetRevokedByAttemptId() != revokeAttemptID || revokedFence.GetRevokedAt() == nil {
		t.Fatalf("revocation lost the high-water work fence: %+v %v", revokedFence, err)
	}
	denied, failed := e.callTool(t, newToken, "after-revoke", "github_repository_get", getArgs(repoA)).structured(t)
	if !failed || denied["status"] != "not_found" {
		t.Fatalf("revoked successor retained an old result: %v", denied)
	}
}

func TestPostgresEmptyDrainGrantsNoRetainedHistory(t *testing.T) {
	e := newEnv(t)
	i := newSignedContinuationIssuer(t)
	i.validator = jwks.NewJWKSValidator(jwks.JWKSConfig{
		JWKSURL: i.keysURL, Issuer: "helm-continuation-proof", Audience: "helm-gateway-worker:proof",
		Algorithms: []string{"RS256"}, RequiredActor: cpActor, RejectExecutor: true,
		MaxTokenTTL: 15 * time.Minute, AllowInsecureLoopback: true, Now: func() time.Time { return i.now },
	})
	e.auth.Validator = i.validator
	raw, grant := signedGrantManifest(t, []string{}, i.now, "worker", "", "")
	effect := seedReassignmentApproval(t, e, raw)
	installer, err := reassignment.New(e.runtime)
	must(t, err)
	digest := sha256.Sum256(raw)
	if got := installer.Dispatch(context.Background(), nil, effect, digest[:]); got.Status != adapters.DispatchSent {
		t.Fatalf("complete native zero drain was refused: %+v", got)
	}
	if members := e.count(tenantA, `SELECT count(*) FROM authority_reassignment_members`); members != 0 {
		t.Fatalf("an empty drain acquired %d retained members", members)
	}
	claim := map[string]any{
		"version": "helm.reassignment.v1", "grant_id": grant["reassignment_id"], "generation": 1,
		"manifest_digest": grant["manifest_digest"], "application_digest": "sha256:" + strings.Repeat("d", 64),
		"work_item_id": "work-ep-1", "recipient": grant["recipient"],
	}
	newToken := signedReassignmentToken(t, i, "seat-2", "ep-seat-2", "worker", "", claim)
	missing, failed := e.callTool(t, newToken, "no-history", AttemptGetTool,
		map[string]any{"attempt_id": uuid.NewString()}).structured(t)
	if !failed || missing["status"] != "not_found" {
		t.Fatalf("zero membership exposed retained history: %v", missing)
	}
	old := signedReassignmentToken(t, i, "seat-1", "ep-seat-1", "worker", "", nil)
	oldCall, failed := e.callTool(t, old, "old-after-empty-drain", "github_repository_get", getArgs(repoA)).structured(t)
	if !failed || oldCall["status"] != "not_found" {
		t.Fatalf("the original seat created work after the empty drain: %v", oldCall)
	}
	fresh, failed := e.callTool(t, newToken, "new-intent", "github_repository_get", getArgs(repoA)).structured(t)
	if failed || fresh["attempt_id"] == nil || e.count(tenantA, `SELECT count(*) FROM authority_reassignment_members`) != 0 {
		t.Fatalf("the recipient's current new admission failed or gained history: %v", fresh)
	}
}

func TestPostgresRecoveryNamesTheExactRevokedGrantNotAnAttempt(t *testing.T) {
	e := newEnv(t)
	i := newSignedContinuationIssuer(t)
	installer, err := reassignment.New(e.runtime)
	must(t, err)
	raw, first := signedGrantManifest(t, nil, i.now, "worker", "", "")
	firstEffect := seedReassignmentApproval(t, e, raw)
	digest := sha256.Sum256(raw)
	if got := installer.Dispatch(context.Background(), nil, firstEffect, digest[:]); got.Status != adapters.DispatchSent {
		t.Fatalf("first native grant was not installed: %+v", got)
	}
	firstID := first["reassignment_id"].(string)
	firstAttemptID := firstEffect.Invocation.AttemptID
	revokeAttemptID := uuid.NewString()
	if firstID == firstAttemptID || firstID == revokeAttemptID || firstAttemptID == revokeAttemptID {
		t.Fatal("grant, grant attempt and revoke attempt must be distinct identities")
	}
	revoke := map[string]any{"schema": effectargs.AuthorityWorkReassignmentRevoke, "org_ref": "org:one",
		"grant_id": firstID, "generation": 1, "reason": "recover queued work"}
	revokeRaw, err := json.Marshal(revoke)
	must(t, err)
	revokeEffect := adapters.Effect{EffectType: effectargs.AuthorityWorkReassignmentRevoke, Target: "org:one", Arguments: revokeRaw,
		Invocation: &adapters.Invocation{TenantID: tenantA, WorkspaceID: workspace,
			AttemptID: revokeAttemptID, RequesterPrincipalID: "svc:compiler"}}
	digest = sha256.Sum256(revokeRaw)
	if got := installer.Dispatch(context.Background(), nil, revokeEffect, digest[:]); got.Status != adapters.DispatchSent {
		t.Fatalf("native orphan revoke failed: %+v", got)
	}
	if got := installer.Observe(context.Background(), nil, revokeEffect); got.Outcome != adapters.OutcomeSucceeded {
		t.Fatalf("native orphan revoke readback failed: %+v", got)
	}
	second := func(predecessor string) (string, adapters.DispatchResult) {
		candidate := map[string]any{
			"schema": effectargs.WorkReassignmentManifest, "reassignment_id": uuid.NewString(),
			"drain_digest": first["drain_digest"], "org_ref": "org:one",
			"work_item_id": "work-ep-1", "organization_version_id": "ver-1", "commitment_id": "commit-1",
			"terms_digest": first["terms_digest"], "plan_digest": first["plan_digest"],
			"authority_revision": 1, "expected_generation": 1, "generation": 2,
			"expires_at": i.now.Add(15 * time.Minute).UTC().Format(time.RFC3339Nano),
			"recipient": map[string]any{"episode_id": "ep-seat-3", "seat_id": "seat-1", "principal_id": "agt:seat-1",
				"actor_id": cpActor, "profile": "worker", "client": ""},
			"sources": []any{map[string]any{"episode_id": "ep-seat-2", "seat_id": "seat-2",
				"principal_id": "agt:seat-2", "actor_id": cpActor, "profile": "worker", "attempt_ids": []string{}}},
		}
		if predecessor != "" {
			candidate["predecessor_reassignment_id"] = predecessor
		}
		body := encodeReassignmentManifest(t, candidate)
		effect := seedReassignmentApproval(t, e, body)
		bodyDigest := sha256.Sum256(body)
		return candidate["reassignment_id"].(string), installer.Dispatch(context.Background(), nil, effect, bodyDigest[:])
	}
	if _, got := second(""); got.Status != adapters.DispatchNotSent {
		t.Fatalf("a revoked predecessor was silently omitted: %+v", got)
	}
	if _, got := second(firstAttemptID); got.Status != adapters.DispatchNotSent {
		t.Fatalf("the grant attempt ID was accepted as predecessor: %+v", got)
	}
	if _, got := second(revokeAttemptID); got.Status != adapters.DispatchNotSent {
		t.Fatalf("the revoke attempt ID was accepted as predecessor: %+v", got)
	}
	secondID, got := second(firstID)
	if got.Status != adapters.DispatchSent || secondID == firstID || secondID == firstAttemptID || secondID == revokeAttemptID {
		t.Fatalf("exact revoked grant recovery did not install a distinct generation: %s %+v", secondID, got)
	}
	var generation int64
	var currentID, revokedBy string
	must(t, e.owner.QueryRow(`SELECT generation, grant_id::text FROM authority_reassignment_work
		WHERE tenant_id = $1 AND workspace_id = $2 AND work_item_id = 'work-ep-1'`, tenantA, workspace).
		Scan(&generation, &currentID))
	must(t, e.owner.QueryRow(`SELECT revoked_by FROM authority_reassignment_grants
		WHERE tenant_id = $1 AND grant_id = $2`, tenantA, firstID).Scan(&revokedBy))
	if generation != 2 || currentID != secondID || revokedBy != revokeAttemptID {
		t.Fatalf("native recovery identity or high-water generation changed: generation=%d grant=%s revoked_by=%s",
			generation, currentID, revokedBy)
	}
}
