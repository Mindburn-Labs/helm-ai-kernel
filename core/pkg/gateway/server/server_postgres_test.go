package server

// The gateway effect API on the wire, against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): a JWKS issuer signs ADR-0005 tokens, a
// Connect client calls the handler, and every refusal carries its
// ErrorDetail.
//
// quantum_posture: signs classical RS256 test tokens and computes SHA-256
// digests; no post-quantum claim.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

const (
	testIssuer   = "https://control-plane.test"
	testAudience = "helm-gateway:test"
	testRepo     = "github.com/Mindburn-Labs/example"
)

type issuer struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(server.Close)
	return &issuer{key: key, server: server}
}

type tokenClaims struct {
	Scope       string `json:"scope"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Act         *struct {
		Sub string `json:"sub"`
	} `json:"act,omitempty"`
	AuthorizationDetails []map[string]string `json:"authorization_details,omitempty"`
	jwt.RegisteredClaims
}

func (i *issuer) token(t *testing.T, audience, tenant, principal, scope string, edit ...func(*tokenClaims)) string {
	t.Helper()
	now := time.Now()
	claims := tokenClaims{
		Scope: scope, TenantID: tenant, WorkspaceID: "ws-a",
		Act: &struct {
			Sub string `json:"sub"`
		}{Sub: testActor},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: testIssuer, Audience: jwt.ClaimStrings{audience}, Subject: principal,
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
			ID: fmt.Sprintf("jti-%d", now.UnixNano()),
		},
	}
	for _, e := range edit {
		e(&claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "k1"
	signed, err := token.SignedString(i.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (i *issuer) validator() *jwks.JWKSValidator {
	return jwks.NewJWKSValidator(jwks.JWKSConfig{
		JWKSURL: i.server.URL, Issuer: testIssuer, Audience: testAudience, Algorithms: []string{"RS256"},
		MaxTokenTTL: 5 * time.Minute, Leeway: 30 * time.Second, AllowInsecureLoopback: true,
	})
}

// newWire migrates a fresh schema, seeds tenants a and b with a skeleton
// mandate for human-a, and serves the API to a Connect client.
func newWire(t *testing.T) (gatewayv1.EffectGatewayServiceClient, *issuer, *sql.DB) {
	t.Helper()
	base := os.Getenv("HELM_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run the gateway wire proofs")
	}
	schema := fmt.Sprintf("helm_gateway_wire_%d", time.Now().UnixNano())
	admin, err := sql.Open("postgres", base)
	must(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	_, err = admin.Exec(`CREATE SCHEMA ` + schema)
	must(t, err)
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	parsed, err := url.Parse(base)
	must(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("postgres", parsed.String())
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	must(t, admission.Migrate(ctx, db))

	rows, err := authorityrows.New(db)
	must(t, err)
	var now time.Time
	must(t, db.QueryRow(`SELECT now()`).Scan(&now))
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		must(t, rows.CreateTenant(ctx, tenant))
		must(t, rows.CreatePrincipal(ctx, tenant, "human-a", authorityrows.PrincipalHuman))
		must(t, rows.CreatePrincipal(ctx, tenant, "human-b", authorityrows.PrincipalHuman))
		must(t, rows.CreatePrincipal(ctx, tenant, "agent-a", authorityrows.PrincipalAgent))
		must(t, rows.CreateEffectType(ctx, tenant, effectargs.GitHubBranchCreateFromChanges, authorityrows.RiskMedium))
		must(t, rows.CreateEffectType(ctx, tenant, "ops.note", authorityrows.RiskLow))
		_, err = rows.CreateMandate(ctx, tenant, "human-a", authorityrows.Terms{
			EffectTypes: []string{effectargs.GitHubBranchCreateFromChanges, "ops.note"}, Targets: []string{testRepo, "ops"},
			Condition:        `input.effect_type == "ops.note" || input.args.head.startsWith("helm/")`,
			ApprovalRequired: []string{"ops.note"},
			ValidFrom:        now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
		}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"})
		must(t, err)
	}

	svc, err := admission.New(db, admission.Config{})
	must(t, err)
	iss := newIssuer(t)
	api := &Server{Admission: svc, Auth: &Authenticator{Validator: iss.validator(), Actor: testActor}}
	mux := http.NewServeMux()
	mux.Handle(api.Handler())
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return gatewayv1.NewEffectGatewayServiceClient(server.Client(), server.URL, connect.WithGRPC()), iss, db
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func branchRequest(key, head string) *gatewayv1.ProposeRequest {
	args := `{"schema":"helm.github.branch.create_from_changes.v1","base":"main",` +
		`"base_sha":"0123456789abcdef0123456789abcdef01234567","head":"` + head + `","message":"Add skeleton",` +
		`"files":[{"path":"docs/skeleton.md","mode":"100644","content_utf8":"# Skeleton\n"}]}`
	return &gatewayv1.ProposeRequest{
		IdempotencyKey: key,
		WorkRef:        &gatewayv1.ProposeRequest_CommitmentId{CommitmentId: "commitment-1"},
		Effect:         &gatewayv1.EffectDescriptor{EffectType: effectargs.GitHubBranchCreateFromChanges, Target: testRepo, Arguments: []byte(args)},
	}
}

func withToken[T any](msg *T, token string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

func wantRPCError(t *testing.T, what string, err error, code connect.Code, reason contracts.ReasonCode) {
	t.Helper()
	gotCode, gotReason, _ := errorDetail(t, err)
	if gotCode != code || gotReason != string(reason) {
		t.Fatalf("%s: %v %q, want %v %q (%v)", what, gotCode, gotReason, code, reason, err)
	}
}

func TestPostgresGatewayAPIOnTheWire(t *testing.T) {
	client, iss, _ := newWire(t)
	ctx := context.Background()
	propose := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	read := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead)

	// Known good: Propose admits, a replay returns the stored attempt, and a
	// read token reads it back with its content.
	resp, err := client.Propose(ctx, withToken(branchRequest("wire-1", "helm/skeleton"), propose))
	must(t, err)
	attempt := resp.Msg.GetAttempt()
	if resp.Msg.GetExisting() || attempt.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED ||
		attempt.GetRequesterPrincipalId() != "human-a" || attempt.GetRequesterActorId() != testActor ||
		attempt.GetWorkspaceId() != "ws-a" || attempt.GetRiskClass() != gatewayv1.RiskClass_RISK_CLASS_MEDIUM ||
		attempt.GetPermit().GetPermitId() == "" || attempt.GetCommitmentId() != "commitment-1" {
		t.Fatalf("Propose = %+v", resp.Msg)
	}
	replay, err := client.Propose(ctx, withToken(branchRequest("wire-1", "helm/skeleton"), propose))
	must(t, err)
	if !replay.Msg.GetExisting() || replay.Msg.GetAttempt().GetAttemptId() != attempt.GetAttemptId() {
		t.Fatalf("replay = %+v", replay.Msg)
	}
	got, err := client.GetAttempt(ctx, withToken(&gatewayv1.GetAttemptRequest{AttemptId: attempt.GetAttemptId()}, read))
	must(t, err)
	if got.Msg.GetAttempt().GetVersion() != attempt.GetVersion() {
		t.Fatalf("GetAttempt = %+v", got.Msg)
	}
	content, err := client.GetAttemptContent(ctx, withToken(&gatewayv1.GetAttemptContentRequest{AttemptId: attempt.GetAttemptId()}, read))
	must(t, err)
	sum := sha256.Sum256(content.Msg.GetArguments())
	if string(sum[:]) != string(attempt.GetArgumentDigest()) {
		t.Fatal("the content does not hash to the attempt's argument digest")
	}

	// Decisions are states: head on the default branch is DENIED, not an error.
	denied, err := client.Propose(ctx, withToken(branchRequest("wire-2", "main"), propose))
	must(t, err)
	if denied.Msg.GetAttempt().GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_DENIED ||
		denied.Msg.GetAttempt().GetReasonCode() != string(contracts.ReasonMissingRequirement) {
		t.Fatalf("head on the default branch = %+v", denied.Msg.GetAttempt())
	}

	// Known bad: each refusal is a Connect error with its ErrorDetail.
	_, err = client.Propose(ctx, withToken(branchRequest("wire-3", "helm/x"), ""))
	wantRPCError(t, "no token", err, connect.CodeUnauthenticated, "")
	kernel := iss.token(t, "helm-kernel:test", "tenant-a", "human-a", ScopePropose)
	_, err = client.Propose(ctx, withToken(branchRequest("wire-3", "helm/x"), kernel))
	wantRPCError(t, "a kernel-audience token", err, connect.CodeUnauthenticated, "")
	_, err = client.Propose(ctx, withToken(branchRequest("wire-3", "helm/x"), read))
	wantRPCError(t, "a read token on Propose", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	_, err = client.GetAttempt(ctx, withToken(&gatewayv1.GetAttemptRequest{AttemptId: attempt.GetAttemptId()}, propose))
	wantRPCError(t, "a propose token on GetAttempt", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	changed := branchRequest("wire-1", "helm/other")
	_, err = client.Propose(ctx, withToken(changed, propose))
	wantRPCError(t, "same key, other content", err, connect.CodeAlreadyExists, contracts.ReasonIdempotencyConflict)
	bad := branchRequest("wire-4", "helm/x")
	bad.Effect.Arguments = []byte(`{"schema":"x","schema":"y"}`)
	_, err = client.Propose(ctx, withToken(bad, propose))
	wantRPCError(t, "duplicate keys", err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	noEffect := &gatewayv1.ProposeRequest{IdempotencyKey: "wire-5", WorkRef: &gatewayv1.ProposeRequest_CommitmentId{CommitmentId: "c"}}
	_, err = client.Propose(ctx, withToken(noEffect, propose))
	wantRPCError(t, "no effect", err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	otherTenant := iss.token(t, testAudience, "tenant-b", "human-a", ScopeRead)
	_, err = client.GetAttempt(ctx, withToken(&gatewayv1.GetAttemptRequest{AttemptId: attempt.GetAttemptId()}, otherTenant))
	wantRPCError(t, "another tenant's read", err, connect.CodeNotFound, "")
	_, err = client.GetAttemptContent(ctx, withToken(&gatewayv1.GetAttemptContentRequest{AttemptId: attempt.GetAttemptId()}, otherTenant))
	wantRPCError(t, "another tenant's content", err, connect.CodeNotFound, "")
	stranger := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose, func(c *tokenClaims) { c.Act.Sub = "spiffe://evil" })
	_, err = client.Propose(ctx, withToken(branchRequest("wire-6", "helm/x"), stranger))
	wantRPCError(t, "an unconfigured actor", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	direct := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose, func(c *tokenClaims) { c.Act = nil })
	_, err = client.Propose(ctx, withToken(branchRequest("wire-7", "helm/x"), direct))
	wantRPCError(t, "a human's direct propose token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
}

func decision(attemptID, action string) func(*tokenClaims) {
	return func(c *tokenClaims) {
		c.AuthorizationDetails = []map[string]string{{"type": "helm_effect_decision", "attempt_id": attemptID, "action": action}}
	}
}

func noteRequest(key string) *gatewayv1.ProposeRequest {
	return &gatewayv1.ProposeRequest{
		IdempotencyKey: key,
		WorkRef:        &gatewayv1.ProposeRequest_CaseId{CaseId: "case-1"},
		Effect:         &gatewayv1.EffectDescriptor{EffectType: "ops.note", Target: "ops", Arguments: []byte(`{"text":"hi"}`)},
	}
}

func TestPostgresGatewayDecisionsOnTheWire(t *testing.T) {
	client, iss, _ := newWire(t)
	ctx := context.Background()
	propose := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	resp, err := client.Propose(ctx, withToken(noteRequest("note-1"), propose))
	must(t, err)
	attempt := resp.Msg.GetAttempt()
	if attempt.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED || attempt.GetPendingApproval() == nil {
		t.Fatalf("escalation = %+v", attempt)
	}
	id := attempt.GetAttemptId()
	digest := attempt.GetPendingApproval().GetApprovalDigest()
	// The Console's check: the digest recomputes from what the attempt shows.
	want := admission.ApprovalDigestV1(id, attempt.GetTargetDigest(), attempt.GetArgumentDigest(), nil, attempt.GetPendingApproval().GetExpiresAt().AsTime())
	if string(want) != string(digest) {
		t.Fatal("the pending approval digest does not recompute from the attempt")
	}
	approve := func(token string) (*connect.Response[gatewayv1.ApproveResponse], error) {
		return client.Approve(ctx, withToken(&gatewayv1.ApproveRequest{AttemptId: id, ApprovalDigest: digest, Reason: "ok"}, token))
	}

	// Known bad: a token bound to reject, to another attempt, or unbound; a
	// propose token; self-approval.
	for name, token := range map[string]string{
		"bound to reject":  iss.token(t, testAudience, "tenant-a", "human-b", ScopeDecide, decision(id, "reject")),
		"bound to another": iss.token(t, testAudience, "tenant-a", "human-b", ScopeDecide, decision("0192f0c4-7a1e-7c3b-9d2a-000000000000", "approve")),
		"unbound":          iss.token(t, testAudience, "tenant-a", "human-b", ScopeDecide),
		"a propose token":  iss.token(t, testAudience, "tenant-a", "human-b", ScopePropose, decision(id, "approve")),
	} {
		_, err := approve(token)
		wantRPCError(t, name, err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	_, err = approve(iss.token(t, testAudience, "tenant-a", "human-a", ScopeDecide, decision(id, "approve")))
	wantRPCError(t, "self-approval", err, connect.CodePermissionDenied, contracts.ReasonApproverNotDistinct)

	// Known good: a distinct human's bound decide token admits.
	good := iss.token(t, testAudience, "tenant-a", "human-b", ScopeDecide, decision(id, "approve"))
	approved, err := approve(good)
	must(t, err)
	got := approved.Msg.GetAttempt()
	if got.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED || got.GetApproval().GetApproverPrincipalId() != "human-b" ||
		got.GetApproval().GetApproverActorId() != testActor || got.GetApproval().GetDecision() != gatewayv1.ApprovalDecision_APPROVAL_DECISION_APPROVED ||
		got.GetPendingApproval() != nil || got.GetPermit().GetPermitId() == "" {
		t.Fatalf("approved = %+v", got)
	}
	// The same token again is refused, even though the call would be a no-op.
	_, err = approve(good)
	wantRPCError(t, "a reused decide token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)

	// Cancel by the requester's propose token releases it.
	cancelled, err := client.Cancel(ctx, withToken(&gatewayv1.CancelRequest{AttemptId: id}, propose))
	must(t, err)
	if cancelled.Msg.GetAttempt().GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_CANCELLED {
		t.Fatalf("cancel = %+v", cancelled.Msg)
	}
	read := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead)
	_, err = client.Cancel(ctx, withToken(&gatewayv1.CancelRequest{AttemptId: id}, read))
	wantRPCError(t, "a read token on Cancel", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
}
