package server

// The step-up proof on the wire, against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): a JWKS issuer signs the decide token and
// the proof, a Connect client calls Approve, and a refusal carries
// STEP_UP_REQUIRED. A proof is verified like any gateway token and bound to
// the approver, the tenant, the attempt and the digest approved; its jti is
// single-use in the approval's own transaction.
//
// quantum_posture: signs classical RS256 test tokens and computes SHA-256
// digests; no post-quantum claim.

import (
	"context"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

const (
	stepUpMerge   = "github.pull_request.merge"
	stepUpPublish = "ops.release.publish"
)

// jtiOf fixes a token's jti, so a test can look for it in the replay table.
func jtiOf(id string) func(*tokenClaims) {
	return func(c *tokenClaims) { c.ID = id }
}

// replayRows counts the recorded uses of the given jtis in tenant.
func replayRows(t *testing.T, db *sql.DB, tenant string, jtis ...string) int {
	t.Helper()
	tx, err := db.Begin()
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant)
	must(t, err)
	var n int
	must(t, tx.QueryRow(`SELECT count(*) FROM authority_token_replay WHERE jti = ANY ($1::text[])`, pq.Array(jtis)).Scan(&n))
	return n
}

// stepUpWire is a gateway on the wire with a high-risk and an irreversible
// effect type under a mandate of human-a, who proposes; human-b approves.
type stepUpWire struct {
	t      *testing.T
	client gatewayv1.EffectGatewayServiceClient
	iss    *issuer
	db     *sql.DB
}

func newStepUpWire(t *testing.T) *stepUpWire {
	t.Helper()
	client, iss, db := newWire(t)
	ctx := context.Background()
	rows, err := authorityrows.New(db)
	must(t, err)
	must(t, rows.CreateEffectType(ctx, "tenant-a", stepUpMerge, authorityrows.RiskHigh))
	must(t, rows.CreateEffectType(ctx, "tenant-a", stepUpPublish, authorityrows.RiskIrreversible))
	now := time.Now()
	_, err = rows.CreateMandate(ctx, "tenant-a", "human-a", authorityrows.Terms{
		EffectTypes: []string{stepUpMerge, stepUpPublish}, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-b"})
	must(t, err)
	return &stepUpWire{t: t, client: client, iss: iss, db: db}
}

// escalate proposes an effect as human-a and returns the ESCALATED attempt.
func (w *stepUpWire) escalate(key, effectType string) *gatewayv1.EffectAttempt {
	w.t.Helper()
	resp, err := w.client.Propose(context.Background(), withToken(&gatewayv1.ProposeRequest{
		IdempotencyKey: key,
		WorkRef:        &gatewayv1.ProposeRequest_CommitmentId{CommitmentId: "commitment-1"},
		Effect:         &gatewayv1.EffectDescriptor{EffectType: effectType, Target: testRepo, Arguments: []byte(`{"n":"` + key + `"}`)},
	}, w.iss.token(w.t, testAudience, "tenant-a", "human-a", ScopePropose)))
	must(w.t, err)
	a := resp.Msg.GetAttempt()
	if a.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED || a.GetPendingApproval() == nil {
		w.t.Fatalf("%s = %+v, want ESCALATED", key, a)
	}
	return a
}

// decide is human-b's decide token for the attempt, with a fixed jti.
func (w *stepUpWire) decide(attemptID, jti string) string {
	return w.iss.token(w.t, testAudience, "tenant-a", "human-b", ScopeDecide, decision(attemptID, "approve"), jtiOf(jti))
}

// unstated leaves user_verified out of a helm_step_up entry.
type unstatedField struct{}

var unstated = unstatedField{}

// stepUpEntry is the helm_step_up entry of a proof; verified is the value of
// user_verified, or unstated to leave it out.
func stepUpEntry(attemptID string, digest []byte, method string, verified any) func(*tokenClaims) {
	return func(c *tokenClaims) {
		entry := map[string]any{"type": "helm_step_up", "attempt_id": attemptID, "approval_digest": hex.EncodeToString(digest), "method": method}
		if verified != unstated {
			entry["user_verified"] = verified
		}
		c.AuthorizationDetails = []map[string]any{entry}
	}
}

// binding is the entry of the contract: user-verified.
func binding(attemptID string, digest []byte, method string) func(*tokenClaims) {
	return stepUpEntry(attemptID, digest, method, true)
}

// retained is what an approval record kept of its step-up proof.
type retained struct{ issuer, jti, method, proof string }

func retainedProof(t *testing.T, db *sql.DB, tenant, attemptID string) retained {
	t.Helper()
	tx, err := db.Begin()
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant)
	must(t, err)
	var r retained
	must(t, tx.QueryRow(`SELECT step_up_issuer, step_up_jti, step_up_method, step_up_proof FROM authority_approvals WHERE attempt_id = $1`,
		attemptID).Scan(&r.issuer, &r.jti, &r.method, &r.proof))
	return r
}

// proof is human-b's step-up proof for the attempt, with a fixed jti and the
// binding of the contract; edit changes it.
func (w *stepUpWire) proof(a *gatewayv1.EffectAttempt, jti string, edit ...func(*tokenClaims)) string {
	edits := append([]func(*tokenClaims){jtiOf(jti), binding(a.GetAttemptId(), a.GetPendingApproval().GetApprovalDigest(), "webauthn")}, edit...)
	return w.iss.token(w.t, testAudience, "tenant-a", "human-b", ScopeStepUp, edits...)
}

func (w *stepUpWire) approve(a *gatewayv1.EffectAttempt, decideToken, proof string) (*gatewayv1.EffectAttempt, error) {
	resp, err := w.client.Approve(context.Background(), withToken(&gatewayv1.ApproveRequest{
		AttemptId: a.GetAttemptId(), ApprovalDigest: a.GetPendingApproval().GetApprovalDigest(), Reason: "ok", StepUpProof: proof,
	}, decideToken))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetAttempt(), nil
}

// get reads the attempt back.
func (w *stepUpWire) get(attemptID string) *gatewayv1.EffectAttempt {
	w.t.Helper()
	resp, err := w.client.GetAttempt(context.Background(), withToken(&gatewayv1.GetAttemptRequest{AttemptId: attemptID},
		w.iss.token(w.t, testAudience, "tenant-a", "human-a", ScopeRead)))
	must(w.t, err)
	return resp.Msg.GetAttempt()
}

func (w *stepUpWire) wantAdmitted(what string, a *gatewayv1.EffectAttempt, err error) {
	w.t.Helper()
	must(w.t, err)
	if a.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED || a.GetApproval().GetApproverPrincipalId() != "human-b" ||
		a.GetPermit().GetPermitId() == "" {
		w.t.Fatalf("%s = %+v, want ADMITTED by human-b with a permit", what, a)
	}
}

// wantEscalated checks that the attempt waits, as escalated, for an approval.
func (w *stepUpWire) wantEscalated(what string, a *gatewayv1.EffectAttempt) {
	w.t.Helper()
	got := w.get(a.GetAttemptId())
	if got.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED || got.GetApproval() != nil ||
		got.GetVersion() != a.GetVersion() || got.GetPermit() != nil {
		w.t.Fatalf("%s changed the attempt: %+v", what, got)
	}
}

// Known good: a proof admits a high-risk and an irreversible effect, and an
// effect that needs no step-up ignores one; a stop lift needs one too.
func TestPostgresStepUpProofOnTheWire(t *testing.T) {
	w := newStepUpWire(t)
	ctx := context.Background()

	for _, effectType := range []string{stepUpMerge, stepUpPublish} {
		a := w.escalate("known-good-"+effectType, effectType)
		if a.GetRiskClass() == gatewayv1.RiskClass_RISK_CLASS_LOW || a.GetRiskClass() == gatewayv1.RiskClass_RISK_CLASS_MEDIUM {
			t.Fatalf("%s escalated at %s", effectType, a.GetRiskClass())
		}
		decideJTI, proofJTI := "decide-"+effectType, "proof-"+effectType
		proof := w.proof(a, proofJTI)
		admitted, err := w.approve(a, w.decide(a.GetAttemptId(), decideJTI), proof)
		w.wantAdmitted(effectType+" with a proof", admitted, err)
		if n := replayRows(t, w.db, "tenant-a", decideJTI, proofJTI); n != 2 {
			t.Fatalf("%s: %d replay rows for the decide token and the proof, want 2", effectType, n)
		}
		// The approval keeps the proof exactly as received, and it verifies
		// again against the issuer's keys.
		kept := retainedProof(t, w.db, "tenant-a", a.GetAttemptId())
		if kept.proof != proof || kept.jti != proofJTI || kept.method != "webauthn" || kept.issuer != testIssuer {
			t.Fatalf("%s: the approval keeps %+v, want the proof as sent", effectType, kept)
		}
		claims, err := w.iss.validator().ValidateAuthorization(kept.proof)
		must(t, err)
		if claims.RegisteredClaims.ID != proofJTI || len(claims.Scopes) != 1 || claims.Scopes[0] != ScopeStepUp {
			t.Fatalf("%s: the kept proof verifies as %+v", effectType, claims)
		}
	}

	// A proof is not a credential of any RPC: presented as the bearer of
	// Approve it is refused like any token of another scope.
	a := w.escalate("bearer", stepUpMerge)
	_, err := w.approve(a, w.proof(a, "proof-as-bearer"), "")
	wantRPCError(t, "a step-up proof as the decide token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	w.wantEscalated("a proof as the bearer", a)

	// An effect that needs no step-up (a note the mandate escalates) ignores
	// a proof, valid or not, and does not use it up.
	note := w.iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	resp, err := w.client.Propose(ctx, withToken(noteRequest("note-1"), note))
	must(t, err)
	noteAttempt := resp.Msg.GetAttempt()
	admitted, err := w.approve(noteAttempt, w.decide(noteAttempt.GetAttemptId(), "decide-note"), w.proof(noteAttempt, "proof-note"))
	w.wantAdmitted("a note with a proof", admitted, err)
	if n := replayRows(t, w.db, "tenant-a", "proof-note"); n != 0 {
		t.Fatal("a proof the note did not need was used up")
	}
	resp, err = w.client.Propose(ctx, withToken(noteRequest("note-2"), note))
	must(t, err)
	noteAttempt = resp.Msg.GetAttempt()
	admitted, err = w.approve(noteAttempt, w.decide(noteAttempt.GetAttemptId(), "decide-note-2"), "not a token at all")
	w.wantAdmitted("a note with a proof that is no token", admitted, err)

	// A stop lift, an authority change, needs one whatever its risk row says.
	rows, err := authorityrows.New(w.db)
	must(t, err)
	must(t, rows.CreateEffectType(ctx, "tenant-a", effectargs.AuthorityLift, authorityrows.RiskLow))
	now := time.Now()
	_, err = rows.CreateMandate(ctx, "tenant-a", "human-b", authorityrows.Terms{EffectTypes: []string{effectargs.AuthorityLift},
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-a"})
	must(t, err)
	stopAs := func(edit ...func(*tokenClaims)) string {
		return w.iss.token(t, testAudience, "tenant-a", "human-b", ScopeStop, edit...)
	}
	stopped, err := w.client.Stop(ctx, withToken(&gatewayv1.StopRequest{IdempotencyKey: "stop-1",
		ScopeKind: gatewayv1.StopScopeKind_STOP_SCOPE_KIND_TENANT, Reason: "incident"},
		stopAs(bound("helm_stop", map[string]string{"idempotency_key": "stop-1", "scope_kind": "tenant", "scope_key": ""}))))
	must(t, err)
	stopID := stopped.Msg.GetStop().GetStopId()
	lifted, err := w.client.Lift(ctx, withToken(&gatewayv1.LiftRequest{IdempotencyKey: "lift-1", StopId: stopID},
		stopAs(bound("helm_stop_lift", map[string]string{"stop_id": stopID}))))
	must(t, err)
	lift := lifted.Msg.GetAttempt()
	// human-a approves it: the operator, human-b, requested it.
	approveAsA := func(decideJTI, proof string) (*gatewayv1.EffectAttempt, error) {
		resp, err := w.client.Approve(ctx, withToken(&gatewayv1.ApproveRequest{
			AttemptId: lift.GetAttemptId(), ApprovalDigest: lift.GetPendingApproval().GetApprovalDigest(), StepUpProof: proof,
		}, w.iss.token(t, testAudience, "tenant-a", "human-a", ScopeDecide, decision(lift.GetAttemptId(), "approve"), jtiOf(decideJTI))))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetAttempt(), nil
	}
	_, err = approveAsA("decide-lift", "")
	wantRPCError(t, "a lift without a proof", err, connect.CodePermissionDenied, contracts.ReasonStepUpRequired)
	proofAsA := w.iss.token(t, testAudience, "tenant-a", "human-a", ScopeStepUp, jtiOf("proof-lift"),
		binding(lift.GetAttemptId(), lift.GetPendingApproval().GetApprovalDigest(), "webauthn"))
	approved, err := approveAsA("decide-lift", proofAsA)
	must(t, err)
	if approved.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED || approved.GetApproval().GetApproverPrincipalId() != "human-a" {
		t.Fatalf("a lift with a proof = %+v", approved)
	}
	if n := replayRows(t, w.db, "tenant-a", "decide-lift", "proof-lift"); n != 2 {
		t.Fatalf("%d replay rows for the lift's decide token and proof, want 2", n)
	}
}

// Known bad: every proof that is not one for this approval is
// STEP_UP_REQUIRED, leaves the attempt ESCALATED and uses up neither token:
// the one decide token is still good for the approval that succeeds.
func TestPostgresStepUpProofRefusalsOnTheWireSpendNothing(t *testing.T) {
	w := newStepUpWire(t)
	a := w.escalate("merge-1", stepUpMerge)
	other := w.escalate("merge-2", stepUpMerge)
	id, digest := a.GetAttemptId(), a.GetPendingApproval().GetApprovalDigest()
	zero := make([]byte, 32)
	now := time.Now()
	const decideJTI = "decide-hi"
	decideToken := w.decide(id, decideJTI)

	for name, test := range map[string]struct{ proof, jti string }{
		"no proof":                      {"", ""},
		"not a token":                   {"not-a-token", ""},
		"a decide token as the proof":   {w.iss.token(t, testAudience, "tenant-a", "human-b", ScopeDecide, jtiOf("bad-1"), binding(id, digest, "webauthn")), "bad-1"},
		"a propose token":               {w.iss.token(t, testAudience, "tenant-a", "human-b", ScopePropose, jtiOf("bad-2"), binding(id, digest, "webauthn")), "bad-2"},
		"another attempt":               {w.proof(a, "bad-3", binding(other.GetAttemptId(), digest, "webauthn")), "bad-3"},
		"another digest":                {w.proof(a, "bad-4", binding(id, zero, "webauthn")), "bad-4"},
		"the other attempt's digest":    {w.proof(a, "bad-5", binding(id, other.GetPendingApproval().GetApprovalDigest(), "webauthn")), "bad-5"},
		"a wrong method":                {w.proof(a, "bad-6", binding(id, digest, "totp")), "bad-6"},
		"no method":                     {w.proof(a, "bad-7", binding(id, digest, "")), "bad-7"},
		"user verification false":       {w.proof(a, "bad-15", stepUpEntry(id, digest, "webauthn", false)), "bad-15"},
		"user verification not stated":  {w.proof(a, "bad-16", stepUpEntry(id, digest, "webauthn", unstated)), "bad-16"},
		"user verification as a string": {w.proof(a, "bad-17", stepUpEntry(id, digest, "webauthn", "true")), "bad-17"},
		"a proof with no iat":           {w.proof(a, "bad-18", func(c *tokenClaims) { c.IssuedAt = nil }), "bad-18"},
		"no binding":                    {w.iss.token(t, testAudience, "tenant-a", "human-b", ScopeStepUp, jtiOf("bad-8")), "bad-8"},
		"another principal":             {w.iss.token(t, testAudience, "tenant-a", "human-a", ScopeStepUp, jtiOf("bad-9"), binding(id, digest, "webauthn")), "bad-9"},
		"another tenant's proof":        {w.iss.token(t, testAudience, "tenant-b", "human-b", ScopeStepUp, jtiOf("bad-10"), binding(id, digest, "webauthn")), "bad-10"},
		"another audience":              {w.iss.token(t, "helm-kernel:test", "tenant-a", "human-b", ScopeStepUp, jtiOf("bad-11"), binding(id, digest, "webauthn")), "bad-11"},
		"a foreign actor":               {w.proof(a, "bad-12", func(c *tokenClaims) { c.Act.Sub = "spiffe://evil" }), "bad-12"},
		"an expired proof": {w.proof(a, "bad-13", func(c *tokenClaims) {
			c.IssuedAt, c.ExpiresAt = jwt.NewNumericDate(now.Add(-10*time.Minute)), jwt.NewNumericDate(now.Add(-5*time.Minute))
		}), "bad-13"},
		"a proof that lives past the maximum TTL": {w.proof(a, "bad-14", func(c *tokenClaims) {
			c.IssuedAt, c.ExpiresAt = jwt.NewNumericDate(now), jwt.NewNumericDate(now.Add(time.Hour))
		}), "bad-14"},
	} {
		_, err := w.approve(a, decideToken, test.proof)
		wantRPCError(t, name, err, connect.CodePermissionDenied, contracts.ReasonStepUpRequired)
		w.wantEscalated(name, a)
		jtis := []string{decideJTI}
		if test.jti != "" {
			jtis = append(jtis, test.jti)
		}
		if n := replayRows(t, w.db, "tenant-a", jtis...); n != 0 {
			t.Fatalf("%s used up %d token(s)", name, n)
		}
	}
	w.wantEscalated("all of them", other)

	// Known good after all that: the same decide token and a proper proof.
	admitted, err := w.approve(a, decideToken, w.proof(a, "proof-hi"))
	w.wantAdmitted("the proof after the refusals", admitted, err)

	// The proof is single-use: a proof of the same jti, bound to the other
	// attempt as an issuer's mistake would be, is refused and leaves the
	// other attempt ESCALATED.
	replayed, otherDecide := w.proof(other, "proof-hi"), w.decide(other.GetAttemptId(), "decide-hi-2")
	_, err = w.approve(other, otherDecide, replayed)
	wantRPCError(t, "a proof used for a second attempt", err, connect.CodePermissionDenied, contracts.ReasonStepUpRequired)
	w.wantEscalated("a replayed proof", other)
	if n := replayRows(t, w.db, "tenant-a", "decide-hi-2"); n != 0 {
		t.Fatal("a replayed proof used up the decide token")
	}
	admitted, err = w.approve(other, otherDecide, w.proof(other, "proof-hi-2"))
	w.wantAdmitted("a fresh proof for the other attempt", admitted, err)
}
