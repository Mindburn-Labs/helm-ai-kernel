package admission

// HELM-751's step-up proof against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): Approve of an effect that needs step-up
// takes the verified proof the server hands it, uses its jti up in the
// approval's own transaction after the decide token's, and keeps it on the
// approval record. Every refusal leaves the attempt ESCALATED and uses up
// neither token. The server's checks of the token itself (signature, scope,
// approver, tenant, binding) are proved on the wire in core/pkg/gateway/server.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

const (
	highType         = "github.pull_request.merge"
	irreversibleType = "ops.release.publish"
)

// stepUpProof is a fresh verified proof, as the server hands it to Approve.
// Admission does not parse the compact token, so Raw is a placeholder made of
// the jti: what the approval record must keep, exactly.
func stepUpProof() *StepUp {
	token := decideToken("helm.gateway.stepup")
	return &StepUp{Token: token, Method: "webauthn", Raw: "compact-" + token.ID}
}

func withProof(in DecideInput, proof *StepUp) DecideInput {
	in.StepUp = proof
	return in
}

// stepUpRequester registers a high and an irreversible effect type under a
// mandate of human-c and returns human-c, carried by the Control Plane runner.
func (f *fixture) stepUpRequester() Caller {
	f.t.Helper()
	ctx := context.Background()
	must(f.t, f.rows.CreateEffectType(ctx, tenantA, highType, authorityrows.RiskHigh))
	must(f.t, f.rows.CreateEffectType(ctx, tenantA, irreversibleType, authorityrows.RiskIrreversible))
	f.rootMandate(tenantA, "human-c", authorityrows.Terms{
		EffectTypes: []string{highType, irreversibleType}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour),
	})
	requester := human
	requester.PrincipalID = "human-c"
	return requester
}

// escalatedEffect proposes a high or irreversible effect, which escalates by
// its risk class.
func (f *fixture) escalatedEffect(requester Caller, key, effectType string) Attempt {
	f.t.Helper()
	a := f.propose(requester, proposal(key, effectType, repo, []byte(`{"merge_method":"squash"}`)))
	wantState(f.t, key, a, "ESCALATED", contracts.ReasonApprovalRequired)
	return a
}

// replayRows counts the recorded uses of the given jtis.
func (f *fixture) replayRows(jtis ...string) int {
	f.t.Helper()
	n := 0
	for _, jti := range jtis {
		n += f.count(tenantA, `SELECT count(*) FROM authority_token_replay WHERE jti = $1`, jti)
	}
	return n
}

// wantProofRecord checks the approval's record of the proof it used up: the
// compact token as received, issuer, jti and method, and the replay row they
// name, of scope stepup.
func (f *fixture) wantProofRecord(attemptID string, proof *StepUp) {
	f.t.Helper()
	if n := f.count(tenantA, `SELECT count(*) FROM authority_approvals
		WHERE attempt_id = $1 AND decision = 'APPROVED' AND step_up_issuer = $2 AND step_up_jti = $3 AND step_up_method = $4
		AND step_up_proof = $5`,
		attemptID, proof.Token.Issuer, proof.Token.ID, proof.Method, proof.Raw); n != 1 {
		f.t.Fatalf("the approval of %s does not record the proof %s", attemptID, proof.Token.ID)
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_token_replay r JOIN authority_approvals a
		ON a.tenant_id = r.tenant_id AND a.step_up_issuer = r.issuer AND a.step_up_jti = r.jti
		WHERE a.attempt_id = $1 AND r.scope = 'helm.gateway.stepup'`, attemptID); n != 1 {
		f.t.Fatalf("the proof of %s names no stepup row of authority_token_replay", attemptID)
	}
}

// wantNoProofRecord checks that the approval of attemptID records no proof.
func (f *fixture) wantNoProofRecord(attemptID string) {
	f.t.Helper()
	if n := f.count(tenantA, `SELECT count(*) FROM authority_approvals WHERE attempt_id = $1
		AND step_up_issuer IS NULL AND step_up_jti IS NULL AND step_up_method IS NULL AND step_up_proof IS NULL`, attemptID); n != 1 {
		f.t.Fatalf("the decision on %s records a proof, or none was made", attemptID)
	}
}

// wantStillEscalated checks that a refused call changed nothing.
func (f *fixture) wantStillEscalated(what string, a Attempt) {
	f.t.Helper()
	got, err := f.svc.Get(context.Background(), human, a.ID)
	must(f.t, err)
	if got.State != "ESCALATED" || got.Version != a.Version || got.Approval != nil || got.Permit != nil {
		f.t.Fatalf("%s changed the attempt: %+v", what, got)
	}
}

// Known good: a proof admits a high-risk, an irreversible and an authority
// change (a lift), each recorded with the proof that admitted it. A lift
// stops at ADMITTED here: nothing applies it yet.
func TestPostgresStepUpProofAdmitsHighIrreversibleAndAuthorityChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	requester := f.stepUpRequester()

	approveWithProof := func(name string, a Attempt) {
		t.Helper()
		decide, proof := decideToken("helm.gateway.decide"), stepUpProof()
		approved, existing, err := f.svc.Approve(ctx, approverB, decide, withProof(approval(a, "with step-up"), proof))
		must(t, err)
		wantState(t, name+" approved with a proof", approved, "ADMITTED", "")
		if existing || approved.Permit == nil || approved.Approval == nil || approved.Approval.ApproverPrincipalID != "human-b" {
			t.Fatalf("%s: approved = %+v existing=%v", name, approved, existing)
		}
		f.wantProofRecord(a.ID, proof)
		// The decide token and the proof are two rows of the replay table.
		if n := f.replayRows(decide.ID, proof.Token.ID); n != 2 {
			t.Fatalf("%s: %d replay rows for the decide token and the proof, want 2", name, n)
		}
	}
	approveWithProof("a high-risk effect", f.escalatedEffect(requester, "merge-1", highType))
	approveWithProof("an irreversible effect", f.escalatedEffect(requester, "publish-1", irreversibleType))

	// The lift comes last: its stop holds for everything approved after it.
	must(t, f.rows.CreateEffectType(ctx, tenantA, effectargs.AuthorityLift, authorityrows.RiskLow))
	liftMandate := f.rootMandate(tenantA, "human-c", authorityrows.Terms{
		EffectTypes: []string{effectargs.AuthorityLift}, ValidFrom: f.now.Add(-time.Hour), ValidUntil: f.now.Add(24 * time.Hour),
	})
	stop, _, err := f.svc.Stop(ctx, operator, stopToken(), tenantStop("stop-1"))
	must(t, err)
	lift, _, err := f.svc.Lift(ctx, operator, stopToken(), LiftInput{IdempotencyKey: "lift-1", StopID: stop.ID, MandateID: liftMandate.ID.String()})
	must(t, err)
	wantState(t, "the lift", lift, "ESCALATED", contracts.ReasonApprovalRequired)
	if lift.RiskClass != "low" {
		t.Fatalf("the lift's risk row is %s: it needs step-up whatever the row says", lift.RiskClass)
	}
	approveWithProof("a stop lift", lift)
}

// Known bad: a missing proof and each proof that is not one leave the attempt
// ESCALATED and use up neither the decide token nor the proof. The one decide
// token is then good for the approval that succeeds.
func TestPostgresStepUpProofRefusalsSpendNothing(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	requester := f.stepUpRequester()
	a := f.escalatedEffect(requester, "merge-1", highType)
	decide := decideToken("helm.gateway.decide")

	withScope := func(scope string) *StepUp { return &StepUp{Token: decideToken(scope), Method: "webauthn"} }
	other := func(edit func(*StepUp)) *StepUp {
		p := stepUpProof()
		edit(p)
		return p
	}
	for name, bad := range map[string]*StepUp{
		"no proof":                    nil,
		"a decide token as the proof": withScope("helm.gateway.decide"),
		"a stop token as the proof":   withScope("helm.gateway.stop"),
		"another method":              other(func(p *StepUp) { p.Method = "totp" }),
		"no method":                   other(func(p *StepUp) { p.Method = "" }),
		"no compact proof to keep":    other(func(p *StepUp) { p.Raw = "" }),
		"a proof longer than kept":    other(func(p *StepUp) { p.Raw = strings.Repeat("a", MaxStepUpProofBytes+1) }),
		"no jti":                      other(func(p *StepUp) { p.Token.ID = "" }),
		"no issuer":                   other(func(p *StepUp) { p.Token.Issuer = "" }),
		"no exp":                      other(func(p *StepUp) { p.Token.ExpiresAt = time.Time{} }),
		"an expired proof":            other(func(p *StepUp) { p.Token.ExpiresAt = time.Now().Add(-time.Minute) }),
	} {
		_, _, err := f.svc.Approve(ctx, approverB, decide, withProof(approval(a, ""), bad))
		wantRefusal(t, name, err, CodePermissionDenied, contracts.ReasonStepUpRequired)
		f.wantStillEscalated(name, a)
		jtis := []string{decide.ID}
		if bad != nil {
			jtis = append(jtis, bad.Token.ID)
		}
		if n := f.replayRows(jtis...); n != 0 {
			t.Fatalf("%s used up %d token(s)", name, n)
		}
	}

	// Known good after all that: the same decide token, a proper proof.
	proof := stepUpProof()
	approved, _, err := f.svc.Approve(ctx, approverB, decide, withProof(approval(a, ""), proof))
	must(t, err)
	wantState(t, "the proof after the refusals", approved, "ADMITTED", "")
	f.wantProofRecord(a.ID, proof)
}

// The proof's jti is single-use across attempts and across gateway processes:
// the row lives in Postgres.
func TestPostgresStepUpProofIsSingleUse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	requester := f.stepUpRequester()
	first := f.escalatedEffect(requester, "merge-1", highType)
	second := f.escalatedEffect(requester, "merge-2", highType)
	proof := stepUpProof()

	_, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(first, ""), proof))
	must(t, err)
	decide := decideToken("helm.gateway.decide")
	_, _, err = f.svc.Approve(ctx, approverB, decide, withProof(approval(second, ""), proof))
	wantRefusal(t, "a proof used for a second attempt", err, CodePermissionDenied, contracts.ReasonStepUpRequired)
	f.wantStillEscalated("the replayed proof", second)
	if n := f.replayRows(decide.ID); n != 0 {
		t.Fatal("a refused replay used up the decide token")
	}
	other, err := New(f.runtime, Config{})
	must(t, err)
	_, _, err = other.Approve(ctx, approverB, decide, withProof(approval(second, ""), proof))
	wantRefusal(t, "a replay on another gateway process", err, CodePermissionDenied, contracts.ReasonStepUpRequired)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_token_replay WHERE jti = $1`, proof.Token.ID); n != 1 {
		t.Fatalf("%d replay rows for one proof", n)
	}

	// A proof of the same jti from another issuer is another proof.
	elsewhere := stepUpProof()
	elsewhere.Token.ID, elsewhere.Token.Issuer = proof.Token.ID, "https://another-issuer.test"
	approved, _, err := f.svc.Approve(ctx, approverB, decide, withProof(approval(second, ""), elsewhere))
	must(t, err)
	wantState(t, "another issuer's proof", approved, "ADMITTED", "")
}

// A proof for an effect that needs none is ignored: not looked at, not used
// up, not recorded. A Reject never needs one, and does not use one up.
func TestPostgresStepUpProofIsIgnoredWhenNoneIsNeeded(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	medium := f.escalated("pr1")
	proof := stepUpProof()
	approved, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(medium, ""), proof))
	must(t, err)
	wantState(t, "a medium effect with a proof", approved, "ADMITTED", "")
	f.wantNoProofRecord(medium.ID)
	if n := f.replayRows(proof.Token.ID); n != 0 {
		t.Fatal("a proof no effect needed was used up")
	}

	// Not even verified: a proof that would be refused where it is needed.
	unusable := f.escalated("pr2")
	notAProof := &StepUp{Token: decideToken("helm.gateway.decide"), Method: "carrier pigeon"}
	approved, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(unusable, ""), notAProof))
	must(t, err)
	wantState(t, "a medium effect with an unusable proof", approved, "ADMITTED", "")
	f.wantNoProofRecord(unusable.ID)

	// Reject with a proof, on an effect that would need one to be approved.
	high := f.escalatedEffect(f.stepUpRequester(), "merge-1", highType)
	rejectProof := stepUpProof()
	rejected, _, err := f.svc.Reject(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(high, "not now"), rejectProof))
	must(t, err)
	wantState(t, "a rejection with a proof", rejected, "REJECTED", contracts.ReasonApprovalRejected)
	f.wantNoProofRecord(high.ID)
	if n := f.replayRows(rejectProof.Token.ID); n != 0 {
		t.Fatal("a rejection used up a proof")
	}
}

// Step-up follows the risk re-admission recomputes, and the proof satisfies
// it: an approval of a class raised since the escalation uses the proof it
// carries, and one of a class lowered since keeps needing the proof the
// stored class asked for.
func TestPostgresStepUpProofFollowsARiskChangedAfterEscalation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	setRisk := func(effectType, risk string) {
		f.ownerTx(tenantA, func(tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE authority_effect_types SET risk_class = $3, version = version + 1
				WHERE tenant_id = $1 AND effect_type = $2`, tenantA, effectType, risk)
			return err
		})
	}

	raised := f.escalated("raised")
	if raised.RiskClass != "medium" {
		t.Fatalf("escalated at %s, want medium", raised.RiskClass)
	}
	setRisk(effectargs.GitHubPullRequestCreateDraft, "high")
	proof := stepUpProof()
	approved, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(raised, ""), proof))
	must(t, err)
	wantState(t, "a risk raised after escalation, with a proof", approved, "ADMITTED", "")
	if approved.RiskClass != "high" {
		t.Fatalf("re-admitted at %s, want high", approved.RiskClass)
	}
	f.wantProofRecord(raised.ID, proof)

	requester := f.stepUpRequester()
	lowered := f.escalatedEffect(requester, "merge-1", highType)
	setRisk(highType, "medium")
	_, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(lowered, ""))
	wantRefusal(t, "a class lowered after escalation, without a proof", err, CodePermissionDenied, contracts.ReasonStepUpRequired)
	f.wantStillEscalated("a lowered class without a proof", lowered)
	loweredProof := stepUpProof()
	approved, _, err = f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(lowered, ""), loweredProof))
	must(t, err)
	wantState(t, "a class lowered after escalation, with a proof", approved, "ADMITTED", "")
	f.wantProofRecord(lowered.ID, loweredProof)
}

// The approval record carries its proof whole or not at all, and only an
// approval carries one.
func TestPostgresApprovalRecordKeepsTheWholeProofOrNone(t *testing.T) {
	f := newFixture(t)
	requester := f.stepUpRequester()
	approvedAttempt := f.escalatedEffect(requester, "merge-1", highType)
	proof := stepUpProof()
	_, _, err := f.svc.Approve(context.Background(), approverB, decideToken("helm.gateway.decide"), withProof(approval(approvedAttempt, ""), proof))
	must(t, err)
	rejectedAttempt := f.escalatedEffect(requester, "merge-2", highType)
	_, _, err = f.svc.Reject(context.Background(), approverB, decideToken("helm.gateway.decide"), approval(rejectedAttempt, "no"))
	must(t, err)

	update := func(where, set string) string {
		return `UPDATE authority_approvals SET ` + set + ` WHERE attempt_id = '` + where + `'`
	}
	for name, statement := range map[string]string{
		"the issuer of an approval's proof removed": update(approvedAttempt.ID, `step_up_issuer = NULL`),
		"the method of an approval's proof removed": update(approvedAttempt.ID, `step_up_method = NULL`),
		"the compact proof of an approval removed":  update(approvedAttempt.ID, `step_up_proof = NULL`),
		"an empty jti":                    update(approvedAttempt.ID, `step_up_jti = ''`),
		"an empty compact proof":          update(approvedAttempt.ID, `step_up_proof = ''`),
		"a compact proof past 8192 bytes": update(approvedAttempt.ID, `step_up_proof = repeat('a', 8193)`),
		"a jti alone on a rejection":      update(rejectedAttempt.ID, `step_up_jti = 'x'`),
		"a whole proof on a rejection": update(rejectedAttempt.ID,
			`step_up_issuer = 'i', step_up_jti = 'x', step_up_method = 'webauthn', step_up_proof = 'p'`),
	} {
		tx, err := f.owner.Begin()
		must(t, err)
		_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenantA)
		must(t, err)
		_, err = tx.Exec(statement)
		_ = tx.Rollback()
		if err == nil || !strings.Contains(err.Error(), "authority_approvals_step_up_proof") {
			t.Errorf("%s: err = %v, want the step-up check constraint", name, err)
		}
	}
	f.ownerTx(tenantA, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE authority_approvals SET step_up_proof = repeat('a', 8192) WHERE attempt_id = $1`, approvedAttempt.ID)
		return err
	})
}
