package admission

// The owner's passkey assertion inside the approval transaction
// (helm-tracker#334) against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): Approve verifies a present assertion
// against the approver's enrolled passkey, keeps it on the approval record,
// stores its counter and records it once; with Config.OwnerAssertionRequired
// only it satisfies the step-up of an authority widening. A refusal uses up
// nothing. A provision plan enrols the passkeys of the humans it adds. The
// wire proofs, genesis included, are in package server.
//
// quantum_posture: verifies classical ES256 and Ed25519 test assertions; no
// post-quantum claim.

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/passkey"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// enrollPasskey records k as principal's passkey the way an applied plan does.
func (f *fixture) enrollPasskey(tenant, principal string, k *passkey.Authenticator) {
	f.t.Helper()
	f.exec(tenant, `INSERT INTO authority_principal_credentials
		(tenant_id, credential_id, principal_id, alg, public_key_spki, rp_id, enrolled_by, enrolled_attempt_id)
		VALUES ($1, $2, $3, $4, $5, $6, 'plan', gen_random_uuid())`, tenant, k.ID, principal, k.Alg, k.SPKI, k.RPID)
}

// withOwner is the approval of a by approver with k's assertion over the
// approver's challenge for it.
func withOwner(t *testing.T, in DecideInput, approver Caller, a Attempt, k *passkey.Authenticator) DecideInput {
	assertion := assertionOf(k.Assert(t, OwnerChallengeV1(approver.TenantID, approver.PrincipalID, a.ID, a.ApprovalDigest)))
	in.OwnerAssertion = &assertion
	return in
}

// ownerService is the plan fixture's service with owner assertions required.
func (f *planFixture) ownerService(extra ...adapters.Adapter) *Service {
	f.t.Helper()
	svc, err := New(f.runtime, Config{ReceiptSigner: testReceiptSigner, OwnerAssertionRequired: true,
		Adapters: append([]adapters.Adapter{f.adapter}, extra...)})
	must(f.t, err)
	return svc
}

// Known good, flag off: the owner's assertion alone satisfies the step-up of a
// provision plan; the record keeps it with its challenge and counter, the
// counter is stored, the assertion is recorded once, and the receipt binding
// is unchanged (it names no step-up proof, since none was used).
func TestPostgresOwnerAssertionApprovesAWideningAndIsKept(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	k := passkey.New(t, passkey.ES256, testRPID)
	f.enrollPasskey(tenantA, "human-b", k)
	raw := f.plan(effectargs.AuthorityProvision, "", "v1", nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("prov-owner", effectargs.AuthorityProvision, raw))
	must(t, err)
	got, err := f.svc.Get(ctx, approverB, a.ID)
	must(t, err)
	challenge := OwnerChallengeV1(tenantA, "human-b", a.ID, a.ApprovalDigest)
	if string(got.OwnerChallenge) != string(challenge) {
		t.Fatal("the approver reads another owner challenge than it signs")
	}

	in := withOwner(t, approval(a, "the owner approves"), approverB, a, k)
	decide := decideToken("helm.gateway.decide")
	approved, _, err := f.svc.Approve(ctx, approverB, decide, in)
	must(t, err)
	wantState(t, "approved with the owner's assertion", approved, "ADMITTED", "")
	if approved.Approval == nil || string(approved.Approval.OwnerCredentialID) != string(k.ID) {
		t.Fatalf("approval = %+v", approved.Approval)
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_approvals WHERE attempt_id = $1 AND owner_credential_id = $2
		AND owner_challenge = $3 AND owner_authenticator_data = $4 AND owner_client_data_json = $5 AND owner_signature = $6
		AND owner_sign_count = 1 AND step_up_jti IS NULL`, a.ID, k.ID, challenge, in.OwnerAssertion.AuthenticatorData,
		in.OwnerAssertion.ClientDataJSON, in.OwnerAssertion.Signature); n != 1 {
		t.Fatal("the approval does not keep the verified assertion exactly")
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_principal_credentials WHERE credential_id = $1 AND sign_count = 1`, k.ID); n != 1 {
		t.Fatal("the counter the assertion carried was not stored")
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_token_replay WHERE issuer = 'helm.gateway.owner-assertion'`); n != 1 {
		t.Fatal("the assertion was not recorded once")
	}
	if f.replayRows(decide.ID) != 1 {
		t.Fatal("the decide token was not used up")
	}
	receipts, err := f.svc.GetReceipts(ctx, organization, a.ID)
	must(t, err)
	if len(receipts) < 2 {
		t.Fatalf("%d receipts", len(receipts))
	}
	var bound map[string]any
	must(t, json.Unmarshal(receipts[len(receipts)-1].Binding, &bound))
	if bound["approver_principal_id"] != "human-b" || bound["step_up_jti"] != "" {
		t.Fatalf("the admission receipt binds %v / %v", bound["approver_principal_id"], bound["step_up_jti"])
	}
}

// Known good and bad, flag on: only the approver's assertion satisfies the
// step-up of an authority widening; the Control Plane's step-up proof alone is
// OWNER_ASSERTION_REQUIRED and uses nothing up. A high-risk effect that is not
// an authority change still takes the proof.
func TestPostgresOwnerAssertionRequiredRefusesTheIssuersProofForWidenings(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	svc := f.ownerService()
	k := passkey.New(t, passkey.EdDSA, testRPID)
	f.enrollPasskey(tenantA, "human-b", k)
	raw := f.plan(effectargs.AuthorityProvision, "", "v1", nil)
	a, _, err := svc.Propose(ctx, organization, planProposal("prov-required", effectargs.AuthorityProvision, raw))
	must(t, err)

	decide, proof := decideToken("helm.gateway.decide"), stepUpProof()
	_, _, err = svc.Approve(ctx, approverB, decide, withProof(approval(a, "issuer only"), proof))
	wantRefusal(t, "a widening with the issuer's proof alone", err, CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)
	f.wantStillEscalated("the refused approval", a)
	if f.replayRows(decide.ID, proof.Token.ID) != 0 {
		t.Fatal("the refused approval used up a token")
	}
	_, _, err = svc.Approve(ctx, approverB, decide, approval(a, "nothing"))
	wantRefusal(t, "a widening with nothing", err, CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)

	// The same decide token is still good: the owner's assertion approves.
	approved, _, err := svc.Approve(ctx, approverB, decide, withOwner(t, withProof(approval(a, "the owner"), proof), approverB, a, k))
	must(t, err)
	wantState(t, "the owner's approval", approved, "ADMITTED", "")
	// The proof that rode along was not used: the owner's act was.
	if f.replayRows(proof.Token.ID) != 0 {
		t.Fatal("the step-up proof was used up beside the owner's assertion")
	}

	// A merge is high risk but no authority change: the proof still serves.
	requester := f.stepUpRequester()
	merge := f.escalatedEffect(requester, "merge-required", highType)
	admitted, _, err := svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), withProof(approval(merge, "merge"), stepUpProof()))
	must(t, err)
	wantState(t, "a high-risk effect with a step-up proof", admitted, "ADMITTED", "")
}

// Known bad: every assertion that is not the approver's act over this attempt
// is refused, the attempt stays ESCALATED and nothing is used up, so the one
// decide token is then good for the valid approval.
func TestPostgresOwnerAssertionRefusalsSpendNothing(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	k := passkey.New(t, passkey.ES256, testRPID)
	c := passkey.New(t, passkey.ES256, testRPID)
	f.enrollPasskey(tenantA, "human-b", k)
	f.enrollPasskey(tenantA, "human-c", c)
	raw := f.plan(effectargs.AuthorityProvision, "", "v1", nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("prov-refusals", effectargs.AuthorityProvision, raw))
	must(t, err)
	challenge := OwnerChallengeV1(tenantA, "human-b", a.ID, a.ApprovalDigest)
	decide := decideToken("helm.gateway.decide")
	forged := assertionOf(k.Assert(t, challenge))
	forged.Signature = append([]byte(nil), forged.Signature...)
	forged.Signature[len(forged.Signature)-2] ^= 0x40
	wrongKey := assertionOf(passkey.New(t, passkey.ES256, testRPID).Assert(t, challenge))
	wrongKey.CredentialID = k.ID
	for name, bad := range map[string]OwnerAssertion{
		"a forged signature":              forged,
		"the owner's key, another digest": assertionOf(k.Assert(t, OwnerChallengeV1(tenantA, "human-b", a.ID, make([]byte, 32)))),
		"another attempt's challenge":     assertionOf(k.Assert(t, OwnerChallengeV1(tenantA, "human-b", "attempt-x", a.ApprovalDigest))),
		"another key under the id":        wrongKey,
		"another human's passkey":         assertionOf(c.Assert(t, OwnerChallengeV1(tenantA, "human-c", a.ID, a.ApprovalDigest))),
		"an unenrolled passkey":           assertionOf(passkey.New(t, passkey.EdDSA, testRPID).Assert(t, challenge)),
		"another relying party":           assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) { p.RPID = "evil.example" })),
		"no user verification":            assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) { p.Flags = 0x01 })),
		"a registration ceremony": assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) {
			p.ClientData["type"] = "webauthn.create"
		})),
		"a challenge in padded base64": assertionOf(k.AssertWith(t, challenge, func(p *passkey.Parts) {
			p.ClientData["challenge"] = base64.URLEncoding.EncodeToString(challenge)
		})),
	} {
		in := approval(a, name)
		in.OwnerAssertion = &bad
		_, _, err := f.svc.Approve(ctx, approverB, decide, withProof(in, stepUpProof()))
		wantRefusal(t, name, err, CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)
		f.wantStillEscalated(name, a)
	}
	if f.replayRows(decide.ID) != 0 || f.count(tenantA, `SELECT count(*) FROM authority_token_replay WHERE issuer = 'helm.gateway.owner-assertion'`) != 0 {
		t.Fatal("a refused approval used something up")
	}
	// The counter never goes backwards: one that does is refused, and the
	// stored one stays.
	f.exec(tenantA, `UPDATE authority_principal_credentials SET sign_count = 100 WHERE credential_id = $1`, k.ID)
	_, _, err = f.svc.Approve(ctx, approverB, decide, withOwner(t, approval(a, "behind"), approverB, a, k))
	wantRefusal(t, "a counter behind the stored one", err, CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)
	k.Counter = 200
	approved, _, err := f.svc.Approve(ctx, approverB, decide, withOwner(t, approval(a, "valid"), approverB, a, k))
	must(t, err)
	wantState(t, "the valid approval", approved, "ADMITTED", "")
}

// The same signed assertion is accepted once, even from an authenticator that
// keeps no counter: the second presentation is refused in its own
// transaction.
func TestPostgresOwnerAssertionIsAcceptedOnce(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	k := passkey.New(t, passkey.EdDSA, testRPID)
	k.Counting = false
	f.enrollPasskey(tenantA, "human-b", k)
	raw := f.plan(effectargs.AuthorityProvision, "", "v1", nil)
	a, _, err := f.svc.Propose(ctx, organization, planProposal("prov-once", effectargs.AuthorityProvision, raw))
	must(t, err)
	assertion := assertionOf(k.Assert(t, OwnerChallengeV1(tenantA, "human-b", a.ID, a.ApprovalDigest)))
	present := func() error {
		return f.svc.inTenant(ctx, tenantA, func(tx *sql.Tx) error {
			locked, err := lockAttempt(ctx, tx, approverB, a.ID)
			if err != nil {
				return err
			}
			_, err = verifyOwnerAssertion(ctx, tx, approverB, locked, assertion)
			return err
		})
	}
	must(t, present())
	wantRefusal(t, "the same assertion again", present(), CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)
	// The schema holds the counter too: it never goes backwards, and the key
	// of an enrolled passkey never changes.
	f.exec(tenantA, `UPDATE authority_principal_credentials SET sign_count = 7 WHERE credential_id = $1`, k.ID)
	for name, stmt := range map[string]string{
		"a counter that goes backwards": `UPDATE authority_principal_credentials SET sign_count = 6 WHERE credential_id = $1`,
		"a replaced key":                `UPDATE authority_principal_credentials SET public_key_spki = '\x00' WHERE credential_id = $1`,
		"another holder":                `UPDATE authority_principal_credentials SET principal_id = 'human-c' WHERE credential_id = $1`,
	} {
		err := f.svc.inTenant(ctx, tenantA, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, stmt, k.ID)
			return err
		})
		if err == nil {
			t.Errorf("%s was written", name)
		}
	}
}

// A provision plan enrols the passkeys of the humans it lists; once applied,
// such a human approves with its own assertion. A credential id the tenant
// has for another key is refused, and the plan applies nothing.
func TestPostgresProvisionPlanEnrolsAHumansPasskey(t *testing.T) {
	f := newPlanFixture(t)
	ctx := context.Background()
	k := passkey.New(t, passkey.ES256, testRPID)
	credential := map[string]any{"credential_id": base64.RawURLEncoding.EncodeToString(k.ID), "alg": k.Alg,
		"public_key_spki": base64.RawURLEncoding.EncodeToString(k.SPKI), "rp_id": k.RPID}
	withApprover := func(cred map[string]any) func(map[string]any) {
		return func(d map[string]any) {
			d["principals"] = append(d["principals"].([]any), map[string]any{"id": "usr_reviewer", "kind": "human",
				"external_subject": map[string]any{"system": "helm-control-plane", "id": "usr_reviewer"},
				"credentials":      []any{cred}})
		}
	}
	raw := f.plan(effectargs.AuthorityProvision, "", "v1", withApprover(credential))
	f.applyBase(tenantA, raw)
	if n := f.count(tenantA, `SELECT count(*) FROM authority_principal_credentials WHERE principal_id = 'usr_reviewer'
		AND credential_id = $1 AND enrolled_by = 'plan' AND enrolled_attempt_id IS NOT NULL`, k.ID); n != 1 {
		t.Fatal("the plan's passkey was not enrolled")
	}
	// The enrolled reviewer approves a later widening with its own passkey.
	next := f.plan(effectargs.AuthorityProvision, f.provisioning(tenantA).Digest, "v2", func(d map[string]any) {
		withApprover(credential)(d)
		limits(90, 70)(d)
	})
	reviewer := Caller{TenantID: tenantA, WorkspaceID: workspace, PrincipalID: "usr_reviewer", ActorID: actor}
	svc := f.ownerService()
	a, _, err := svc.Propose(ctx, organization, planProposal("prov-reviewer", effectargs.AuthorityProvision, next))
	must(t, err)
	approved, _, err := svc.Approve(ctx, reviewer, decideToken("helm.gateway.decide"), withOwner(t, approval(a, "reviewer"), reviewer, a, k))
	must(t, err)
	wantState(t, "the plan-enrolled reviewer's approval", approved, "ADMITTED", "")

	// The same credential id under another key is an identity conflict.
	other := passkey.New(t, passkey.ES256, testRPID)
	clash := map[string]any{"credential_id": credential["credential_id"], "alg": other.Alg,
		"public_key_spki": base64.RawURLEncoding.EncodeToString(other.SPKI), "rp_id": other.RPID}
	conflicting := f.plan(effectargs.AuthorityProvision, "", "v1", withApprover(clash))
	r := f.dispatchPlan(tenantB, effectargs.AuthorityProvision, conflicting)
	if r.Status != adapters.DispatchSent {
		t.Fatalf("a first enrolment in tenant b: %+v", r)
	}
	if n := f.count(tenantB, `SELECT count(*) FROM authority_principal_credentials WHERE tenant_id = $1`, tenantB); n != 1 {
		t.Fatal("tenant b's enrolment is missing")
	}
	clashing := f.plan(effectargs.AuthorityProvision, f.provisioning(tenantB).Digest, "v2", func(d map[string]any) {
		withApprover(credential)(d)
		limits(90, 70)(d)
	})
	wantNotSent(t, "a credential id the tenant has for another key", f.dispatchPlan(tenantB, effectargs.AuthorityProvision, clashing),
		contracts.ReasonIdentityIsolationViolation)

	// A narrowing plan enrols none, and only a human has passkeys.
	narrow := f.plan(effectargs.AuthorityNarrow, f.provisioning(tenantA).Digest, "v3", withApprover(credential))
	if _, err := effectargs.ParsePlan(effectargs.AuthorityNarrow, narrow); err == nil {
		t.Fatal("a narrowing plan with a passkey parsed")
	}
	service := f.plan(effectargs.AuthorityProvision, "", "v4", func(d map[string]any) {
		d["principals"].([]any)[0].(map[string]any)["credentials"] = []any{credential}
	})
	if _, err := effectargs.ParsePlan(effectargs.AuthorityProvision, service); err == nil {
		t.Fatal("a service with a passkey parsed")
	}
	// Row security: tenant b reads none of tenant a's passkeys.
	var visible int
	must(t, f.svc.inTenant(ctx, tenantB, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM authority_principal_credentials WHERE tenant_id = $1`, tenantA).Scan(&visible)
	}))
	if visible != 0 {
		t.Fatalf("tenant b reads %d of tenant a's passkeys", visible)
	}
}
