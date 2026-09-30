package server

// The organization provisioning path end to end on the wire, against real
// PostgreSQL 16 (listed in scripts/ci/postgres-proofs.txt), the way the
// Control Plane drives it: EnsurePrincipals registers the requester, the
// workload and the owner; Propose escalates the provision plan; the owner
// approves with a step-up proof; the workload dispatches and observes; and
// GetProvisioning reads the applied plan. A narrowing plan then needs no
// approval. Nothing here stands in for the gateway: no fixture writes an
// attempt or an approval.
//
// quantum_posture: signs classical RS256 test tokens and computes SHA-256
// digests; no post-quantum claim.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

// e2ePlan renders a plan for adminOrg with a team below it and a daily budget
// on each, for the given effect type and base.
func e2ePlan(t *testing.T, schema, base, version string, org, team int64, now time.Time) []byte {
	t.Helper()
	doc := map[string]any{
		"schema": schema, "org_ref": adminOrg, "version_ref": version, "stage": "approval-required", "base_plan_digest": base,
		"valid_from": now.Add(-time.Minute).UTC().Format(time.RFC3339), "valid_until": now.Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"effect_types": []any{map[string]any{"effect_type": "github.repository.get", "risk_class": "low"}},
		"principals":   []any{map[string]any{"id": adminOrg, "kind": "service"}, map[string]any{"id": adminTeam, "kind": "service"}},
		"mandates": []any{
			map[string]any{"node": adminOrg, "holder": adminOrg, "parent": nil,
				"terms": map[string]any{"effect_types": []string{"github.repository.get"}, "targets": nil}},
			map[string]any{"node": adminTeam, "holder": adminTeam, "parent": adminOrg,
				"terms": map[string]any{"effect_types": []string{"github.repository.get"}, "targets": []string{testRepo}}},
		},
		"limits": []any{
			map[string]any{"node": adminOrg, "unit": "usd_micros", "measure": "sum", "window": "day", "span": 1, "value": org},
			map[string]any{"node": adminTeam, "unit": "usd_micros", "measure": "sum", "window": "day", "span": 1, "value": team},
		},
	}
	raw, err := json.Marshal(doc)
	must(t, err)
	return raw
}

func TestPostgresProvisionAndNarrowEndToEndOnTheWire(t *testing.T) {
	w := newAdminWire(t)
	ctx := context.Background()
	now := time.Now()

	// Bootstrap: the tenant, the organization's service principal (the
	// requester), the workload that carries its calls (the actor) and the
	// owner, a person with an external subject.
	_, err := w.ensure("tenant-a", serviceSpec(adminProvision), serviceSpec(testActor), humanSpec(adminOwner, adminOwner))
	must(t, err)

	// A provision plan is proposed by the requester, carried by the workload,
	// and waits for the owner.
	plan := e2ePlan(t, effectargs.AuthorityProvision, "", "v1", 100, 80, now)
	proposeToken := w.token("tenant-a", adminProvision, ScopePropose)
	proposed, err := w.effects.Propose(ctx, withToken(&gatewayv1.ProposeRequest{
		IdempotencyKey: "provision-v1", WorkRef: &gatewayv1.ProposeRequest_CommitmentId{CommitmentId: "activation-1"},
		Effect: &gatewayv1.EffectDescriptor{EffectType: effectargs.AuthorityProvision, Target: adminOrg, Arguments: plan},
	}, proposeToken))
	must(t, err)
	attempt := proposed.Msg.GetAttempt()
	if attempt.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED || attempt.GetRiskClass() != gatewayv1.RiskClass_RISK_CLASS_IRREVERSIBLE ||
		attempt.GetMandateId() != "" || attempt.GetPendingApproval() == nil || attempt.GetRequesterPrincipalId() != adminProvision {
		t.Fatalf("Propose = %+v", attempt)
	}
	digest := attempt.GetPendingApproval().GetApprovalDigest()

	// The approver reads the plan itself, and is refused without step-up.
	read := w.token("tenant-a", adminOwner, ScopeRead)
	content, err := w.effects.GetAttemptContent(ctx, withToken(&gatewayv1.GetAttemptContentRequest{AttemptId: attempt.GetAttemptId()}, read))
	must(t, err)
	if string(content.Msg.GetArguments()) != string(plan) {
		t.Fatal("the approver is not shown the plan as proposed")
	}
	decide := func(jti string) string {
		return w.iss.token(t, testAudience, "tenant-a", adminOwner, ScopeDecide, decision(attempt.GetAttemptId(), "approve"), jtiOf(jti))
	}
	approve := func(decideToken, proof string) (*gatewayv1.EffectAttempt, error) {
		resp, err := w.effects.Approve(ctx, withToken(&gatewayv1.ApproveRequest{
			AttemptId: attempt.GetAttemptId(), ApprovalDigest: digest, Reason: "the plan is right", StepUpProof: proof,
		}, decideToken))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetAttempt(), nil
	}
	_, err = approve(decide("decide-without-proof"), "")
	wantRPCError(t, "a widening plan approved without step-up", err, connect.CodePermissionDenied, contracts.ReasonStepUpRequired)
	if still, err := get2(w, attempt.GetAttemptId(), read); err != nil ||
		still.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED || still.GetApproval() != nil {
		t.Fatalf("a refused approval changed the attempt: %+v, %v", still, err)
	}

	// Approved with the owner's step-up proof, it is admitted with a permit;
	// nothing is applied before Dispatch.
	proof := w.iss.token(t, testAudience, "tenant-a", adminOwner, ScopeStepUp, jtiOf("proof-1"), binding(attempt.GetAttemptId(), digest, "webauthn"))
	admitted, err := approve(decide("decide-1"), proof)
	must(t, err)
	if admitted.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED || admitted.GetApproval().GetApproverPrincipalId() != adminOwner ||
		admitted.GetPermit().GetPermitId() == "" {
		t.Fatalf("Approve = %+v", admitted)
	}
	_, err = w.client.GetProvisioning(ctx, withToken(&gatewayv1.GetProvisioningRequest{OrgRef: adminOrg}, read))
	wantRPCError(t, "GetProvisioning before Dispatch", err, connect.CodeNotFound, "")

	// The workload dispatches it once and reads it back: applied, by digest.
	execute := w.iss.token(t, testAudience, "tenant-a", testActor, ScopeExecute, func(c *tokenClaims) { c.Act = nil })
	dispatched, err := w.effects.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: attempt.GetAttemptId()}, execute))
	must(t, err)
	got := dispatched.Msg.GetAttempt()
	if got.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_OBSERVED || got.GetOutcome() != gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED {
		t.Fatalf("Dispatch = %s(%s) %q", got.GetState(), got.GetOutcome(), got.GetReasonCode())
	}
	parsed, err := effectargs.ParsePlan(effectargs.AuthorityProvision, plan)
	must(t, err)
	applied, err := w.client.GetProvisioning(ctx, withToken(&gatewayv1.GetProvisioningRequest{OrgRef: adminOrg}, read))
	must(t, err)
	p := applied.Msg.GetProvisioning()
	if p.GetPlanDigest() != parsed.Digest || p.GetRevision() != 1 || p.GetProvisioner() != adminProvision || p.GetAttemptId() != attempt.GetAttemptId() ||
		len(p.GetNodes()) != 2 || !p.GetNodes()[0].GetActive() || !p.GetNodes()[1].GetActive() || p.GetNodes()[1].GetParentNode() != adminOrg {
		t.Fatalf("GetProvisioning = %+v", p)
	}

	// A replayed Dispatch dispatches nothing; the owner's spent proof cannot be
	// used for another approval.
	again, err := w.effects.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: attempt.GetAttemptId()}, execute))
	must(t, err)
	if !again.Msg.GetExisting() {
		t.Fatalf("a second Dispatch = %+v", again.Msg)
	}

	// A plan that only narrows needs no approval: the requester proposes it on
	// the applied digest, it is admitted at once, and Dispatch applies it.
	narrow := e2ePlan(t, effectargs.AuthorityNarrow, p.GetPlanDigest(), "v2", 50, 40, now)
	narrowed, err := w.effects.Propose(ctx, withToken(&gatewayv1.ProposeRequest{
		IdempotencyKey: "narrow-v2", WorkRef: &gatewayv1.ProposeRequest_CommitmentId{CommitmentId: "activation-1"},
		Effect: &gatewayv1.EffectDescriptor{EffectType: effectargs.AuthorityNarrow, Target: adminOrg, Arguments: narrow},
	}, proposeToken))
	must(t, err)
	n := narrowed.Msg.GetAttempt()
	if n.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED || n.GetRiskClass() != gatewayv1.RiskClass_RISK_CLASS_MEDIUM ||
		n.GetApproval() != nil || n.GetPermit().GetPermitId() == "" {
		t.Fatalf("Propose narrow = %+v", n)
	}
	done, err := w.effects.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: n.GetAttemptId()}, execute))
	must(t, err)
	if done.Msg.GetAttempt().GetOutcome() != gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED {
		t.Fatalf("Dispatch narrow = %+v", done.Msg.GetAttempt())
	}
	after, err := w.client.GetProvisioning(ctx, withToken(&gatewayv1.GetProvisioningRequest{OrgRef: adminOrg}, read))
	must(t, err)
	q := after.Msg.GetProvisioning()
	parsedNarrow, err := effectargs.ParsePlan(effectargs.AuthorityNarrow, narrow)
	must(t, err)
	if q.GetPlanDigest() != parsedNarrow.Digest || q.GetRevision() != 2 || q.GetAttemptId() != n.GetAttemptId() ||
		q.GetNodes()[0].GetMandateId() != p.GetNodes()[0].GetMandateId() {
		t.Fatalf("GetProvisioning after narrowing = %+v", q)
	}

	// Only the provisioner narrows: another service principal is refused
	// before any attempt exists.
	_, err = w.ensure("tenant-a", serviceSpec("svc:other"))
	must(t, err)
	_, err = w.effects.Propose(ctx, withToken(&gatewayv1.ProposeRequest{
		IdempotencyKey: "narrow-v3", WorkRef: &gatewayv1.ProposeRequest_CommitmentId{CommitmentId: "activation-1"},
		Effect: &gatewayv1.EffectDescriptor{EffectType: effectargs.AuthorityNarrow, Target: adminOrg,
			Arguments: e2ePlan(t, effectargs.AuthorityNarrow, q.GetPlanDigest(), "v3", 30, 20, now)},
	}, w.token("tenant-a", "svc:other", ScopePropose)))
	wantRPCError(t, "a narrowing plan from another service principal", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
}

// get2 reads an attempt back with the given read token.
func get2(w *adminWire, attemptID, read string) (*gatewayv1.EffectAttempt, error) {
	resp, err := w.effects.GetAttempt(context.Background(), withToken(&gatewayv1.GetAttemptRequest{AttemptId: attemptID}, read))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetAttempt(), nil
}
