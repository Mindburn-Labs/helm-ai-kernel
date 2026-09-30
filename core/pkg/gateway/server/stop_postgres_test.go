package server

// Stop, Lift and a stop token's Cancel on the wire, against real PostgreSQL
// 16 (listed in scripts/ci/postgres-proofs.txt): each single-use stop token
// names its object in authorization_details.
//
// quantum_posture: signs classical RS256 test tokens; no post-quantum claim.

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func bound(detailType string, fields map[string]string) func(*tokenClaims) {
	return func(c *tokenClaims) {
		entry := map[string]any{"type": detailType}
		for k, v := range fields {
			entry[k] = v
		}
		c.AuthorizationDetails = []map[string]any{entry}
	}
}

func TestPostgresStopLiftAndCancelOnTheWire(t *testing.T) {
	client, iss, db := newWire(t)
	ctx := context.Background()
	propose := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	stopAs := func(edit ...func(*tokenClaims)) string {
		return iss.token(t, testAudience, "tenant-a", "human-b", ScopeStop, edit...)
	}

	// Cancel with an operator's stop token names the attempt (L4).
	resp, err := client.Propose(ctx, withToken(noteRequest("cancel-me"), propose))
	must(t, err)
	id := resp.Msg.GetAttempt().GetAttemptId()
	cancel := func(token string) error {
		_, err := client.Cancel(ctx, withToken(&gatewayv1.CancelRequest{AttemptId: id}, token))
		return err
	}
	wantRPCError(t, "an unbound stop token on Cancel", cancel(stopAs()), connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	wantRPCError(t, "a stop token bound to another attempt", cancel(stopAs(bound("helm_effect_cancel", map[string]string{"attempt_id": "0192f0c4-7a1e-7c3b-9d2a-000000000000"}))),
		connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	must(t, cancel(stopAs(bound("helm_effect_cancel", map[string]string{"attempt_id": id}))))

	// Stop: the tenant, by a human operator.
	stopRequest := &gatewayv1.StopRequest{IdempotencyKey: "stop-1", ScopeKind: gatewayv1.StopScopeKind_STOP_SCOPE_KIND_TENANT, Reason: "incident"}
	stopBinding := bound("helm_stop", map[string]string{"idempotency_key": "stop-1", "scope_kind": "tenant", "scope_key": ""})
	// A stop token minted to cancel, or bound to another stop, cannot stop
	// the tenant (L1).
	for name, token := range map[string]string{
		"unbound":             stopAs(),
		"minted for a Cancel": stopAs(bound("helm_effect_cancel", map[string]string{"attempt_id": id})),
		"another key":         stopAs(bound("helm_stop", map[string]string{"idempotency_key": "stop-x", "scope_kind": "tenant", "scope_key": ""})),
		"another scope":       stopAs(bound("helm_stop", map[string]string{"idempotency_key": "stop-1", "scope_kind": "principal", "scope_key": "human-a"})),
	} {
		_, err := client.Stop(ctx, withToken(stopRequest, token))
		wantRPCError(t, name+" stop token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
	stopped, err := client.Stop(ctx, withToken(stopRequest, stopAs(stopBinding)))
	must(t, err)
	stop := stopped.Msg.GetStop()
	if stopped.Msg.GetExisting() || stop.GetStopId() == "" || stop.GetScopeKind() != gatewayv1.StopScopeKind_STOP_SCOPE_KIND_TENANT ||
		stop.GetCreatedByPrincipalId() != "human-b" || stop.GetScopeKey() != "" {
		t.Fatalf("Stop = %+v", stopped.Msg)
	}
	denied, err := client.Propose(ctx, withToken(noteRequest("after-stop"), propose))
	must(t, err)
	if denied.Msg.GetAttempt().GetReasonCode() != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("a proposal under the stop = %+v", denied.Msg.GetAttempt())
	}
	_, err = client.Stop(ctx, withToken(&gatewayv1.StopRequest{IdempotencyKey: "stop-2",
		ScopeKind: gatewayv1.StopScopeKind_STOP_SCOPE_KIND_TENANT, Reason: "x"}, propose))
	wantRPCError(t, "a propose token on Stop", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	_, err = client.Stop(ctx, withToken(&gatewayv1.StopRequest{IdempotencyKey: "stop-3", Reason: "x"}, stopAs()))
	wantRPCError(t, "no scope kind", err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)

	// Lift: the token names the stop; the attempt waits for a distinct
	// approver with step-up.
	rows, err := authorityrows.New(db)
	must(t, err)
	must(t, rows.CreateEffectType(ctx, "tenant-a", effectargs.AuthorityLift, authorityrows.RiskLow))
	now := time.Now()
	_, err = rows.CreateMandate(ctx, "tenant-a", "human-b", authorityrows.Terms{EffectTypes: []string{effectargs.AuthorityLift},
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}, authorityrows.WideningApproval{RequesterID: "agent-a", ApproverID: "human-a"})
	must(t, err)
	lift := func(token string) (*connect.Response[gatewayv1.LiftResponse], error) {
		return client.Lift(ctx, withToken(&gatewayv1.LiftRequest{IdempotencyKey: "lift-1", StopId: stop.GetStopId()}, token))
	}
	_, err = lift(stopAs())
	wantRPCError(t, "an unbound lift token", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	_, err = lift(stopAs(bound("helm_stop_lift", map[string]string{"stop_id": "0192f0c4-7a1e-7c3b-9d2a-000000000000"})))
	wantRPCError(t, "a lift token bound to another stop", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	lifted, err := lift(stopAs(bound("helm_stop_lift", map[string]string{"stop_id": stop.GetStopId()})))
	must(t, err)
	attempt := lifted.Msg.GetAttempt()
	if attempt.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED || attempt.GetEffectType() != effectargs.AuthorityLift {
		t.Fatalf("Lift = %+v", lifted.Msg)
	}
}
