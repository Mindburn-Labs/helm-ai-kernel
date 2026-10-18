package server

// The read-only principal Stop outcome on the Connect wire, against a real
// PostgreSQL ledger. The admission package proves the claim and read-back.

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func TestPostgresPrincipalStopOutcomeOnTheWire(t *testing.T) {
	client, iss, _ := newWire(t)
	ctx := context.Background()
	propose := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	read := iss.token(t, testAudience, "tenant-a", "human-b", ScopeRead)
	before, err := client.Propose(ctx, withToken(branchRequest("outcome-before", "helm/outcome-before"), propose))
	must(t, err)
	if before.Msg.GetAttempt().GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED {
		t.Fatalf("pre-Stop attempt = %+v", before.Msg.GetAttempt())
	}
	stopReq := &gatewayv1.StopRequest{IdempotencyKey: "outcome-stop", ScopeKind: gatewayv1.StopScopeKind_STOP_SCOPE_KIND_PRINCIPAL,
		ScopeKey: "human-a", Reason: "seat freeze"}
	stopToken := iss.token(t, testAudience, "tenant-a", "human-b", ScopeStop,
		bound("helm_stop", map[string]string{"idempotency_key": "outcome-stop", "scope_kind": "principal", "scope_key": "human-a"}))
	stopped, err := client.Stop(ctx, withToken(stopReq, stopToken))
	must(t, err)
	after, err := client.Propose(ctx, withToken(branchRequest("outcome-after", "helm/outcome-after"), propose))
	must(t, err)
	if after.Msg.GetAttempt().GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_DENIED ||
		after.Msg.GetAttempt().GetReasonCode() != string(contracts.ReasonEmergencyStopFenced) {
		t.Fatalf("post-Stop attempt = %+v", after.Msg.GetAttempt())
	}
	get := &gatewayv1.GetStopOutcomeRequest{StopId: stopped.Msg.GetStop().GetStopId()}
	outcome, err := client.GetStopOutcome(ctx, withToken(get, read))
	must(t, err)
	if !outcome.Msg.GetActive() || outcome.Msg.GetStop().GetStopId() != get.GetStopId() ||
		len(outcome.Msg.GetAwaitingClaimAttemptIds()) != 1 || outcome.Msg.GetAwaitingClaimAttemptIds()[0] != before.Msg.GetAttempt().GetAttemptId() ||
		len(outcome.Msg.GetBlockedAdmissionAttemptIds()) != 1 || outcome.Msg.GetBlockedAdmissionAttemptIds()[0] != after.Msg.GetAttempt().GetAttemptId() ||
		len(outcome.Msg.GetCheckingAttemptIds()) != 0 || len(outcome.Msg.GetVoidedAtClaimAttemptIds()) != 0 {
		t.Fatalf("Stop outcome = %+v", outcome.Msg)
	}
	_, err = client.GetStopOutcome(ctx, withToken(get, stopToken))
	wantRPCError(t, "a stop token on the read RPC", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	otherTenant := iss.token(t, testAudience, "tenant-b", "human-b", ScopeRead)
	_, err = client.GetStopOutcome(ctx, withToken(get, otherTenant))
	wantRPCError(t, "another tenant", err, connect.CodeNotFound, "")
	otherWorkspace := iss.token(t, testAudience, "tenant-a", "human-b", ScopeRead,
		func(c *tokenClaims) { c.WorkspaceID = "ws-b" })
	view, err := client.GetStopOutcome(ctx, withToken(get, otherWorkspace))
	must(t, err)
	if len(view.Msg.GetAwaitingClaimAttemptIds()) != 0 || len(view.Msg.GetBlockedAdmissionAttemptIds()) != 0 {
		t.Fatalf("another workspace saw attempts: %+v", view.Msg)
	}
}
