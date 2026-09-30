package server

// ListAttempts on the wire without a database (HELM-751): the request the
// handler carries into admission, and what only the wire types can say and
// admission cannot see.

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func TestListInputCarriesTheRequestAndRefusesWhatOnlyTheWireCanSay(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)

	// Known good: every field arrives, states by their stored names.
	in, err := listInput(&gatewayv1.ListAttemptsRequest{
		States:               []gatewayv1.EffectAttemptState{gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED, gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED_TO_HUMAN},
		WorkRef:              &gatewayv1.ListAttemptsRequest_CaseId{CaseId: "case-1"},
		RequesterPrincipalId: "human-a", EffectType: "ops.note", UpdatedAfter: timestamppb.New(at), PageSize: 25, PageToken: "token",
	})
	must(t, err)
	if len(in.States) != 2 || in.States[0] != "ESCALATED" || in.States[1] != "ESCALATED_TO_HUMAN" || in.CaseID != "case-1" || in.CommitmentID != "" ||
		in.RequesterPrincipalID != "human-a" || in.EffectType != "ops.note" || in.PageSize != 25 || in.PageToken != "token" ||
		in.UpdatedAfter == nil || !in.UpdatedAfter.Equal(at) {
		t.Fatalf("listInput = %+v", in)
	}
	in, err = listInput(&gatewayv1.ListAttemptsRequest{WorkRef: &gatewayv1.ListAttemptsRequest_CommitmentId{CommitmentId: "commitment-1"}})
	must(t, err)
	if in.CommitmentID != "commitment-1" || in.CaseID != "" || in.UpdatedAfter != nil || in.States != nil {
		t.Fatalf("listInput = %+v", in)
	}
	// No filter is every attempt.
	in, err = listInput(&gatewayv1.ListAttemptsRequest{})
	must(t, err)
	if in.CommitmentID != "" || in.CaseID != "" || in.PageSize != 0 || in.PageToken != "" {
		t.Fatalf("listInput of an empty request = %+v", in)
	}

	// Known bad: what the wire can say and admission cannot see.
	for name, msg := range map[string]*gatewayv1.ListAttemptsRequest{
		"an unspecified state":              {States: []gatewayv1.EffectAttemptState{gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED, gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_UNSPECIFIED}},
		"a state outside the enum":          {States: []gatewayv1.EffectAttemptState{99}},
		"a negative state":                  {States: []gatewayv1.EffectAttemptState{-1}},
		"a commitment_id set to nothing":    {WorkRef: &gatewayv1.ListAttemptsRequest_CommitmentId{}},
		"a case_id set to nothing":          {WorkRef: &gatewayv1.ListAttemptsRequest_CaseId{}},
		"updated_after past year 9999":      {UpdatedAfter: &timestamppb.Timestamp{Seconds: 253402300800}},
		"updated_after before year 1":       {UpdatedAfter: &timestamppb.Timestamp{Seconds: -62135596801}},
		"updated_after with bad nanos":      {UpdatedAfter: &timestamppb.Timestamp{Seconds: 1, Nanos: 1_000_000_000}},
		"updated_after with negative nanos": {UpdatedAfter: &timestamppb.Timestamp{Seconds: 1, Nanos: -1}},
	} {
		_, err := listInput(msg)
		wantRPCError(t, name, err, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation)
	}
}

func TestStateNameInvertsStateProto(t *testing.T) {
	// UNSPECIFIED names no state, and every other value names the state
	// stateProto renders back to it: the two conversions cannot drift apart.
	if _, ok := stateName(gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_UNSPECIFIED); ok {
		t.Fatal("UNSPECIFIED has a state name")
	}
	if _, ok := stateName(99); ok {
		t.Fatal("a number outside the enum has a state name")
	}
	for number, enumName := range gatewayv1.EffectAttemptState_name {
		state := gatewayv1.EffectAttemptState(number)
		if state == gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_UNSPECIFIED {
			continue
		}
		name, ok := stateName(state)
		if !ok || "EFFECT_ATTEMPT_STATE_"+name != enumName || stateProto(name) != state {
			t.Fatalf("stateName(%s) = %q, %v", enumName, name, ok)
		}
	}
}
