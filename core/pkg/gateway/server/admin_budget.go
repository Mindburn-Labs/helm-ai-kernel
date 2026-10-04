package server

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

// GetProvisionBudget serves native amounts for the exact applied authority.
// Neither the request nor a CP projection supplies tenant/workspace identity.
func (s *AdminServer) GetProvisionBudget(ctx context.Context, req *connect.Request[gatewayv1.GetProvisionBudgetRequest]) (*connect.Response[gatewayv1.GetProvisionBudgetResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	b := req.Msg.GetBinding()
	read, err := provision.GetProvisionBudget(ctx, s.Rows, id.TenantID, id.WorkspaceID, id.PrincipalID, provision.BudgetBinding{
		OrgRef: b.GetOrgRef(), VersionRef: b.GetVersionRef(), PlanDigest: b.GetPlanDigest(), Revision: b.GetRevision(),
		Node: b.GetNode(), MandateID: b.GetMandateId(), LimitID: b.GetLimitId(), LimitVersion: b.GetLimitVersion(),
	})
	if err != nil {
		return nil, adminError(ctx, "GetProvisionBudget", err)
	}
	out := &gatewayv1.GetProvisionBudgetResponse{
		Binding: b, AsOf: timestamppb.New(read.AsOf), CoverageComplete: read.CoverageComplete,
		Activity: gatewayv1.ProvisionBudgetActivity_PROVISION_BUDGET_ACTIVITY_NOT_REPORTED,
		Reason:   read.Reason, OverageDetected: read.OverageDetected, EnforcementAvailable: read.EnforcementAvailable,
		EvidenceDigest: read.EvidenceDigest,
	}
	if read.Activity == "no_runs_yet" {
		out.Activity = gatewayv1.ProvisionBudgetActivity_PROVISION_BUDGET_ACTIVITY_NO_RUNS_YET
	} else if read.Activity == "reported" {
		out.Activity = gatewayv1.ProvisionBudgetActivity_PROVISION_BUDGET_ACTIVITY_REPORTED
	}
	if a := read.Amounts; a != nil {
		out.Amounts = &gatewayv1.ProvisionBudgetAmounts{Cap: a.Cap, SpentFinal: a.SpentFinal, SetAside: a.SetAside}
	}
	return connect.NewResponse(out), nil
}
