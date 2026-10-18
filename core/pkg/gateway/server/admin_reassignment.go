package server

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

// GetCurrentWorkReassignment is a service-only read of the Kernel's current
// work generation. A revoked grant remains present as the high-water fence.
func (s *AdminServer) GetCurrentWorkReassignment(ctx context.Context, req *connect.Request[gatewayv1.GetCurrentWorkReassignmentRequest]) (*connect.Response[gatewayv1.GetCurrentWorkReassignmentResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	if s.Admission == nil {
		return nil, toRPCError(ctx, "GetCurrentWorkReassignment", errors.New("the reassignment ledger is unavailable"))
	}
	current, err := s.Admission.GetCurrentWorkReassignment(ctx, id.Caller, req.Msg.GetOrgRef(), req.Msg.GetWorkItemId())
	if err != nil {
		return nil, toRPCError(ctx, "GetCurrentWorkReassignment", err)
	}
	out := &gatewayv1.GetCurrentWorkReassignmentResponse{
		Present: current.Present, OrgRef: req.Msg.GetOrgRef(), WorkItemId: req.Msg.GetWorkItemId(),
		Generation: current.Generation,
	}
	if current.Present {
		out.GrantId = current.GrantID
		out.ManifestDigest = current.ManifestDigest
		out.GrantAttemptId = current.GrantAttemptID
		out.Revoked = current.Revoked
		out.RevokedByAttemptId = current.RevokedByAttemptID
		out.ExpiresAt = timestamppb.New(current.ExpiresAt)
		if current.RevokedAt != nil {
			out.RevokedAt = timestamppb.New(*current.RevokedAt)
		}
		out.RecipientEpisodeId = current.RecipientEpisodeID
		out.RecipientSeatId = current.RecipientSeatID
		out.RecipientPrincipalId = current.RecipientPrincipalID
		out.RecipientActorId = current.RecipientActorID
		out.RecipientProfile = current.RecipientProfile
		out.RecipientClient = current.RecipientClient
	}
	return connect.NewResponse(out), nil
}
