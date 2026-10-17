package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/activitytrail"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

// ActivityReader is the source-owned read API; it cannot change activity or
// create governance objects. The main runtime supplies *activitytrail.Service.
type ActivityReader interface {
	CoverageMap(context.Context, activitytrail.Scope) (activitytrail.Coverage, error)
	ListObservations(context.Context, activitytrail.Scope, activitytrail.Page) ([]activitytrail.Observation, string, error)
	ListOwnerExceptions(context.Context, activitytrail.Scope, activitytrail.Page) ([]activitytrail.OwnerException, string, error)
}

// ActivityServer serves only authenticated, tenant-scoped activity reads.
type ActivityServer struct {
	gatewayv1.UnimplementedActivityTrailServiceHandler
	Trail ActivityReader
	Auth  *Authenticator
}

// Handler returns a bounded Connect handler. Runtime registration is separate.
func (s *ActivityServer) Handler() (string, http.Handler) {
	path, handler := gatewayv1.NewActivityTrailServiceHandler(s, connect.WithReadMaxBytes(MaxMessageBytes))
	return path, http.MaxBytesHandler(withTLSState(handler), MaxBodyBytes)
}

func (s *ActivityServer) scope(ctx context.Context, header http.Header, repository string) (activitytrail.Scope, error) {
	if s.Auth == nil || s.Trail == nil {
		return activitytrail.Scope{}, rpcError(connect.CodeUnavailable, "", true, errors.New("activity trail is unavailable"))
	}
	id, err := s.Auth.Authenticate(ctx, header, ScopeRead)
	if err != nil {
		return activitytrail.Scope{}, err
	}
	scope := activitytrail.Scope{TenantID: id.TenantID, WorkspaceID: id.WorkspaceID, Repository: repository}
	if err := scope.Validate(); err != nil {
		return activitytrail.Scope{}, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, err)
	}
	return scope, nil
}

func activityPage(size int32, cursor string) (activitytrail.Page, error) {
	if size < 0 || size > 100 || len(cursor) > 1024 {
		return activitytrail.Page{}, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, errors.New("page size or page token is invalid"))
	}
	return activitytrail.Page{Limit: int(size), After: cursor}, nil
}

func activityReadError(ctx context.Context, method string, err error) error {
	if errors.Is(err, activitytrail.ErrInvalidPage) {
		return rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, err)
	}
	if errors.Is(err, activitytrail.ErrNotEnabled) {
		return rpcError(connect.CodeFailedPrecondition, "", false, err)
	}
	return toRPCError(ctx, method, err)
}

func (s *ActivityServer) GetCoverage(ctx context.Context, req *connect.Request[gatewayv1.GetCoverageRequest]) (*connect.Response[gatewayv1.GetCoverageResponse], error) {
	scope, err := s.scope(ctx, req.Header(), req.Msg.GetRepository())
	if err != nil {
		return nil, err
	}
	coverage, err := s.Trail.CoverageMap(ctx, scope)
	if err != nil {
		return nil, activityReadError(ctx, "GetActivityCoverage", err)
	}
	return connect.NewResponse(&gatewayv1.GetCoverageResponse{Coverage: activityCoverageProto(coverage)}), nil
}

func (s *ActivityServer) ListObservations(ctx context.Context, req *connect.Request[gatewayv1.ListObservationsRequest]) (*connect.Response[gatewayv1.ListObservationsResponse], error) {
	scope, err := s.scope(ctx, req.Header(), req.Msg.GetRepository())
	if err != nil {
		return nil, err
	}
	page, err := activityPage(req.Msg.GetPageSize(), req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	items, next, err := s.Trail.ListObservations(ctx, scope, page)
	if err != nil {
		return nil, activityReadError(ctx, "ListActivityObservations", err)
	}
	out := &gatewayv1.ListObservationsResponse{NextPageToken: next}
	for _, item := range items {
		out.Observations = append(out.Observations, activityObservationProto(item))
	}
	return connect.NewResponse(out), nil
}

func (s *ActivityServer) ListOwnerExceptions(ctx context.Context, req *connect.Request[gatewayv1.ListOwnerExceptionsRequest]) (*connect.Response[gatewayv1.ListOwnerExceptionsResponse], error) {
	scope, err := s.scope(ctx, req.Header(), req.Msg.GetRepository())
	if err != nil {
		return nil, err
	}
	page, err := activityPage(req.Msg.GetPageSize(), req.Msg.GetPageToken())
	if err != nil {
		return nil, err
	}
	items, next, err := s.Trail.ListOwnerExceptions(ctx, scope, page)
	if err != nil {
		return nil, activityReadError(ctx, "ListOwnerExceptions", err)
	}
	out := &gatewayv1.ListOwnerExceptionsResponse{NextPageToken: next}
	for _, item := range items {
		out.Exceptions = append(out.Exceptions, &gatewayv1.OwnerException{
			Observation: activityObservationProto(item.Observation), Reason: item.Reason})
	}
	return connect.NewResponse(out), nil
}

func activityTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func activityCoverageProto(c activitytrail.Coverage) *gatewayv1.ActivityCoverage {
	return &gatewayv1.ActivityCoverage{Repository: c.Repository, Class: c.Class, Enabled: c.Enabled,
		DefaultBranch: c.DefaultBranch, HeadSha: c.HeadSHA, LastPollAt: activityTimestamp(c.LastPollAt),
		LastPollError: c.LastPollError, LastEventPollAt: activityTimestamp(c.LastEventPollAt),
		NextEventPollAt: activityTimestamp(c.NextEventPollAt), EventWindowCapped: c.EventWindowCapped,
		AttributionComplete: c.AttributionComplete, UnattributedCount: c.UnattributedCount}
}

func activityObservationProto(o activitytrail.Observation) *gatewayv1.ActivityObservation {
	return &gatewayv1.ActivityObservation{Repository: o.Repository, Ref: o.Ref, BeforeSha: o.BeforeSHA,
		AfterSha: o.AfterSHA, FactDigest: o.FactDigest, ActorLogin: o.ActorLogin,
		ProviderTime: activityTimestamp(o.ProviderTime), ObservedAt: timestamppb.New(o.ObservedAt),
		Source: o.Source, Coverage: o.Coverage, Governed: o.Governed}
}
