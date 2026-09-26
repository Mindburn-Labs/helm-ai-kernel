// Package server serves the gateway effect API (helm.gateway.v1,
// EffectGatewayService) over Connect, gRPC and gRPC-Web on one handler.
//
// Every RPC first verifies the bearer token and its scope; tenant, workspace
// and principal come only from the token. Decisions are attempt states in a
// successful response; an error means the call could not be evaluated, and
// carries one helm.errors.v1.ErrorDetail.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	errorsv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/errors/v1"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// Server implements EffectGatewayServiceHandler. Dispatch, Observe, Stop and
// Lift are later slices and answer unimplemented.
type Server struct {
	gatewayv1.UnimplementedEffectGatewayServiceHandler

	Admission *admission.Service
	Auth      *Authenticator
}

// Handler returns the mount path and the HTTP handler of the service.
func (s *Server) Handler() (string, http.Handler) {
	path, handler := gatewayv1.NewEffectGatewayServiceHandler(s)
	return path, withTLSState(handler)
}

// Propose admits one effect (token scope helm.gateway.propose).
func (s *Server) Propose(ctx context.Context, req *connect.Request[gatewayv1.ProposeRequest]) (*connect.Response[gatewayv1.ProposeResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopePropose)
	if err != nil {
		return nil, err
	}
	in, err := proposeInput(req.Msg)
	if err != nil {
		return nil, err
	}
	attempt, existing, err := s.Admission.Propose(ctx, id.Caller, in)
	if err != nil {
		return nil, toRPCError(ctx, "Propose", err)
	}
	return connect.NewResponse(&gatewayv1.ProposeResponse{Attempt: attemptProto(attempt), Existing: existing}), nil
}

// Approve approves an ESCALATED attempt and re-runs admission (token scope
// helm.gateway.decide, single-use, bound to the attempt and "approve").
func (s *Server) Approve(ctx context.Context, req *connect.Request[gatewayv1.ApproveRequest]) (*connect.Response[gatewayv1.ApproveResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeDecide)
	if err != nil {
		return nil, err
	}
	if err := checkDecisionBinding(id.AuthorizationDetails, req.Msg.GetAttemptId(), "approve"); err != nil {
		return nil, err
	}
	attempt, existing, err := s.Admission.Approve(ctx, id.Caller, id.token(), admission.DecideInput{
		AttemptID: req.Msg.GetAttemptId(), ApprovalDigest: req.Msg.GetApprovalDigest(), Reason: req.Msg.GetReason(),
	})
	if err != nil {
		return nil, toRPCError(ctx, "Approve", err)
	}
	return connect.NewResponse(&gatewayv1.ApproveResponse{Attempt: attemptProto(attempt), Existing: existing}), nil
}

// Reject rejects an ESCALATED attempt (token scope helm.gateway.decide,
// single-use, bound to the attempt and "reject").
func (s *Server) Reject(ctx context.Context, req *connect.Request[gatewayv1.RejectRequest]) (*connect.Response[gatewayv1.RejectResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeDecide)
	if err != nil {
		return nil, err
	}
	if err := checkDecisionBinding(id.AuthorizationDetails, req.Msg.GetAttemptId(), "reject"); err != nil {
		return nil, err
	}
	attempt, existing, err := s.Admission.Reject(ctx, id.Caller, id.token(), admission.DecideInput{
		AttemptID: req.Msg.GetAttemptId(), ApprovalDigest: req.Msg.GetApprovalDigest(), Reason: req.Msg.GetReason(),
	})
	if err != nil {
		return nil, toRPCError(ctx, "Reject", err)
	}
	return connect.NewResponse(&gatewayv1.RejectResponse{Attempt: attemptProto(attempt), Existing: existing}), nil
}

// Cancel withdraws an ESCALATED or ADMITTED attempt: the requester with
// helm.gateway.propose, or an operator with helm.gateway.stop (single-use).
func (s *Server) Cancel(ctx context.Context, req *connect.Request[gatewayv1.CancelRequest]) (*connect.Response[gatewayv1.CancelResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopePropose, ScopeStop)
	if err != nil {
		return nil, err
	}
	attempt, existing, err := s.Admission.Cancel(ctx, id.Caller, id.token(), req.Msg.GetAttemptId())
	if err != nil {
		return nil, toRPCError(ctx, "Cancel", err)
	}
	return connect.NewResponse(&gatewayv1.CancelResponse{Attempt: attemptProto(attempt), Existing: existing}), nil
}

// GetAttempt returns one attempt (token scope helm.gateway.read).
func (s *Server) GetAttempt(ctx context.Context, req *connect.Request[gatewayv1.GetAttemptRequest]) (*connect.Response[gatewayv1.GetAttemptResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	attempt, err := s.Admission.Get(ctx, id.Caller, req.Msg.GetAttemptId())
	if err != nil {
		return nil, toRPCError(ctx, "GetAttempt", err)
	}
	return connect.NewResponse(&gatewayv1.GetAttemptResponse{Attempt: attemptProto(attempt)}), nil
}

// GetAttemptContent returns an attempt's argument bytes (token scope
// helm.gateway.read).
func (s *Server) GetAttemptContent(ctx context.Context, req *connect.Request[gatewayv1.GetAttemptContentRequest]) (*connect.Response[gatewayv1.GetAttemptContentResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	content, err := s.Admission.GetContent(ctx, id.Caller, req.Msg.GetAttemptId())
	if err != nil {
		return nil, toRPCError(ctx, "GetAttemptContent", err)
	}
	return connect.NewResponse(&gatewayv1.GetAttemptContentResponse{AttemptId: req.Msg.GetAttemptId(), Arguments: content}), nil
}

func proposeInput(msg *gatewayv1.ProposeRequest) (admission.ProposeInput, error) {
	if msg.GetEffect() == nil {
		return admission.ProposeInput{}, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, errors.New("effect is required"))
	}
	in := admission.ProposeInput{
		IdempotencyKey: msg.GetIdempotencyKey(),
		MandateID:      msg.GetMandateId(),
		CommitmentID:   msg.GetCommitmentId(),
		CaseID:         msg.GetCaseId(),
		EffectType:     msg.GetEffect().GetEffectType(),
		Target:         msg.GetEffect().GetTarget(),
		Arguments:      msg.GetEffect().GetArguments(),
	}
	// A oneof member set to "" is still a choice the digest must see; treat
	// it as a malformed reference.
	switch ref := msg.GetWorkRef().(type) {
	case *gatewayv1.ProposeRequest_CommitmentId:
		if ref.CommitmentId == "" {
			return in, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, errors.New("commitment_id is empty"))
		}
	case *gatewayv1.ProposeRequest_CaseId:
		if ref.CaseId == "" {
			return in, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, errors.New("case_id is empty"))
		}
	}
	for _, q := range msg.GetQuote() {
		in.Quote = append(in.Quote, admission.Amount{Unit: q.GetUnit(), Amount: q.GetAmount()})
	}
	for _, d := range msg.GetDistinctValues() {
		in.Distinct = append(in.Distinct, admission.DistinctValue{Unit: d.GetUnit(), Digest: d.GetValueDigest()})
	}
	if ts := msg.GetApprovalExpiresAt(); ts != nil {
		if err := ts.CheckValid(); err != nil {
			return in, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, errors.New("approval_expires_at is not a valid timestamp"))
		}
		t := ts.AsTime().UTC().Truncate(time.Second)
		in.ApprovalExpiresAt = &t
	}
	return in, nil
}

// toRPCError maps an admission refusal onto the contract's Connect codes.
// Anything else is a transient gateway failure: logged, and unavailable with
// retryable set, so the caller repeats the same request.
func toRPCError(ctx context.Context, rpc string, err error) error {
	var refusal *admission.Error
	if errors.As(err, &refusal) {
		code := map[admission.Code]connect.Code{
			admission.CodeInvalidArgument:    connect.CodeInvalidArgument,
			admission.CodePermissionDenied:   connect.CodePermissionDenied,
			admission.CodeNotFound:           connect.CodeNotFound,
			admission.CodeAlreadyExists:      connect.CodeAlreadyExists,
			admission.CodeFailedPrecondition: connect.CodeFailedPrecondition,
		}[refusal.Code]
		if code == 0 {
			code = connect.CodeInternal
		}
		return rpcError(code, refusal.Reason, false, errors.New(refusal.Message))
	}
	if errors.Is(err, context.Canceled) {
		return connect.NewError(connect.CodeCanceled, err)
	}
	slog.ErrorContext(ctx, "gateway call failed", "rpc", rpc, "error", err)
	return rpcError(connect.CodeUnavailable, "", true, errors.New("the gateway could not evaluate the request"))
}

// rpcError builds a Connect error with its one ErrorDetail.
func rpcError(code connect.Code, reason contracts.ReasonCode, retryable bool, err error) error {
	out := connect.NewError(code, err)
	if detail, derr := connect.NewErrorDetail(&errorsv1.ErrorDetail{ReasonCode: string(reason), Retryable: retryable}); derr == nil {
		out.AddDetail(detail)
	}
	return out
}
