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

// Server implements EffectGatewayServiceHandler.
type Server struct {
	gatewayv1.UnimplementedEffectGatewayServiceHandler

	Admission *admission.Service
	Auth      *Authenticator
}

// Handler returns the mount path and the HTTP handler of the service.
//
// A request message is capped at MaxMessageBytes after decompression, and the
// request body at MaxBodyBytes on the wire, both before the message reaches a
// handler, so an unauthenticated caller cannot make the gateway buffer or
// inflate more than that.
func (s *Server) Handler() (string, http.Handler) {
	path, handler := gatewayv1.NewEffectGatewayServiceHandler(s, connect.WithReadMaxBytes(MaxMessageBytes))
	return path, http.MaxBytesHandler(withTLSState(handler), MaxBodyBytes)
}

// MaxMessageBytes caps one decoded request message: twice the 64 KiB argument
// cap leaves room for the rest of a ProposeRequest.
const MaxMessageBytes = 128 << 10

// MaxBodyBytes caps a request body as sent, envelope and compression
// included.
const MaxBodyBytes = MaxMessageBytes + 4<<10

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
	// An operator's single-use stop token names the attempt it cancels.
	if id.Scope == ScopeStop {
		if err := checkBinding(id.AuthorizationDetails, "helm_effect_cancel", map[string]string{"attempt_id": req.Msg.GetAttemptId()}); err != nil {
			return nil, err
		}
	}
	attempt, existing, err := s.Admission.Cancel(ctx, id.Caller, id.token(), req.Msg.GetAttemptId())
	if err != nil {
		return nil, toRPCError(ctx, "Cancel", err)
	}
	return connect.NewResponse(&gatewayv1.CancelResponse{Attempt: attemptProto(attempt), Existing: existing}), nil
}

// Dispatch claims an ADMITTED attempt's permit and sends the effect through
// its adapter (token scope helm.gateway.execute, workload principals only).
// A refused claim, a NOT_SENT and an UNKNOWN are attempt states, not errors.
func (s *Server) Dispatch(ctx context.Context, req *connect.Request[gatewayv1.DispatchRequest]) (*connect.Response[gatewayv1.DispatchResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeExecute)
	if err != nil {
		return nil, err
	}
	attempt, existing, err := s.Admission.Dispatch(ctx, id.Caller, req.Msg.GetAttemptId())
	if err != nil {
		return nil, toRPCError(ctx, "Dispatch", err)
	}
	return connect.NewResponse(&gatewayv1.DispatchResponse{Attempt: attemptProto(attempt), Existing: existing}), nil
}

// Observe reads a dispatched effect back and records the observation (token
// scope helm.gateway.execute, workload principals only). It never
// dispatches.
func (s *Server) Observe(ctx context.Context, req *connect.Request[gatewayv1.ObserveRequest]) (*connect.Response[gatewayv1.ObserveResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeExecute)
	if err != nil {
		return nil, err
	}
	attempt, existing, err := s.Admission.Observe(ctx, id.Caller, req.Msg.GetAttemptId())
	if err != nil {
		return nil, toRPCError(ctx, "Observe", err)
	}
	return connect.NewResponse(&gatewayv1.ObserveResponse{Attempt: attemptProto(attempt), Existing: existing}), nil
}

// Stop stops new effects in one scope (token scope helm.gateway.stop,
// single-use, human operators only). Idempotent by key.
func (s *Server) Stop(ctx context.Context, req *connect.Request[gatewayv1.StopRequest]) (*connect.Response[gatewayv1.StopResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeStop)
	if err != nil {
		return nil, err
	}
	kind, ok := stopKinds[req.Msg.GetScopeKind()]
	if !ok {
		return nil, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, errors.New("scope_kind is required"))
	}
	// The single-use stop token names the stop it was minted for, so a token
	// issued to cancel or lift cannot be spent on a tenant-wide stop.
	if err := checkBinding(id.AuthorizationDetails, "helm_stop", map[string]string{
		"idempotency_key": req.Msg.GetIdempotencyKey(), "scope_kind": kind, "scope_key": req.Msg.GetScopeKey(),
	}); err != nil {
		return nil, err
	}
	in := admission.StopInput{IdempotencyKey: req.Msg.GetIdempotencyKey(), ScopeKind: kind, ScopeKey: req.Msg.GetScopeKey(),
		Reason: req.Msg.GetReason()}
	if ts := req.Msg.GetExpiresAt(); ts != nil {
		if err := ts.CheckValid(); err != nil {
			return nil, rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, errors.New("expires_at is not a valid timestamp"))
		}
		t := ts.AsTime().UTC()
		in.ExpiresAt = &t
	}
	stop, existing, err := s.Admission.Stop(ctx, id.Caller, id.token(), in)
	if err != nil {
		return nil, toRPCError(ctx, "Stop", err)
	}
	return connect.NewResponse(&gatewayv1.StopResponse{Stop: stopProto(stop), Existing: existing}), nil
}

// Lift proposes lifting a stop: a helm.authority.lift attempt, normally
// ESCALATED (token scope helm.gateway.stop, single-use, bound to the stop by
// its helm_stop_lift authorization_details entry).
func (s *Server) Lift(ctx context.Context, req *connect.Request[gatewayv1.LiftRequest]) (*connect.Response[gatewayv1.LiftResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeStop)
	if err != nil {
		return nil, err
	}
	if err := checkBinding(id.AuthorizationDetails, "helm_stop_lift", map[string]string{"stop_id": req.Msg.GetStopId()}); err != nil {
		return nil, err
	}
	attempt, existing, err := s.Admission.Lift(ctx, id.Caller, id.token(), admission.LiftInput{
		IdempotencyKey: req.Msg.GetIdempotencyKey(), StopID: req.Msg.GetStopId(), MandateID: req.Msg.GetMandateId(),
	})
	if err != nil {
		return nil, toRPCError(ctx, "Lift", err)
	}
	return connect.NewResponse(&gatewayv1.LiftResponse{Attempt: attemptProto(attempt), Existing: existing}), nil
}

var stopKinds = map[gatewayv1.StopScopeKind]string{
	gatewayv1.StopScopeKind_STOP_SCOPE_KIND_TENANT:      "tenant",
	gatewayv1.StopScopeKind_STOP_SCOPE_KIND_PRINCIPAL:   "principal",
	gatewayv1.StopScopeKind_STOP_SCOPE_KIND_MANDATE:     "mandate",
	gatewayv1.StopScopeKind_STOP_SCOPE_KIND_EFFECT_TYPE: "effect_type",
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
