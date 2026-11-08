package server

// quantum_posture: returns stored classical Ed25519 receipt.v5 envelopes and
// their binding bytes exactly as the ledger holds them; it signs and verifies
// nothing and makes no post-quantum claim.

import (
	"context"

	"connectrpc.com/connect"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// GetAttemptReceipts returns an attempt's signed decision receipts with their
// exact bytes (token scope helm.gateway.read).
func (s *Server) GetAttemptReceipts(ctx context.Context, req *connect.Request[gatewayv1.GetAttemptReceiptsRequest]) (*connect.Response[gatewayv1.GetAttemptReceiptsResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	receipts, err := s.Admission.GetReceipts(ctx, id.Caller, req.Msg.GetAttemptId())
	if err != nil {
		return nil, toRPCError(ctx, "GetAttemptReceipts", err)
	}
	out := &gatewayv1.GetAttemptReceiptsResponse{AttemptId: req.Msg.GetAttemptId()}
	for _, r := range receipts {
		out.Receipts = append(out.Receipts, &gatewayv1.SignedReceipt{
			Ref: receiptRefProto(r.Ref), ReceiptId: r.Ref.ReceiptID, Format: r.Ref.Format, Receipt: r.Envelope, Binding: r.Binding,
		})
	}
	return connect.NewResponse(out), nil
}

// ExportReceiptChain exports a contiguous range of the token's workspace
// receipt chain as the document receipt_verify checks offline (token scope
// helm.gateway.read).
func (s *Server) ExportReceiptChain(ctx context.Context, req *connect.Request[gatewayv1.ExportReceiptChainRequest]) (*connect.Response[gatewayv1.ExportReceiptChainResponse], error) {
	id, err := s.Auth.Authenticate(ctx, req.Header(), ScopeRead)
	if err != nil {
		return nil, err
	}
	export, err := s.Admission.ExportReceiptChain(ctx, id.Caller, admission.ExportInput{
		WorkspaceID: req.Msg.GetWorkspaceId(), FromSeq: req.Msg.GetFromSeq(), ToSeq: req.Msg.GetToSeq(),
	})
	if err != nil {
		return nil, toRPCError(ctx, "ExportReceiptChain", err)
	}
	out := &gatewayv1.ExportReceiptChainResponse{ChainId: export.ChainID, HeadSeq: export.HeadSeq, Bundle: string(export.Bundle)}
	for _, r := range export.Receipts {
		out.Receipts = append(out.Receipts, receiptRefProto(r.Ref))
	}
	return connect.NewResponse(out), nil
}

// receiptRefProto is a stored receipt's reference on the wire.
func receiptRefProto(r admission.ReceiptRef) *gatewayv1.ReceiptRef {
	return &gatewayv1.ReceiptRef{ChainId: r.ChainID, Seq: r.Seq, ReceiptHash: r.Digest, Kid: r.KeyID}
}
