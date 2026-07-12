package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/metering"
)

type gatewayRecordingMeter struct {
	authorizations []metering.AuthorizationRequest
	settlements    []metering.SettlementRequest
	authorizeErr   error
	settleErr      error
}

func (m *gatewayRecordingMeter) Enabled() bool { return true }

func (m *gatewayRecordingMeter) Authorize(_ context.Context, request metering.AuthorizationRequest) (metering.Authorization, error) {
	m.authorizations = append(m.authorizations, request)
	if m.authorizeErr != nil {
		return metering.Authorization{}, m.authorizeErr
	}
	return metering.Authorization{AuthorizationID: "auth-1", Approved: true}, nil
}

func (m *gatewayRecordingMeter) Settle(_ context.Context, request metering.SettlementRequest) (metering.Settlement, error) {
	m.settlements = append(m.settlements, request)
	if m.settleErr != nil {
		return metering.Settlement{}, m.settleErr
	}
	return metering.Settlement{SettlementID: "settle-1", Settled: true}, nil
}

func meteringGatewayRequest(t *testing.T) *http.Request {
	t.Helper()
	body, err := json.Marshal(MCPToolCallRequest{Method: "metered.echo", Params: map[string]any{"text": "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPost, "/mcp/v1/execute", bytes.NewReader(body))
}

type staticDecisionReceiptProvider struct {
	receipt DecisionReceipt
	err     error
}

func (p staticDecisionReceiptProvider) PreDispatchDecisionReceipt(context.Context, ToolExecutionRequest) (DecisionReceipt, error) {
	return p.receipt, p.err
}

func newMeteredGateway(t *testing.T, meter metering.Client, executor ToolExecutor) *Gateway {
	t.Helper()
	return newMeteredGatewayWithProvider(t, meter, executor, staticDecisionReceiptProvider{
		receipt: DecisionReceipt{ReceiptID: "rcpt-mcp-decision", Verdict: contracts.VerdictAllow},
	})
}

func newMeteredGatewayWithProvider(t *testing.T, meter metering.Client, executor ToolExecutor, provider DecisionReceiptProvider) *Gateway {
	t.Helper()
	catalog := NewInMemoryCatalog()
	if err := catalog.Register(context.Background(), ToolRef{
		Name:        "metered.echo",
		Description: "hosted meter test tool",
		Schema: map[string]any{
			"properties": map[string]any{"text": map[string]any{"type": "string"}},
			"required":   []string{"text"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return NewGateway(catalog, GatewayConfig{}, WithExecutor(executor), WithMetering(meter, metering.Subject{
		TenantID:    "tenant-a",
		WorkspaceID: "workspace-a",
		PrincipalID: "principal-a",
	}, provider))
}

func TestGatewayHostedMeteringBlocksExecutorWhenAuthorizationFails(t *testing.T) {
	meter := &gatewayRecordingMeter{authorizeErr: errors.New("spend policy")}
	dispatches := 0
	gateway := newMeteredGateway(t, meter, func(context.Context, ToolExecutionRequest) (ToolExecutionResponse, error) {
		dispatches++
		return ToolExecutionResponse{Content: "must not run"}, nil
	})
	rec := httptest.NewRecorder()
	gateway.handleExecute(rec, meteringGatewayRequest(t))

	if rec.Code != http.StatusInternalServerError || dispatches != 0 {
		t.Fatalf("status=%d dispatches=%d body=%s", rec.Code, dispatches, rec.Body.String())
	}
}

func TestGatewayHostedMeteringSettlesVerifiedReceipts(t *testing.T) {
	meter := &gatewayRecordingMeter{}
	gateway := newMeteredGateway(t, meter, func(_ context.Context, request ToolExecutionRequest) (ToolExecutionResponse, error) {
		if request.ReceiptID != "rcpt-mcp-decision" {
			t.Fatalf("metered dispatch decision receipt=%q", request.ReceiptID)
		}
		return ToolExecutionResponse{Content: "ok", ReceiptID: "rcpt-mcp-settlement"}, nil
	})
	rec := httptest.NewRecorder()
	gateway.handleExecute(rec, meteringGatewayRequest(t))

	if rec.Code != http.StatusOK || len(meter.authorizations) != 1 || len(meter.settlements) != 1 {
		t.Fatalf("status=%d authorizations=%d settlements=%d body=%s", rec.Code, len(meter.authorizations), len(meter.settlements), rec.Body.String())
	}
	auth := meter.authorizations[0]
	if auth.Ingress != metering.IngressMCP || auth.DecisionReceiptID != "rcpt-mcp-decision" {
		t.Fatalf("authorization=%+v", auth)
	}
	if meter.settlements[0].SettlementReceiptID != "rcpt-mcp-settlement" {
		t.Fatalf("settlement receipt=%q", meter.settlements[0].SettlementReceiptID)
	}
}

func TestGatewayHostedMeteringDoesNotClaimBlockedExecutionSucceeded(t *testing.T) {
	meter := &gatewayRecordingMeter{}
	gateway := newMeteredGateway(t, meter, func(_ context.Context, request ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "tool failed", IsError: true, ReceiptID: "rcpt-mcp-settlement"}, nil
	})
	rec := httptest.NewRecorder()
	gateway.handleExecute(rec, meteringGatewayRequest(t))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(meter.settlements) != 1 || meter.settlements[0].SettlementReceiptID == "" {
		t.Fatalf("settlements=%+v", meter.settlements)
	}
}

func TestGatewayHostedMeteringSettlesTrustedDenyBeforeExecutor(t *testing.T) {
	meter := &gatewayRecordingMeter{}
	dispatches := 0
	gateway := newMeteredGatewayWithProvider(t, meter, func(context.Context, ToolExecutionRequest) (ToolExecutionResponse, error) {
		dispatches++
		return ToolExecutionResponse{Content: "must not run"}, nil
	}, staticDecisionReceiptProvider{receipt: DecisionReceipt{ReceiptID: "rcpt-mcp-deny", Verdict: contracts.VerdictDeny}})
	rec := httptest.NewRecorder()
	gateway.handleExecute(rec, meteringGatewayRequest(t))

	if rec.Code != http.StatusForbidden || dispatches != 0 {
		t.Fatalf("status=%d dispatches=%d body=%s", rec.Code, dispatches, rec.Body.String())
	}
	if len(meter.authorizations) != 1 || len(meter.settlements) != 1 {
		t.Fatalf("authorizations=%d settlements=%d", len(meter.authorizations), len(meter.settlements))
	}
	if got := meter.settlements[0].SettlementReceiptID; got != "rcpt-mcp-deny" {
		t.Fatalf("deny settlement receipt=%q", got)
	}
}

func TestGatewayHostedMeteringLeavesEscalationForCeremonyOwner(t *testing.T) {
	meter := &gatewayRecordingMeter{}
	dispatches := 0
	gateway := newMeteredGatewayWithProvider(t, meter, func(context.Context, ToolExecutionRequest) (ToolExecutionResponse, error) {
		dispatches++
		return ToolExecutionResponse{Content: "must not run"}, nil
	}, staticDecisionReceiptProvider{receipt: DecisionReceipt{ReceiptID: "rcpt-mcp-escalate", Verdict: contracts.VerdictEscalate}})
	rec := httptest.NewRecorder()
	gateway.handleExecute(rec, meteringGatewayRequest(t))

	if rec.Code != http.StatusForbidden || dispatches != 0 {
		t.Fatalf("status=%d dispatches=%d body=%s", rec.Code, dispatches, rec.Body.String())
	}
	if len(meter.authorizations) != 1 || len(meter.settlements) != 0 {
		t.Fatalf("authorizations=%d settlements=%d", len(meter.authorizations), len(meter.settlements))
	}
}

func TestGatewayHostedMeteringRefusesSyntheticReceipts(t *testing.T) {
	meter := &gatewayRecordingMeter{}
	dispatches := 0
	catalog := NewInMemoryCatalog()
	if err := catalog.Register(context.Background(), ToolRef{Name: "metered.echo", Schema: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	gateway := NewGateway(catalog, GatewayConfig{}, WithExecutor(func(context.Context, ToolExecutionRequest) (ToolExecutionResponse, error) {
		dispatches++
		return ToolExecutionResponse{Content: "must not run"}, nil
	}), WithMetering(meter, metering.Subject{TenantID: "tenant-a", WorkspaceID: "workspace-a", PrincipalID: "principal-a"}))
	rec := httptest.NewRecorder()
	gateway.handleExecute(rec, meteringGatewayRequest(t))

	if rec.Code != http.StatusInternalServerError || dispatches != 0 || len(meter.authorizations) != 0 {
		t.Fatalf("status=%d dispatches=%d authorizations=%d body=%s", rec.Code, dispatches, len(meter.authorizations), rec.Body.String())
	}
}

func TestGatewayHostedMeteringSettlementFailureDoesNotReturnSuccess(t *testing.T) {
	meter := &gatewayRecordingMeter{settleErr: errors.New("ledger unavailable")}
	gateway := newMeteredGateway(t, meter, func(_ context.Context, request ToolExecutionRequest) (ToolExecutionResponse, error) {
		return ToolExecutionResponse{Content: "upstream-ran", ReceiptID: "rcpt-mcp-settlement"}, nil
	})
	rec := httptest.NewRecorder()
	gateway.handleExecute(rec, meteringGatewayRequest(t))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
