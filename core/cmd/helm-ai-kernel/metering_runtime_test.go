package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/metering"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

type recordingMeter struct {
	authorizeRequests []metering.AuthorizationRequest
	settleRequests    []metering.SettlementRequest
	authorizeErr      error
	settleErr         error
}

func (m *recordingMeter) Enabled() bool { return true }

func (m *recordingMeter) Authorize(_ context.Context, request metering.AuthorizationRequest) (metering.Authorization, error) {
	m.authorizeRequests = append(m.authorizeRequests, request)
	if m.authorizeErr != nil {
		return metering.Authorization{}, m.authorizeErr
	}
	return metering.Authorization{AuthorizationID: "auth-test", Approved: true}, nil
}

func (m *recordingMeter) Settle(_ context.Context, request metering.SettlementRequest) (metering.Settlement, error) {
	m.settleRequests = append(m.settleRequests, request)
	if m.settleErr != nil {
		return metering.Settlement{}, m.settleErr
	}
	return metering.Settlement{SettlementID: "settle-test", Settled: true}, nil
}

func newHostedOpenAIService(t *testing.T) *Services {
	t.Helper()
	signer, err := helmcrypto.NewEd25519Signer("hosted-openai-metering-test")
	if err != nil {
		t.Fatal(err)
	}
	graph := prg.NewGraph()
	if err := graph.AddRule("LLM_INFERENCE", prg.RequirementSet{
		ID:    "allow-inference",
		Logic: prg.AND,
		Requirements: []prg.Requirement{
			{ID: "allow", Expression: "true"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return &Services{
		Guardian:      guardian.NewGuardian(signer, graph, artifacts.NewRegistry(nil, nil)),
		ReceiptStore:  &captureReceiptStore{},
		ReceiptSigner: signer,
	}
}

func TestHostedEvaluateSendsVerifiedReceiptForControlPlaneDerivedAllow(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-trusted")
	svc, receipts := newEvaluateRouteTestServices(t)
	meter := &recordingMeter{}
	svc.Metering = meter
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewBufferString(`{"action":"EXECUTE_TOOL","resource":"local.echo"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	req.Header.Set(workspaceHeader, "workspace-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(meter.authorizeRequests) != 1 || len(meter.settleRequests) != 1 {
		t.Fatalf("meter calls authorize=%d settle=%d", len(meter.authorizeRequests), len(meter.settleRequests))
	}
	auth := meter.authorizeRequests[0]
	if auth.Subject != (metering.Subject{TenantID: "tenant-trusted", WorkspaceID: "workspace-trusted", PrincipalID: "principal-trusted"}) {
		t.Fatalf("subject=%+v", auth.Subject)
	}
	if receipts.stored == nil || auth.DecisionReceiptID != receipts.stored.ReceiptID {
		t.Fatalf("meter receipt %q does not bind stored receipt %+v", auth.DecisionReceiptID, receipts.stored)
	}
	if got := meter.settleRequests[0].SettlementReceiptID; got != auth.DecisionReceiptID {
		t.Fatalf("settlement receipt=%q authorization receipt=%q", got, auth.DecisionReceiptID)
	}
}

func TestHostedEvaluateStopsWhenAuthorizationFails(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-trusted")
	svc, _ := newEvaluateRouteTestServices(t)
	svc.Metering = &recordingMeter{authorizeErr: errors.New("spend policy denied")}
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewBufferString(`{"action":"EXECUTE_TOOL","resource":"local.echo"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	req.Header.Set(workspaceHeader, "workspace-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHostedEvaluateSendsReceiptForControlPlaneDerivedDeny(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-trusted")
	svc, _ := newEvaluateRouteTestServices(t)
	meter := &recordingMeter{}
	svc.Metering = meter
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewBufferString(`{"action":"EXECUTE_TOOL","resource":"not-allowlisted"}`))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-trusted")
	req.Header.Set(principalHeader, "principal-trusted")
	req.Header.Set(workspaceHeader, "workspace-trusted")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || len(meter.authorizeRequests) != 1 || len(meter.settleRequests) != 1 {
		t.Fatalf("status=%d authorizations=%d settlements=%d body=%s", rec.Code, len(meter.authorizeRequests), len(meter.settleRequests), rec.Body.String())
	}
	if auth := meter.authorizeRequests[0]; auth.DecisionReceiptID == "" {
		t.Fatal("deny must provide a decision receipt for control-plane pricing")
	}
}

func TestMeteringLifecycleCatalogKeepsEscalationNonBillable(t *testing.T) {
	allow := meteringLifecycleForVerdict("ALLOW")
	if allow.Class != "routine_allow" || allow.Credits != 0 || !allow.SettleNow {
		t.Fatalf("allow lifecycle=%+v", allow)
	}
	deny := meteringLifecycleForVerdict("DENY")
	if deny.Class != "deny" || deny.Credits != 1 || !deny.SettleNow {
		t.Fatalf("deny lifecycle=%+v", deny)
	}
	escalate := meteringLifecycleForVerdict("ESCALATE")
	if escalate.Class != "escalate" || escalate.Credits != 0 || escalate.SettleNow {
		t.Fatalf("escalate lifecycle=%+v", escalate)
	}
}

func TestHostedOpenAIProxyBlocksUpstreamWhenMeterAuthorizationFails(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-trusted")
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte(`{"id":"upstream"}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)
	svc := newHostedOpenAIService(t)
	svc.Metering = &recordingMeter{authorizeErr: errors.New("spend policy")}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"local.echo","messages":[]}`))
	req.Header.Set(workspaceHeader, "workspace-trusted")
	req = req.WithContext(helmauth.WithPrincipal(req.Context(), &helmauth.BasePrincipal{ID: "principal-trusted", TenantID: "tenant-trusted"}))
	rec := httptest.NewRecorder()

	handleGovernedOpenAIProxy(rec, req, svc)

	if rec.Code != http.StatusServiceUnavailable || upstreamCalls.Load() != 0 {
		t.Fatalf("status=%d upstream=%d body=%s", rec.Code, upstreamCalls.Load(), rec.Body.String())
	}
}

func TestHostedOpenAIProxyDoesNotReturnSuccessWhenSettlementFails(t *testing.T) {
	t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
	t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
	t.Setenv(runtimeWorkspaceIDEnv, "workspace-trusted")
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"upstream","choices":[]}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)
	svc := newHostedOpenAIService(t)
	svc.Metering = &recordingMeter{settleErr: errors.New("ledger unavailable")}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"local.echo","messages":[]}`))
	req.Header.Set(workspaceHeader, "workspace-trusted")
	req = req.WithContext(helmauth.WithPrincipal(req.Context(), &helmauth.BasePrincipal{ID: "principal-trusted", TenantID: "tenant-trusted"}))
	rec := httptest.NewRecorder()

	handleGovernedOpenAIProxy(rec, req, svc)

	if rec.Code != http.StatusBadGateway || upstreamCalls.Load() != 1 {
		t.Fatalf("status=%d upstream=%d body=%s", rec.Code, upstreamCalls.Load(), rec.Body.String())
	}
}

func TestHostedCLIProxyMeteringRequiresDecisionReceiptProvider(t *testing.T) {
	meter := &recordingMeter{}
	if err := requireCLIProxyMeteringReceiptProvider(meter); err == nil {
		t.Fatal("hosted CLI proxy must refuse synthetic receipt metering")
	}
	if len(meter.authorizeRequests) != 0 || len(meter.settleRequests) != 0 {
		t.Fatalf("meter calls authorize=%d settle=%d", len(meter.authorizeRequests), len(meter.settleRequests))
	}
	if err := requireCLIProxyMeteringReceiptProvider(metering.Disabled{}); err != nil {
		t.Fatalf("local OSS proxy should remain available: %v", err)
	}
}
