package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/extauthz"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	otelapi "go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestExtAuthzAuthorizeRouteSignsAllowPermit(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")
	t.Setenv("HELM_EXTAUTHZ_TRUST_ROOT_ID", "kernel-test-root")

	signer, err := helmcrypto.NewEd25519Signer("extauthz-test")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{
		Guardian:      guardian.NewGuardian(signer, allowGraphForExtAuthzTest("local.echo"), artifacts.NewRegistry(nil, nil)),
		ReceiptSigner: signer,
	}
	mux := http.NewServeMux()
	registerExtAuthzRoutes(mux, svc)

	body := mustJSONExtAuthzRoute(t, extAuthzRouteFixture("req-allow", "tenant-a", "epoch-1"))
	req := httptest.NewRequest(http.MethodPost, extauthzAuthorizePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer route-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp extauthz.AuthorizationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != extauthz.VerdictAllow {
		t.Fatalf("verdict=%s body=%s", resp.Verdict, rec.Body.String())
	}
	if resp.EffectPermitRef == "" || resp.PermitNonce == "" || resp.ProofSessionRef == "" {
		t.Fatalf("allow response missing permit/proof refs: %+v", resp)
	}
	store := extauthz.TrustStore{Keys: map[string]extauthz.TrustedKey{
		resp.SigningKeyRef: {TrustRootID: resp.KernelTrustRootID, PublicKey: signer.PublicKeyBytes(), Enabled: true},
	}}
	err = extauthz.VerifyResponse(extAuthzRouteFixture("req-allow", "tenant-a", "epoch-1"), resp, store, extauthz.VerifyOptions{
		ExpectedKernelTrustRootID: "kernel-test-root",
		ExpectedPolicyEpoch:       "epoch-1",
		MaxVerdictTTL:             time.Minute,
		MaxPermitTTL:              time.Minute,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("verify response: %v\nresponse=%+v", err, resp)
	}
}

func TestExtAuthzAuthorizeRouteSignsDenyWithoutPermit(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")

	signer, err := helmcrypto.NewEd25519Signer("extauthz-test")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{
		Guardian:      guardian.NewGuardian(signer, prg.NewGraph(), artifacts.NewRegistry(nil, nil)),
		ReceiptSigner: signer,
	}
	mux := http.NewServeMux()
	registerExtAuthzRoutes(mux, svc)

	body := mustJSONExtAuthzRoute(t, extAuthzRouteFixture("req-deny", "tenant-a", "epoch-1"))
	req := httptest.NewRequest(http.MethodPost, extauthzAuthorizePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer route-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp extauthz.AuthorizationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != extauthz.VerdictDeny {
		t.Fatalf("verdict=%s body=%s", resp.Verdict, rec.Body.String())
	}
	if resp.EffectPermitRef != "" || resp.PermitNonce != "" || resp.PermitExpiry != "" {
		t.Fatalf("deny response carried permit material: %+v", resp)
	}
	store := extauthz.TrustStore{Keys: map[string]extauthz.TrustedKey{
		resp.SigningKeyRef: {TrustRootID: resp.KernelTrustRootID, PublicKey: signer.PublicKeyBytes(), Enabled: true},
	}}
	err = extauthz.VerifyResponse(extAuthzRouteFixture("req-deny", "tenant-a", "epoch-1"), resp, store, extauthz.VerifyOptions{
		MaxVerdictTTL: time.Minute,
		MaxPermitTTL:  time.Minute,
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("verify deny response: %v\nresponse=%+v", err, resp)
	}
}

func TestExtAuthzAuthorizeRouteAllowsMatchingPolicySnapshot(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")
	t.Setenv("HELM_EXTAUTHZ_TRUST_ROOT_ID", "kernel-test-root")

	signer, err := helmcrypto.NewEd25519Signer("extauthz-test")
	if err != nil {
		t.Fatal(err)
	}
	reqFixture := extAuthzRouteFixture("req-snapshot-allow", "tenant-a", "42")
	reqFixture.PolicyHash = hashURNForExtAuthzRouteTest("snapshot-policy")
	svc := extAuthzSnapshotService(t, signer, reqFixture.PolicyHash, 42)
	mux := http.NewServeMux()
	registerExtAuthzRoutes(mux, svc)

	body := mustJSONExtAuthzRoute(t, reqFixture)
	req := httptest.NewRequest(http.MethodPost, extauthzAuthorizePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer route-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp extauthz.AuthorizationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != extauthz.VerdictAllow {
		t.Fatalf("verdict=%s body=%s", resp.Verdict, rec.Body.String())
	}
	if resp.PolicyHash != reqFixture.PolicyHash || resp.PolicyEpoch != reqFixture.PolicyEpoch {
		t.Fatalf("response lost request policy binding: %+v", resp)
	}
	store := extauthz.TrustStore{Keys: map[string]extauthz.TrustedKey{
		resp.SigningKeyRef: {TrustRootID: resp.KernelTrustRootID, PublicKey: signer.PublicKeyBytes(), Enabled: true},
	}}
	if err := extauthz.VerifyResponse(reqFixture, resp, store, extauthz.VerifyOptions{
		ExpectedKernelTrustRootID: "kernel-test-root",
		ExpectedPolicyEpoch:       "42",
		MaxVerdictTTL:             time.Minute,
		MaxPermitTTL:              time.Minute,
	}, time.Now().UTC()); err != nil {
		t.Fatalf("verify response: %v\nresponse=%+v", err, resp)
	}
}

func TestExtAuthzAuthorizeRouteDeniesPolicySnapshotMismatch(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")

	signer, err := helmcrypto.NewEd25519Signer("extauthz-test")
	if err != nil {
		t.Fatal(err)
	}
	activePolicyHash := hashURNForExtAuthzRouteTest("active-snapshot-policy")
	reqFixture := extAuthzRouteFixture("req-snapshot-mismatch", "tenant-a", "41")
	reqFixture.PolicyHash = hashURNForExtAuthzRouteTest("stale-request-policy")
	svc := extAuthzSnapshotService(t, signer, activePolicyHash, 42)
	mux := http.NewServeMux()
	registerExtAuthzRoutes(mux, svc)

	body := mustJSONExtAuthzRoute(t, reqFixture)
	req := httptest.NewRequest(http.MethodPost, extauthzAuthorizePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer route-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp extauthz.AuthorizationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != extauthz.VerdictDeny || resp.ReasonCode != extauthzPolicyBindingMismatchReason {
		t.Fatalf("expected policy binding mismatch deny, got %+v", resp)
	}
	if resp.EffectPermitRef != "" || resp.PermitNonce != "" || resp.ProofSessionRef != "" {
		t.Fatalf("mismatch deny carried permit/proof refs: %+v", resp)
	}
	if resp.PolicyHash != reqFixture.PolicyHash || resp.PolicyEpoch != reqFixture.PolicyEpoch {
		t.Fatalf("response should preserve request echo for verification: %+v", resp)
	}
	store := extauthz.TrustStore{Keys: map[string]extauthz.TrustedKey{
		resp.SigningKeyRef: {TrustRootID: resp.KernelTrustRootID, PublicKey: signer.PublicKeyBytes(), Enabled: true},
	}}
	if err := extauthz.VerifyResponse(reqFixture, resp, store, extauthz.VerifyOptions{
		MaxVerdictTTL: time.Minute,
		MaxPermitTTL:  time.Minute,
	}, time.Now().UTC()); err != nil {
		t.Fatalf("verify mismatch deny response: %v\nresponse=%+v", err, resp)
	}
}

func TestExtAuthzAuthorizeRouteRequiresServiceAuth(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "route-secret")
	mux := http.NewServeMux()
	registerExtAuthzRoutes(mux, &Services{})
	req := httptest.NewRequest(http.MethodPost, extauthzAuthorizePath, strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExtAuthzAuthorizeRouteExtractsTraceparent(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	previous := otelapi.GetTracerProvider()
	otelapi.SetTracerProvider(provider)
	defer otelapi.SetTracerProvider(previous)

	t.Setenv(serviceAPIKeyEnv, "route-secret")
	t.Setenv("HELM_EXTAUTHZ_TRUST_ROOT_ID", "kernel-test-root")

	signer, err := helmcrypto.NewEd25519Signer("extauthz-test")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{
		Guardian:      guardian.NewGuardian(signer, allowGraphForExtAuthzTest("local.echo"), artifacts.NewRegistry(nil, nil)),
		ReceiptSigner: signer,
	}
	mux := http.NewServeMux()
	registerExtAuthzRoutes(mux, svc)

	body := mustJSONExtAuthzRoute(t, extAuthzRouteFixture("req-trace", "tenant-a", "epoch-1"))
	req := httptest.NewRequest(http.MethodPost, extauthzAuthorizePath, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer route-secret")
	req.Header.Set("traceparent", "00-0102030405060708090a0b0c0d0e0f10-0000000000000001-01")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	wantTraceID, err := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	if err != nil {
		t.Fatal(err)
	}
	for _, span := range exporter.GetSpans() {
		if span.SpanContext.TraceID() == wantTraceID {
			return
		}
	}
	t.Fatalf("no Kernel span carried incoming trace id; spans=%+v", exporter.GetSpans())
}

func extAuthzSnapshotService(t *testing.T, signer *helmcrypto.Ed25519Signer, policyHash string, policyEpoch uint64) *Services {
	t.Helper()
	scope := policyreconcile.PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	store := policyreconcile.NewAtomicSnapshotStore()
	if err := store.Swap(scope, &policyreconcile.EffectivePolicySnapshot{
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		PolicyEpoch: policyEpoch,
		PolicyHash:  policyHash,
		Validation:  policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive},
		Graph:       allowGraphForExtAuthzTest("local.echo"),
	}); err != nil {
		t.Fatalf("swap policy snapshot: %v", err)
	}
	return &Services{
		Guardian:      guardian.NewGuardian(signer, prg.NewGraph(), artifacts.NewRegistry(nil, nil), guardian.WithPolicySnapshots(store, scope)),
		ReceiptSigner: signer,
	}
}

func allowGraphForExtAuthzTest(tool string) *prg.Graph {
	graph := prg.NewGraph()
	_ = graph.AddRule(tool, prg.RequirementSet{
		ID:    "allow-" + tool,
		Logic: prg.AND,
		Requirements: []prg.Requirement{
			{ID: "allow", Expression: "true"},
		},
	})
	return graph
}

func extAuthzRouteFixture(requestID, tenantID, epoch string) extauthz.AuthorizationRequest {
	return extauthz.AuthorizationRequest{
		SchemaVersion:           extauthz.SchemaVersionV1,
		ContractVersion:         extauthz.ContractVersionV1,
		RequestID:               requestID,
		TenantID:                tenantID,
		WorkspaceID:             "workspace-a",
		PrincipalID:             "agent-a",
		PrincipalSeq:            7,
		AgentIdentityProfileRef: "agent-profile:a",
		Protocol:                "mcp",
		ActionURN:               "EXECUTE_TOOL",
		ToolURN:                 "local.echo",
		ConnectorID:             "local-echo",
		ConnectorContractHash:   hashURNForExtAuthzRouteTest("connector"),
		ExecutorKind:            "local-echo",
		EffectClass:             "no-op",
		RiskClass:               "T0",
		ArgsC14NHash:            hashURNForExtAuthzRouteTest("args"),
		RequestBodyHash:         hashURNForExtAuthzRouteTest("request"),
		PlanHash:                hashURNForExtAuthzRouteTest("plan"),
		PolicyHash:              hashURNForExtAuthzRouteTest("policy"),
		P0Hash:                  hashURNForExtAuthzRouteTest("p0"),
		PolicyEpoch:             epoch,
		IdempotencyKeyCandidate: "idem-" + requestID,
		PayloadClass:            "test",
		RedactionProfile:        "local-redacted",
		UpstreamTraceID:         "trace-" + requestID,
		UpstreamRunID:           "run-" + requestID,
		DeadlineMS:              1000,
		RiskContextHash:         hashURNForExtAuthzRouteTest("risk"),
	}
}

func hashURNForExtAuthzRouteTest(value string) string {
	return "sha256:" + canonicalize.HashBytes([]byte(value))
}

func mustJSONExtAuthzRoute(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
