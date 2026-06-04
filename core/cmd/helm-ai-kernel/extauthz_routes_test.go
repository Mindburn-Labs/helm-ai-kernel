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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
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
