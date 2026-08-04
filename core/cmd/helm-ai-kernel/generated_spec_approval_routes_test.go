package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapprovalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

func TestGeneratedSpecApprovalResponseCarriesPendingSpecBinding(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeGeneratedSpecApprovalResult(recorder, generatedspecapprovalceremony.Record{
		State: generatedspecapprovalceremony.StateHoldPending, ApprovalID: "approval-a",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", HoldStartedAt: time.Now().UTC(), Version: 1,
		Binding: generatedspecapprovalceremony.Binding{GeneratedSpecID: "generated-spec-a"},
	}, nil)
	if recorder.Code != http.StatusOK || recorder.Header().Get("X-Helm-Contract-Status") != generatedSpecApprovalContractStatus {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var response generatedSpecApprovalRecordResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.GeneratedSpecID != "generated-spec-a" {
		t.Fatalf("generated_spec_id=%q", response.GeneratedSpecID)
	}
}

func TestGeneratedSpecApprovalRoutesFailClosedOnWorkloadAuthentication(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		body      string
		control   approvalConsumerTokenValidator
		consumer  approvalConsumerTokenValidator
		token     string
		status    int
		scopeFail bool
	}{
		{
			name: "missing control bearer", path: generatedSpecApprovalBeginPath, body: `{"binding_ref":"binding-a"}`,
			control:  fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
			consumer: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)}, status: http.StatusUnauthorized,
		},
		{
			name: "consumer scope missing", path: generatedSpecApprovalConsumePath, body: validApprovalConsumptionRequest(), token: "token",
			control:  fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
			consumer: fakeApprovalConsumerTokenValidator{err: &mcppkg.JWKSValidationError{Kind: mcppkg.JWKSErrMissingScope}},
			status:   http.StatusForbidden, scopeFail: true,
		},
		{
			name: "consumer audience rejected", path: generatedSpecApprovalConsumePath, body: validApprovalConsumptionRequest(), token: "token",
			control:  fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
			consumer: fakeApprovalConsumerTokenValidator{err: &mcppkg.JWKSValidationError{Kind: mcppkg.JWKSErrInvalidAudience}},
			status:   http.StatusUnauthorized,
		},
		{
			name: "consumer resource rejected", path: generatedSpecApprovalConsumePath, body: validApprovalConsumptionRequest(), token: "token",
			control:  fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
			consumer: fakeApprovalConsumerTokenValidator{err: &mcppkg.JWKSValidationError{Kind: mcppkg.JWKSErrInvalidResource}},
			status:   http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mux := http.NewServeMux()
			registerGeneratedSpecApprovalRoutes(mux, generatedSpecApprovalRouteTestRuntime(test.control, test.consumer))
			response := postApprovalConsumptionRoute(t, mux, test.path, test.body, test.token)
			if response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
			}
			if test.scopeFail && !strings.Contains(response.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
				t.Fatalf("scope rejection challenge=%q", response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestGeneratedSpecApprovalRoutesRejectMalformedAndCrossScopeRecoveryTuples(t *testing.T) {
	crossScopeRecovery := validApprovalConsumptionRequest()
	crossScopeRecovery = crossScopeRecovery[:len(crossScopeRecovery)-1] + `,"tenant_id":"tenant-other","workspace_id":"workspace-other"}`
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "malformed consume tuple", path: generatedSpecApprovalConsumePath, body: `{"approval_id":"approval-a","grant_id":"grant-a","grant_hash":"sha256:bad","nonce":"not-a-nonce"}`},
		{name: "malformed recovery tuple", path: generatedSpecApprovalRecoverPath, body: `{"approval_id":"approval-a","grant_id":"grant-a","grant_hash":"sha256:bad","nonce":"not-a-nonce"}`},
		{name: "recovery rejects caller supplied scope", path: generatedSpecApprovalRecoverPath, body: crossScopeRecovery},
	}

	validator := fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mux := http.NewServeMux()
			registerGeneratedSpecApprovalRoutes(mux, generatedSpecApprovalRouteTestRuntime(validator, validator))
			response := postApprovalConsumptionRoute(t, mux, test.path, test.body, "token")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func generatedSpecApprovalRouteTestRuntime(control, consumer approvalConsumerTokenValidator) *generatedSpecApprovalRuntime {
	return &generatedSpecApprovalRuntime{
		service:           &generatedspecapprovalceremony.Service{},
		controlValidator:  control,
		consumerValidator: consumer,
		audience:          contracts.GeneratedSpecApprovalAudienceV1,
		maxTokenTTL:       5 * time.Minute,
	}
}
