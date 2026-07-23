package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/golang-jwt/jwt/v5"
)

type fakeApprovalConsumerTokenValidator struct {
	claims *mcppkg.OAuthTokenClaims
	err    error
}

func (v fakeApprovalConsumerTokenValidator) ValidateAuthorization(string) (*mcppkg.OAuthTokenClaims, error) {
	return v.claims, v.err
}

type fakeApprovalGrantConsumer struct {
	record       approvalceremony.Record
	err          error
	consumeCalls int
	recoverCalls int
	identity     approvalceremony.ConsumerIdentity
}

type fakeApprovalDispatchAdmitter struct {
	record       approvalceremony.DispatchAdmissionRecord
	active       []approvalceremony.EffectReservationEvent
	err          error
	claimCalls   int
	recoverCalls int
	listCalls    int
	identity     approvalceremony.ConsumerIdentity
	request      approvalceremony.DispatchAdmissionRequest
}

type fakeEffectDispositionRecorder struct {
	record       approvalceremony.EffectDispositionRecord
	listed       map[string][]approvalceremony.EffectDispositionRecord
	err          error
	recordCalls  int
	recoverCalls int
	listCalls    int
	identity     approvalceremony.ConsumerIdentity
	envelope     contracts.EffectDispositionCommandEnvelope
	commandID    string
	admissionID  string
}

func (f *fakeEffectDispositionRecorder) Record(ctx context.Context, envelope contracts.EffectDispositionCommandEnvelope) (approvalceremony.EffectDispositionRecord, error) {
	f.recordCalls++
	f.identity, _ = (approvalceremony.ContextConsumerIdentityProvider{}).LoadConsumerIdentity(ctx)
	f.envelope = envelope
	return f.record, f.err
}

func (f *fakeEffectDispositionRecorder) Recover(ctx context.Context, commandID string) (approvalceremony.EffectDispositionRecord, error) {
	f.recoverCalls++
	f.identity, _ = (approvalceremony.ContextConsumerIdentityProvider{}).LoadConsumerIdentity(ctx)
	f.commandID = commandID
	return f.record, f.err
}

func (f *fakeEffectDispositionRecorder) ListForEffect(ctx context.Context, admissionID string) ([]approvalceremony.EffectDispositionRecord, error) {
	f.listCalls++
	f.identity, _ = (approvalceremony.ContextConsumerIdentityProvider{}).LoadConsumerIdentity(ctx)
	f.admissionID = admissionID
	return append([]approvalceremony.EffectDispositionRecord(nil), f.listed[admissionID]...), f.err
}

func (a *fakeApprovalDispatchAdmitter) Claim(ctx context.Context, request approvalceremony.DispatchAdmissionRequest) (approvalceremony.DispatchAdmissionRecord, error) {
	a.claimCalls++
	a.capture(ctx, request)
	return a.record, a.err
}

func (a *fakeApprovalDispatchAdmitter) Recover(ctx context.Context, request approvalceremony.DispatchAdmissionRequest) (approvalceremony.DispatchAdmissionRecord, error) {
	a.recoverCalls++
	a.capture(ctx, request)
	return a.record, a.err
}

func (a *fakeApprovalDispatchAdmitter) ListActive(ctx context.Context) ([]approvalceremony.EffectReservationEvent, error) {
	a.listCalls++
	a.identity, _ = (approvalceremony.ContextConsumerIdentityProvider{}).LoadConsumerIdentity(ctx)
	return append([]approvalceremony.EffectReservationEvent(nil), a.active...), a.err
}

func (a *fakeApprovalDispatchAdmitter) capture(ctx context.Context, request approvalceremony.DispatchAdmissionRequest) {
	a.identity, _ = (approvalceremony.ContextConsumerIdentityProvider{}).LoadConsumerIdentity(ctx)
	a.request = request
}

type fakeApprovalScopedStopReader struct {
	state  kernel.FenceState
	fenced bool
	err    error
	calls  int
	scope  kernel.StopScope
}

func (r *fakeApprovalScopedStopReader) IsFenced(_ context.Context, scope kernel.StopScope) (kernel.FenceState, bool, error) {
	r.calls++
	r.scope = scope
	return r.state, r.fenced, r.err
}

func (c *fakeApprovalGrantConsumer) ConsumeGrant(ctx context.Context, _, _, _, _ string) (approvalceremony.Record, error) {
	c.consumeCalls++
	c.captureIdentity(ctx)
	return c.record, c.err
}

func (c *fakeApprovalGrantConsumer) RecoverGrantConsumption(ctx context.Context, _, _, _, _ string) (approvalceremony.Record, error) {
	c.recoverCalls++
	c.captureIdentity(ctx)
	return c.record, c.err
}

func (c *fakeApprovalGrantConsumer) captureIdentity(ctx context.Context) {
	c.identity, _ = (approvalceremony.ContextConsumerIdentityProvider{}).LoadConsumerIdentity(ctx)
}

func TestApprovalGrantConsumptionRoutesUseVerifiedWorkloadIdentity(t *testing.T) {
	consumer := &fakeApprovalGrantConsumer{record: approvalConsumptionRouteRecord()}
	runtime := approvalConsumptionRouteRuntime(consumer)
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, runtime)

	consume := postApprovalConsumptionRoute(t, mux, approvalGrantConsumePath, validApprovalConsumptionRequest(), "workload-token")
	if consume.Code != http.StatusOK {
		t.Fatalf("consume status = %d body=%s", consume.Code, consume.Body.String())
	}
	if consumer.consumeCalls != 1 || consumer.recoverCalls != 0 {
		t.Fatalf("consume calls=%d recover calls=%d", consumer.consumeCalls, consumer.recoverCalls)
	}
	wantIdentity := approvalceremony.ConsumerIdentity{
		Subject: "spiffe://helm/data-plane-a", TenantID: "tenant-a",
		WorkspaceID: "workspace-a", Audience: "helm-data-plane",
	}
	if consumer.identity != wantIdentity {
		t.Fatalf("verified identity = %+v, want %+v", consumer.identity, wantIdentity)
	}
	var response approvalGrantConsumptionResponse
	if err := json.NewDecoder(consume.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Consumption.ConsumptionHash == "" || response.ConsumedBy != wantIdentity.Subject ||
		response.ConsumptionSignature == "" || consume.Header().Get("Cache-Control") != "no-store" ||
		consume.Header().Get("X-Helm-Contract-Status") != "internal_non_production" {
		t.Fatalf("unexpected response=%+v headers=%v", response, consume.Header())
	}

	recover := postApprovalConsumptionRoute(t, mux, approvalGrantConsumptionRecoverPath, validApprovalConsumptionRequest(), "workload-token")
	if recover.Code != http.StatusOK || consumer.recoverCalls != 1 {
		t.Fatalf("recover status=%d calls=%d body=%s", recover.Code, consumer.recoverCalls, recover.Body.String())
	}
}

func TestApprovalDispatchAdmissionRoutesUseSeparateVerifiedCapability(t *testing.T) {
	admitter := &fakeApprovalDispatchAdmitter{record: approvalDispatchAdmissionRouteRecord(t)}
	runtime := approvalDispatchRouteRuntime(admitter)
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, runtime)

	claim := postApprovalConsumptionRoute(t, mux, approvalDispatchAdmissionPath, validApprovalDispatchAdmissionRequest(), "dispatch-token")
	if claim.Code != http.StatusOK {
		t.Fatalf("claim status=%d body=%s", claim.Code, claim.Body.String())
	}
	wantIdentity := approvalceremony.ConsumerIdentity{
		Subject: "spiffe://helm/data-plane-a", TenantID: "tenant-a",
		WorkspaceID: "workspace-a", Audience: "helm-data-plane",
	}
	if admitter.claimCalls != 1 || admitter.recoverCalls != 0 || admitter.identity != wantIdentity {
		t.Fatalf("claim calls=%d recover=%d identity=%+v", admitter.claimCalls, admitter.recoverCalls, admitter.identity)
	}
	var response approvalDispatchAdmissionResponse
	if err := json.NewDecoder(claim.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Admission.AttemptID != "attempt-a" ||
		response.Admission.ConnectorAuthority.ConnectorID != "connector-a" || response.AdmissionSignature == "" ||
		claim.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response=%+v headers=%v", response, claim.Header())
	}

	recover := postApprovalConsumptionRoute(t, mux, approvalDispatchAdmissionRecoverPath, validApprovalDispatchAdmissionRequest(), "dispatch-token")
	if recover.Code != http.StatusOK || admitter.recoverCalls != 1 {
		t.Fatalf("recover status=%d calls=%d body=%s", recover.Code, admitter.recoverCalls, recover.Body.String())
	}
}

func TestEffectDispositionRoutesUseVerifiedWorkloadScopeAndRecoverSignedRecord(t *testing.T) {
	record := effectDispositionRouteRecord(t)
	recorder := &fakeEffectDispositionRecorder{record: record}
	runtime := &approvalConsumptionRuntime{
		disposition:          recorder,
		dispositionValidator: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
		audience:             "helm-data-plane", maxTokenTTL: 5 * time.Minute,
	}
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, runtime)
	body, err := json.Marshal(record.Command)
	if err != nil {
		t.Fatal(err)
	}
	response := postApprovalConsumptionRoute(t, mux, effectDispositionPath, string(body), "workload-token")
	if response.Code != http.StatusOK || recorder.recordCalls != 1 || recorder.envelope != record.Command {
		t.Fatalf("record status=%d calls=%d body=%s", response.Code, recorder.recordCalls, response.Body.String())
	}
	wantIdentity := approvalceremony.ConsumerIdentity{
		Subject: "spiffe://helm/data-plane-a", TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "helm-data-plane",
	}
	if recorder.identity != wantIdentity || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Helm-Contract-Status") != "internal_non_production" ||
		!strings.Contains(response.Body.String(), `"execution_authority":"NONE"`) {
		t.Fatalf("identity=%+v headers=%v body=%s", recorder.identity, response.Header(), response.Body.String())
	}

	response = postApprovalConsumptionRoute(t, mux, effectDispositionRecoverPath,
		`{"command_id":"`+record.Command.Command.CommandID+`"}`, "workload-token")
	if response.Code != http.StatusOK || recorder.recoverCalls != 1 || recorder.commandID != record.Command.Command.CommandID {
		t.Fatalf("recover status=%d calls=%d id=%q body=%s", response.Code, recorder.recoverCalls, recorder.commandID, response.Body.String())
	}
}

func TestEffectDispositionCandidateRouteListsOnlyReconciliationCandidates(t *testing.T) {
	record := effectDispositionRouteRecord(t)
	started := effectReservationCandidateEvent(t, approvalceremony.EffectReservationStateStarted, "")
	admitted := effectReservationCandidateEvent(t, approvalceremony.EffectReservationStateAdmitted, "")
	admitter := &fakeApprovalDispatchAdmitter{active: []approvalceremony.EffectReservationEvent{started, admitted}}
	recorder := &fakeEffectDispositionRecorder{
		record: record,
		listed: map[string][]approvalceremony.EffectDispositionRecord{
			started.Admission.Admission.AdmissionID: {record},
		},
	}
	runtime := &approvalConsumptionRuntime{
		reservations: admitter, disposition: recorder,
		dispositionValidator: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
		stops:                &fakeApprovalScopedStopReader{fenced: true, state: record.Fence},
		audience:             "helm-data-plane", maxTokenTTL: 5 * time.Minute,
	}
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, runtime)

	request := httptest.NewRequest(http.MethodGet, effectDispositionCandidatesPath, nil)
	request.Header.Set("Authorization", "Bearer workload-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if admitter.listCalls != 1 || recorder.listCalls != 1 || recorder.admissionID != started.Admission.Admission.AdmissionID {
		t.Fatalf("list calls admitter=%d recorder=%d admission=%q", admitter.listCalls, recorder.listCalls, recorder.admissionID)
	}
	wantIdentity := approvalceremony.ConsumerIdentity{
		Subject: "spiffe://helm/data-plane-a", TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "helm-data-plane",
	}
	if admitter.identity != wantIdentity || recorder.identity != wantIdentity {
		t.Fatalf("identities admitter=%+v recorder=%+v", admitter.identity, recorder.identity)
	}
	var payload effectDispositionCandidateListResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Fence == nil || payload.Fence.CommandID != record.Fence.CommandID || len(payload.Candidates) != 1 {
		t.Fatalf("payload=%+v", payload)
	}
	candidate := payload.Candidates[0]
	headHash, err := approvalceremony.EffectReservationHeadHash(started)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Reservation.Admission.Admission.AdmissionID != started.Admission.Admission.AdmissionID ||
		candidate.ReservationHeadHash != headHash ||
		candidate.PreviousReceiptHash != record.Receipt.ReceiptHash ||
		candidate.NextDispositionSequence != record.Receipt.DispositionSequence+1 ||
		len(candidate.Dispositions) != 1 ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Helm-Contract-Status") != "internal_non_production" {
		t.Fatalf("candidate=%+v headers=%v", candidate, response.Header())
	}
}

func TestEffectDispositionCandidateRouteReturnsEmptyWhenScopeIsNotFenced(t *testing.T) {
	started := effectReservationCandidateEvent(t, approvalceremony.EffectReservationStateStarted, "")
	admitter := &fakeApprovalDispatchAdmitter{active: []approvalceremony.EffectReservationEvent{started}}
	recorder := &fakeEffectDispositionRecorder{listed: map[string][]approvalceremony.EffectDispositionRecord{}}
	runtime := &approvalConsumptionRuntime{
		reservations: admitter, disposition: recorder,
		dispositionValidator: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
		stops:                &fakeApprovalScopedStopReader{},
		audience:             "helm-data-plane", maxTokenTTL: 5 * time.Minute,
	}
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, runtime)

	request := httptest.NewRequest(http.MethodGet, effectDispositionCandidatesPath, nil)
	request.Header.Set("Authorization", "Bearer workload-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload effectDispositionCandidateListResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Fence != nil || len(payload.Candidates) != 1 || payload.Candidates[0].PreviousReceiptHash != "" || payload.Candidates[0].NextDispositionSequence != 1 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestEffectDispositionRoutesAreAbsentWhenDisabled(t *testing.T) {
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, &approvalConsumptionRuntime{})
	response := postApprovalConsumptionRoute(t, mux, effectDispositionPath, `{}`, "workload-token")
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled disposition route status=%d body=%s", response.Code, response.Body.String())
	}
	response = postApprovalConsumptionRoute(t, mux, effectDispositionRecoverPath, `{"command_id":"command-a"}`, "workload-token")
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled disposition recovery route status=%d body=%s", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, effectDispositionCandidatesPath, nil)
	request.Header.Set("Authorization", "Bearer workload-token")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled disposition candidate route status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestEffectDispositionRecoveryPreservesOpaqueCommandID(t *testing.T) {
	for _, commandID := range []string{"a/b", ".", ".."} {
		t.Run(commandID, func(t *testing.T) {
			recorder := &fakeEffectDispositionRecorder{record: effectDispositionRouteRecord(t), err: approvalceremony.ErrNotFound}
			runtime := &approvalConsumptionRuntime{
				disposition:          recorder,
				dispositionValidator: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
				audience:             "helm-data-plane", maxTokenTTL: 5 * time.Minute,
			}
			mux := http.NewServeMux()
			registerApprovalGrantConsumptionRoutes(mux, runtime)
			body, err := json.Marshal(struct {
				CommandID string `json:"command_id"`
			}{CommandID: commandID})
			if err != nil {
				t.Fatal(err)
			}
			response := postApprovalConsumptionRoute(t, mux, effectDispositionRecoverPath, string(body), "workload-token")
			if response.Code != http.StatusNotFound || recorder.recoverCalls != 1 || recorder.commandID != commandID {
				t.Fatalf("recover status=%d calls=%d id=%q body=%s", response.Code, recorder.recoverCalls, recorder.commandID, response.Body.String())
			}
		})
	}
}

func TestEffectDispositionRoutesFailClosedBeforeDurableAuthority(t *testing.T) {
	recorder := &fakeEffectDispositionRecorder{record: effectDispositionRouteRecord(t)}
	runtime := &approvalConsumptionRuntime{
		disposition:          recorder,
		dispositionValidator: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
		audience:             "helm-data-plane", maxTokenTTL: 5 * time.Minute,
	}
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, runtime)

	validBody, err := json.Marshal(recorder.record.Command)
	if err != nil {
		t.Fatal(err)
	}
	badBody := strings.TrimSuffix(string(validBody), "}") + `,"tenant_id":"attacker"}`
	response := postApprovalConsumptionRoute(t, mux, effectDispositionPath, badBody, "workload-token")
	if response.Code != http.StatusBadRequest || recorder.recordCalls != 0 {
		t.Fatalf("malformed status=%d calls=%d body=%s", response.Code, recorder.recordCalls, response.Body.String())
	}

	missingToken := httptest.NewRequest(http.MethodPost, effectDispositionRecoverPath, strings.NewReader(`{"command_id":"command-a"}`))
	missingToken.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, missingToken)
	if response.Code != http.StatusUnauthorized || recorder.recoverCalls != 0 ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Helm-Contract-Status") != "internal_non_production" {
		t.Fatalf("missing-token status=%d calls=%d body=%s", response.Code, recorder.recoverCalls, response.Body.String())
	}

	response = postApprovalConsumptionRoute(t, mux, effectDispositionRecoverPath,
		`{"command_id":"command-a","tenant_id":"attacker"}`, "workload-token")
	if response.Code != http.StatusBadRequest || recorder.recoverCalls != 0 {
		t.Fatalf("unknown-field status=%d calls=%d body=%s", response.Code, recorder.recoverCalls, response.Body.String())
	}

	response = postApprovalConsumptionRoute(t, mux, effectDispositionRecoverPath,
		`{"command_id":"command-a"} {}`, "workload-token")
	if response.Code != http.StatusBadRequest || recorder.recoverCalls != 0 {
		t.Fatalf("trailing-json status=%d calls=%d body=%s", response.Code, recorder.recoverCalls, response.Body.String())
	}

	response = httptest.NewRecorder()
	writeEffectDispositionError(response, errors.New("database password secret"))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "database password secret") {
		t.Fatalf("sanitization status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestApprovalDispatchAdmissionRoutesFailClosedBeforeAuthority(t *testing.T) {
	admitter := &fakeApprovalDispatchAdmitter{record: approvalDispatchAdmissionRouteRecord(t)}
	tests := map[string]struct {
		runtime *approvalConsumptionRuntime
		body    string
		status  int
	}{
		"dispatch verifier missing": {
			runtime: &approvalConsumptionRuntime{admitter: admitter, stops: &fakeApprovalScopedStopReader{}, audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute},
			body:    validApprovalDispatchAdmissionRequest(), status: http.StatusServiceUnavailable,
		},
		"dispatch scope missing": {
			runtime: &approvalConsumptionRuntime{
				admitter: admitter, dispatchValidator: fakeApprovalConsumerTokenValidator{err: &mcppkg.JWKSValidationError{Kind: mcppkg.JWKSErrMissingScope}},
				stops: &fakeApprovalScopedStopReader{}, audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute,
			},
			body: validApprovalDispatchAdmissionRequest(), status: http.StatusForbidden,
		},
		"unknown authority field": {
			runtime: approvalDispatchRouteRuntime(admitter),
			body:    strings.TrimSuffix(validApprovalDispatchAdmissionRequest(), "}") + `,"tenant_id":"attacker"}`,
			status:  http.StatusBadRequest,
		},
		"caller connector selection": {
			runtime: approvalDispatchRouteRuntime(admitter),
			body:    strings.TrimSuffix(validApprovalDispatchAdmissionRequest(), "}") + `,"connector_id":"attacker-connector"}`,
			status:  http.StatusBadRequest,
		},
		"bad idempotency hash": {
			runtime: approvalDispatchRouteRuntime(admitter),
			body:    strings.Replace(validApprovalDispatchAdmissionRequest(), strings.Repeat("a", 64), "bad", 1),
			status:  http.StatusBadRequest,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			registerApprovalGrantConsumptionRoutes(mux, test.runtime)
			response := postApprovalConsumptionRoute(t, mux, approvalDispatchAdmissionPath, test.body, "dispatch-token")
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
	if admitter.claimCalls != 0 {
		t.Fatalf("rejected dispatch requests reached authority %d times", admitter.claimCalls)
	}
}

func TestApprovalDispatchAdmissionFenceDenialIsBounded(t *testing.T) {
	admitter := &fakeApprovalDispatchAdmitter{err: approvalceremony.ErrEmergencyStopFenced}
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, approvalDispatchRouteRuntime(admitter))
	response := postApprovalConsumptionRoute(t, mux, approvalDispatchAdmissionPath, validApprovalDispatchAdmissionRequest(), "dispatch-token")
	if response.Code != http.StatusConflict || response.Header().Get(approvalConsumptionReasonHeader) != approvalConsumptionFencedReason ||
		!strings.Contains(response.Body.String(), approvalConsumptionFencedReason) {
		t.Fatalf("status=%d reason=%q body=%s", response.Code, response.Header().Get(approvalConsumptionReasonHeader), response.Body.String())
	}
}

func TestApprovalGrantConsumptionRoutesFailClosedOnWorkloadAuthentication(t *testing.T) {
	validConsumer := &fakeApprovalGrantConsumer{record: approvalConsumptionRouteRecord()}
	tests := map[string]struct {
		runtime *approvalConsumptionRuntime
		token   string
		status  int
	}{
		"runtime unavailable": {runtime: &approvalConsumptionRuntime{}, token: "token", status: http.StatusServiceUnavailable},
		"bearer missing":      {runtime: approvalConsumptionRouteRuntime(validConsumer), status: http.StatusUnauthorized},
		"signature rejected": {
			runtime: &approvalConsumptionRuntime{consumer: validConsumer, validator: fakeApprovalConsumerTokenValidator{err: errors.New("bad signature")}, stops: &fakeApprovalScopedStopReader{}, audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute},
			token:   "token", status: http.StatusUnauthorized,
		},
		"scope missing": {
			runtime: &approvalConsumptionRuntime{consumer: validConsumer, validator: fakeApprovalConsumerTokenValidator{err: &mcppkg.JWKSValidationError{Kind: mcppkg.JWKSErrMissingScope}}, stops: &fakeApprovalScopedStopReader{}, audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute},
			token:   "token", status: http.StatusForbidden,
		},
		"workspace claim missing": {
			runtime: &approvalConsumptionRuntime{consumer: validConsumer, validator: fakeApprovalConsumerTokenValidator{claims: &mcppkg.OAuthTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: "spiffe://helm/data-plane-a"}, TenantID: "tenant-a",
			}}, stops: &fakeApprovalScopedStopReader{}, audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute},
			token: "token", status: http.StatusUnauthorized,
		},
		"token lifetime too long": {
			runtime: &approvalConsumptionRuntime{
				consumer: validConsumer, validator: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(time.Hour)},
				stops: &fakeApprovalScopedStopReader{}, audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute,
			},
			token: "token", status: http.StatusUnauthorized,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			registerApprovalGrantConsumptionRoutes(mux, test.runtime)
			response := postApprovalConsumptionRoute(t, mux, approvalGrantConsumePath, validApprovalConsumptionRequest(), test.token)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestApprovalGrantConsumptionConsumeEnforcesVerifiedScopedFence(t *testing.T) {
	tests := map[string]struct {
		reader *fakeApprovalScopedStopReader
		status int
		reason string
	}{
		"active fence": {
			reader: &fakeApprovalScopedStopReader{fenced: true, state: kernel.FenceState{Epoch: 7}},
			status: http.StatusConflict, reason: approvalConsumptionFencedReason,
		},
		"unverified fence": {
			reader: &fakeApprovalScopedStopReader{err: errors.New("database unavailable")},
			status: http.StatusServiceUnavailable, reason: approvalConsumptionUnverifiedReason,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			consumer := &fakeApprovalGrantConsumer{record: approvalConsumptionRouteRecord()}
			runtime := approvalConsumptionRouteRuntime(consumer)
			runtime.stops = test.reader
			mux := http.NewServeMux()
			registerApprovalGrantConsumptionRoutes(mux, runtime)

			response := postApprovalConsumptionRoute(t, mux, approvalGrantConsumePath, validApprovalConsumptionRequest(), "workload-token")
			if response.Code != test.status || response.Header().Get(approvalConsumptionReasonHeader) != test.reason {
				t.Fatalf("status=%d reason=%q body=%s", response.Code, response.Header().Get(approvalConsumptionReasonHeader), response.Body.String())
			}
			if consumer.consumeCalls != 0 || consumer.recoverCalls != 0 {
				t.Fatalf("fenced request reached consumer: consume=%d recover=%d", consumer.consumeCalls, consumer.recoverCalls)
			}
			wantScope := kernel.StopScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
			if test.reader.calls != 1 || test.reader.scope != wantScope {
				t.Fatalf("stop checks=%d scope=%+v want=%+v", test.reader.calls, test.reader.scope, wantScope)
			}
		})
	}
}

func TestApprovalGrantConsumptionRecoveryRemainsReadOnlyWhileFenced(t *testing.T) {
	consumer := &fakeApprovalGrantConsumer{record: approvalConsumptionRouteRecord()}
	reader := &fakeApprovalScopedStopReader{fenced: true, state: kernel.FenceState{Epoch: 7}}
	runtime := approvalConsumptionRouteRuntime(consumer)
	runtime.stops = reader
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, runtime)

	response := postApprovalConsumptionRoute(t, mux, approvalGrantConsumptionRecoverPath, validApprovalConsumptionRequest(), "workload-token")
	if response.Code != http.StatusOK || consumer.recoverCalls != 1 || consumer.consumeCalls != 0 {
		t.Fatalf("status=%d consume=%d recover=%d body=%s", response.Code, consumer.consumeCalls, consumer.recoverCalls, response.Body.String())
	}
	if reader.calls != 0 {
		t.Fatalf("read-only recovery was treated as new dispatch authority: stop checks=%d", reader.calls)
	}
}

func TestApprovalGrantConsumptionRoutesRejectMalformedInputBeforeAuthority(t *testing.T) {
	consumer := &fakeApprovalGrantConsumer{record: approvalConsumptionRouteRecord()}
	mux := http.NewServeMux()
	registerApprovalGrantConsumptionRoutes(mux, approvalConsumptionRouteRuntime(consumer))
	valid := validApprovalConsumptionRequest()
	tests := map[string]string{
		"unknown field":   strings.TrimSuffix(valid, "}") + `,"tenant_id":"attacker"}`,
		"trailing object": valid + `{}`,
		"bad grant hash":  strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"bad nonce":       strings.Replace(valid, strings.Repeat("b", 64), "not-a-nonce", 1),
		"oversized body":  `{"approval_id":"` + strings.Repeat("a", approvalGrantConsumptionMaxBody) + `"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			response := postApprovalConsumptionRoute(t, mux, approvalGrantConsumePath, body, "workload-token")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if consumer.consumeCalls != 0 {
		t.Fatalf("malformed requests reached durable authority %d times", consumer.consumeCalls)
	}

	req := httptest.NewRequest(http.MethodGet, approvalGrantConsumePath, nil)
	req.Header.Set("Authorization", "Bearer workload-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status=%d body=%s", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, approvalGrantConsumePath, bytes.NewBufferString(valid))
	request.Header.Set("Authorization", "Bearer workload-token")
	request.Header.Set("Content-Type", "text/plain")
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestApprovalConsumptionErrorMappingDoesNotLeakAuthorityErrors(t *testing.T) {
	tests := map[string]struct {
		err    error
		status int
		reason string
	}{
		"invalid":   {err: approvalceremony.ErrInvalidRecord, status: http.StatusBadRequest},
		"not found": {err: approvalceremony.ErrNotFound, status: http.StatusNotFound},
		"conflict":  {err: approvalceremony.ErrTransitionConflict, status: http.StatusConflict},
		"identity":  {err: approvalceremony.ErrConsumerUnavailable, status: http.StatusForbidden},
		"fenced": {
			err: approvalceremony.ErrEmergencyStopFenced, status: http.StatusConflict,
			reason: approvalConsumptionFencedReason,
		},
		"stop unverified": {
			err: errApprovalConsumptionStopUnverified, status: http.StatusServiceUnavailable,
			reason: approvalConsumptionUnverifiedReason,
		},
		"internal": {err: errors.New("database password secret"), status: http.StatusServiceUnavailable},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeApprovalConsumptionError(response, test.err)
			if response.Code != test.status || response.Header().Get(approvalConsumptionReasonHeader) != test.reason ||
				strings.Contains(response.Body.String(), "database password secret") {
				t.Fatalf("status=%d reason=%q body=%s", response.Code, response.Header().Get(approvalConsumptionReasonHeader), response.Body.String())
			}
		})
	}
}

func approvalConsumptionRouteRuntime(consumer approvalGrantConsumer) *approvalConsumptionRuntime {
	return &approvalConsumptionRuntime{
		consumer: consumer, validator: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
		stops: &fakeApprovalScopedStopReader{}, audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute,
	}
}

func approvalDispatchRouteRuntime(admitter approvalDispatchAdmitter) *approvalConsumptionRuntime {
	return &approvalConsumptionRuntime{
		admitter: admitter, dispatchValidator: fakeApprovalConsumerTokenValidator{claims: approvalConsumerRouteClaims(5 * time.Minute)},
		stops: &fakeApprovalScopedStopReader{}, audience: "helm-data-plane", maxTokenTTL: 5 * time.Minute,
	}
}

func approvalConsumerRouteClaims(ttl time.Duration) *mcppkg.OAuthTokenClaims {
	now := time.Date(2026, 7, 16, 17, 0, 0, 0, time.UTC)
	return &mcppkg.OAuthTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "spiffe://helm/data-plane-a", IssuedAt: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		TenantID: "tenant-a", WorkspaceID: "workspace-a",
	}
}

func approvalConsumptionRouteRecord() approvalceremony.Record {
	now := time.Date(2026, 7, 16, 17, 0, 0, 0, time.UTC)
	consumption := contracts.ApprovalGrantConsumption{
		SchemaVersion:   contracts.ApprovalGrantConsumptionSchemaV1,
		ContractVersion: contracts.ApprovalGrantConsumptionContractV1,
		ApprovalID:      "approval-a", GrantID: "grant-a", GrantHash: "sha256:" + strings.Repeat("a", 64),
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "helm-data-plane",
		ConsumedBy: "spiffe://helm/data-plane-a", PackID: "pack-a", PackVersion: "1.0.0",
		PackManifestHash: "sha256:" + strings.Repeat("c", 64), Action: contracts.ApprovalGrantActionInstall,
		ConnectorAuthority: approvalRouteConnectorAuthority(),
		IntentHash:         "sha256:" + strings.Repeat("d", 64), EffectHash: "sha256:" + strings.Repeat("e", 64),
		PlanHash: "sha256:" + strings.Repeat("f", 64), PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1",
		PolicyHash: "sha256:" + strings.Repeat("1", 64), ServerIdentity: "kernel-a",
		KernelTrustRootID: "root-a", SigningKeyRef: "key-a", GrantIssuedAt: now.Add(-time.Minute),
		GrantExpiresAt: now.Add(time.Minute), ConsumedAt: now, ConsumptionHash: "sha256:" + strings.Repeat("2", 64),
	}
	return approvalceremony.Record{
		ApprovalID: consumption.ApprovalID, TenantID: consumption.TenantID,
		WorkspaceID: consumption.WorkspaceID, State: approvalceremony.StateConsumed,
		GrantConsumption: &consumption, ConsumptionSignatureAlgorithm: approvalceremony.GrantSignatureEd25519,
		ConsumptionSignature: strings.Repeat("a", 128), ConsumedBy: consumption.ConsumedBy, Version: 6,
	}
}

func validApprovalConsumptionRequest() string {
	body, _ := json.Marshal(approvalGrantConsumptionRequest{
		ApprovalID: "approval-a", GrantID: "grant-a",
		GrantHash: "sha256:" + strings.Repeat("a", 64), Nonce: strings.Repeat("b", 64),
	})
	return string(body)
}

func approvalDispatchAdmissionRouteRecord(t *testing.T) approvalceremony.DispatchAdmissionRecord {
	t.Helper()
	consumption := *approvalConsumptionRouteRecord().GrantConsumption
	admission, err := (contracts.ApprovalDispatchAdmission{
		SchemaVersion:   contracts.ApprovalDispatchAdmissionSchemaV1,
		ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
		Coverage:        contracts.ApprovalDispatchAdmissionCoverageV1,
		AdmissionID:     "dispatch-admission-a", AttemptID: "attempt-a", State: contracts.ApprovalDispatchAdmissionStateV1,
		ApprovalID: consumption.ApprovalID, GrantID: consumption.GrantID,
		GrantHash: consumption.GrantHash, ConsumptionHash: consumption.ConsumptionHash,
		TenantID: consumption.TenantID, WorkspaceID: consumption.WorkspaceID,
		Audience: consumption.Audience, AdmittedBy: consumption.ConsumedBy,
		IdempotencyKeyHash: "sha256:" + strings.Repeat("a", 64), EffectHash: consumption.EffectHash,
		Action: consumption.Action, ConnectorAuthority: consumption.ConnectorAuthority,
		KernelTrustRootID: consumption.KernelTrustRootID, SigningKeyRef: consumption.SigningKeyRef,
		IssuedAt: consumption.ConsumedAt.Add(time.Second), ExpiresAt: consumption.ConsumedAt.Add(30 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return approvalceremony.DispatchAdmissionRecord{
		Admission: admission, SignatureAlgorithm: approvalceremony.GrantSignatureEd25519,
		Signature: strings.Repeat("a", 128), CreatedAt: admission.IssuedAt, UpdatedAt: admission.IssuedAt,
	}
}

func validApprovalDispatchAdmissionRequest() string {
	body, _ := json.Marshal(approvalceremony.DispatchAdmissionRequest{
		ApprovalID: "approval-a", AttemptID: "attempt-a",
		ConsumptionHash:    "sha256:" + strings.Repeat("2", 64),
		IdempotencyKeyHash: "sha256:" + strings.Repeat("a", 64),
		EffectHash:         "sha256:" + strings.Repeat("e", 64),
		Action:             contracts.ApprovalGrantActionInstall,
	})
	return string(body)
}

func approvalRouteConnectorAuthority() contracts.ApprovalConnectorAuthority {
	authority, err := (contracts.ApprovalConnectorAuthority{
		SchemaVersion:   contracts.ApprovalConnectorAuthoritySchemaV1,
		ContractVersion: contracts.ApprovalConnectorAuthorityContractV1,
		State:           contracts.ApprovalConnectorAuthorityStateV1,
		BindingRef:      "decision://helm/policy/approval-a", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		PackID: "pack-a", PackVersion: "1.0.0", PackManifestHash: "sha256:" + strings.Repeat("c", 64),
		Action: contracts.ApprovalGrantActionInstall, ConnectorAction: contracts.ApprovalGrantActionInstall,
		EffectHash: "sha256:" + strings.Repeat("e", 64),
		PolicyHash: "sha256:" + strings.Repeat("1", 64), ConnectorID: "connector-a",
		ConnectorVersion: "1.0.0", ReleaseScopeKind: contracts.ConnectorReleaseAuthorityScopeGlobal,
		ReleaseAuthorityID: "connector-registry-a", ReleaseRegistryRevision: 1,
		ReleaseAuthorityHash: "sha256:" + strings.Repeat("4", 64), ConnectorExecutorKind: "digital",
		ConnectorBinaryHash:   "sha256:" + strings.Repeat("7", 64),
		ConnectorSignatureRef: "sigstore://connector-a/1.0.0", ConnectorSignerID: "publisher-a",
		ConnectorSignatureHash:  "sha256:" + strings.Repeat("6", 64),
		ConnectorSandboxProfile: "sandbox-pack-lifecycle-v1", ConnectorDriftPolicyRef: "policy://connector-drift/v1",
		CertificationRef: "cert://connector-a/1.0.0", CertificationHash: "sha256:" + strings.Repeat("8", 64),
		CertificationAuthority: "spiffe://helm/certification-authority",
	}).Seal()
	if err != nil {
		panic(err)
	}
	return authority
}

func postApprovalConsumptionRoute(t *testing.T, mux *http.ServeMux, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	return response
}

func effectDispositionRouteRecord(t *testing.T) approvalceremony.EffectDispositionRecord {
	t.Helper()
	now := time.Date(2026, 7, 18, 17, 0, 0, 0, time.UTC)
	fence := kernel.FenceState{
		StopScope:       kernel.StopScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"},
		ContractVersion: kernel.EmergencyStopFenceContractVersion, Audience: "helm-data-plane",
		KeyID: "cp-stop-a", CommandID: "fence-a", CommandHash: "sha256:" + strings.Repeat("1", 64), Epoch: 1,
		ActorID: "operator-a", Reason: "contain active work", IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour), FencedAt: now.Add(-30 * time.Second),
		AcknowledgementIdentity: emergencyStopAcknowledgementIdentityForTest(),
	}
	payload, err := fence.AcknowledgementPayload()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	fence.ReceiptHash = "sha256:" + hex.EncodeToString(sum[:])
	command, err := (contracts.EffectDispositionCommand{
		SchemaVersion: contracts.EffectDispositionCommandSchemaV1, ContractVersion: contracts.EffectDispositionCommandContractV1,
		CommandID: "command-a", DispositionSequence: 1, TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: "helm-data-plane",
		FenceCommandID: fence.CommandID, FenceCommandHash: fence.CommandHash, FenceEpoch: fence.Epoch, FenceReceiptHash: fence.ReceiptHash,
		AdmissionID: "admission-a", AttemptID: "attempt-a", ReservationSequence: 2,
		ReservationHeadHash: "sha256:" + strings.Repeat("2", 64), ReservationState: string(approvalceremony.EffectReservationStateUncertain),
		ConnectorID: "github", ConnectorVersion: "1.0.0", ConnectorAction: "github.create_issue",
		ConnectorExecutionRef: "github-request-a", ProofSessionRef: "proof-a", IntentRef: "intent-a", EffectRef: "issue-a",
		IdempotencyKeyHash: "sha256:" + strings.Repeat("3", 64), EffectHash: "sha256:" + strings.Repeat("4", 64),
		Action: contracts.EffectDispositionActionReconcileSource, DispositionRef: "disposition-a", ActorID: "operator-a", Reason: "reconcile active work",
		AuthorityID: "spiffe://helm/control-plane", SigningKeyRef: "kms://helm/control-plane/disposition-a",
		Algorithm: contracts.EffectDispositionAlgorithmV1, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	envelope := contracts.EffectDispositionCommandEnvelope{Command: command, Signature: strings.Repeat("a", 128)}
	receipt, err := (contracts.EffectDispositionReceipt{
		SchemaVersion: contracts.EffectDispositionReceiptSchemaV1, ContractVersion: contracts.EffectDispositionReceiptContractV1,
		ReceiptID: "receipt-a", State: contracts.EffectDispositionReceiptStateAccepted,
		ExecutionAuthority: contracts.EffectDispositionExecutionAuthorityNone,
		CommandID:          command.CommandID, CommandHash: command.CommandHash, DispositionSequence: command.DispositionSequence,
		TenantID: command.TenantID, WorkspaceID: command.WorkspaceID, Audience: command.Audience,
		FenceCommandID: command.FenceCommandID, FenceCommandHash: command.FenceCommandHash,
		FenceEpoch: command.FenceEpoch, FenceReceiptHash: command.FenceReceiptHash,
		AdmissionID: command.AdmissionID, ReservationSequence: command.ReservationSequence,
		ReservationHeadHash: command.ReservationHeadHash, ReservationState: command.ReservationState,
		Action: command.Action, DispositionRef: command.DispositionRef,
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kernel-approval-a",
		AcceptedBy: "spiffe://helm/data-plane-a", AcceptedAt: now,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return approvalceremony.EffectDispositionRecord{
		Command: envelope, Fence: fence, Receipt: receipt,
		SignatureAlgorithm: approvalceremony.GrantSignatureEd25519, Signature: strings.Repeat("b", 128), CreatedAt: now,
	}
}

func effectReservationCandidateEvent(t *testing.T, state approvalceremony.EffectReservationState, reason string) approvalceremony.EffectReservationEvent {
	t.Helper()
	admission := approvalDispatchAdmissionRouteRecord(t)
	authority, err := (contracts.ConnectorReleaseAuthority{
		SchemaVersion: contracts.ConnectorReleaseAuthoritySchemaV1, ContractVersion: contracts.ConnectorReleaseAuthorityContractV1,
		AuthorityID: admission.Admission.ConnectorAuthority.ReleaseAuthorityID, SigningKeyRef: "release-key-a",
		Algorithm: contracts.ConnectorReleaseAuthorityAlgorithmV1, RegistryRevision: admission.Admission.ConnectorAuthority.ReleaseRegistryRevision,
		ScopeKind:   contracts.ConnectorReleaseAuthorityScopeGlobal,
		ConnectorID: admission.Admission.ConnectorAuthority.ConnectorID, ConnectorVersion: admission.Admission.ConnectorAuthority.ConnectorVersion,
		State: contracts.ConnectorReleaseAuthorityStateCertified, ConnectorExecutorKind: admission.Admission.ConnectorAuthority.ConnectorExecutorKind,
		ConnectorBinaryHash:     admission.Admission.ConnectorAuthority.ConnectorBinaryHash,
		ConnectorSignatureRef:   admission.Admission.ConnectorAuthority.ConnectorSignatureRef,
		ConnectorSignerID:       admission.Admission.ConnectorAuthority.ConnectorSignerID,
		ConnectorSignatureHash:  admission.Admission.ConnectorAuthority.ConnectorSignatureHash,
		ConnectorSandboxProfile: admission.Admission.ConnectorAuthority.ConnectorSandboxProfile,
		ConnectorDriftPolicyRef: admission.Admission.ConnectorAuthority.ConnectorDriftPolicyRef,
		CertificationRef:        admission.Admission.ConnectorAuthority.CertificationRef,
		CertificationHash:       admission.Admission.ConnectorAuthority.CertificationHash,
		CertificationAuthority:  admission.Admission.ConnectorAuthority.CertificationAuthority,
		SignedAt:                admission.Admission.IssuedAt.Add(-time.Second), ValidFrom: admission.Admission.IssuedAt.Add(-time.Second),
		ValidUntil: testTimePointer(admission.Admission.IssuedAt.Add(time.Hour)),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	connectorAuthority := admission.Admission.ConnectorAuthority
	connectorAuthority.ReleaseAuthorityHash = authority.AuthorityHash
	connectorAuthority, err = connectorAuthority.Seal()
	if err != nil {
		t.Fatal(err)
	}
	admission.Admission.ConnectorAuthority = connectorAuthority
	admission.Admission, err = admission.Admission.Seal()
	if err != nil {
		t.Fatal(err)
	}
	event := approvalceremony.EffectReservationEvent{
		Admission: admission,
		ReleaseAuthority: contracts.ConnectorReleaseAuthorityEnvelope{
			Authority: authority,
			Signature: strings.Repeat("a", 128),
		},
		ReleaseObservedAt: authority.ValidFrom,
		AdmittedAt:        admission.Admission.IssuedAt,
		OccurredAt:        admission.Admission.IssuedAt,
	}
	switch state {
	case approvalceremony.EffectReservationStateAdmitted:
		event.Sequence = 1
		event.State = state
	case approvalceremony.EffectReservationStateStarted:
		startedAt := admission.Admission.IssuedAt.Add(2 * time.Second)
		event.Sequence = 2
		event.State = state
		event.OccurredAt = startedAt
		event.StartedAt = testTimePointer(startedAt)
		event.ConnectorExecutionRef = "github-request-a"
	case approvalceremony.EffectReservationStateUncertain:
		startedAt := admission.Admission.IssuedAt.Add(2 * time.Second)
		resolvedAt := startedAt.Add(time.Second)
		event.Sequence = 3
		event.State = state
		event.OccurredAt = resolvedAt
		event.StartedAt = testTimePointer(startedAt)
		event.ResolvedAt = testTimePointer(resolvedAt)
		event.ConnectorExecutionRef = "github-request-a"
		event.ReasonCode = reason
	default:
		t.Fatalf("unsupported test state %s", state)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("effect reservation candidate event invalid: %v", err)
	}
	return event
}

func testTimePointer(value time.Time) *time.Time {
	value = value.UTC().Truncate(time.Microsecond)
	return &value
}
