package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

const (
	approvalGrantConsumePath             = "/internal/v1/approval-grants/consume"
	approvalGrantConsumptionRecoverPath  = "/internal/v1/approval-grants/recover"
	approvalDispatchAdmissionPath        = "/internal/v1/approval-grants/admit-dispatch"
	approvalDispatchAdmissionRecoverPath = "/internal/v1/approval-grants/recover-dispatch-admission"
	effectDispositionPath                = "/internal/v1/effect-dispositions"
	effectDispositionRecoverPath         = "/internal/v1/effect-dispositions/recover"
	effectReconciliationCandidatesPath   = "/internal/effect-dispositions/reconciliation-candidates"
	approvalCeremoniesPath               = "/internal/v1/approval-ceremonies"
	approvalGrantConsumptionMaxBody      = 32 << 10
	approvalCeremonyControlMaxBody       = 256 << 10
	approvalCeremonyControlStatus        = "approval_ceremony_control.internal.v1"
	approvalConsumptionReasonHeader      = "X-Helm-Reason-Code"
	approvalConsumptionFencedReason      = "EMERGENCY_STOP_FENCED"
	approvalConsumptionUnverifiedReason  = "EMERGENCY_STOP_UNVERIFIED"
)

var errApprovalConsumptionStopUnverified = errors.New("approval consumption emergency-stop status is unverified")

type approvalGrantConsumer interface {
	ConsumeGrant(context.Context, string, string, string, string) (approvalceremony.Record, error)
	RecoverGrantConsumption(context.Context, string, string, string, string) (approvalceremony.Record, error)
}

type approvalCeremonyController interface {
	BeginOrResume(context.Context, string) (approvalceremony.Record, error)
	Get(context.Context, string) (approvalceremony.Record, error)
	IssueChallenge(context.Context, string) (approvalceremony.Record, error)
	VerifyQuorum(context.Context, string, []contracts.ApprovalAssertion) (approvalceremony.Record, error)
	IssueGrant(context.Context, string) (approvalceremony.Record, error)
}

type approvalControlIdentityProvider struct{}

func (approvalControlIdentityProvider) LoadControlIdentity(ctx context.Context) (approvalceremony.ControlIdentity, error) {
	identity, err := (approvalceremony.ContextConsumerIdentityProvider{}).LoadConsumerIdentity(ctx)
	if err != nil {
		return approvalceremony.ControlIdentity{}, approvalceremony.ErrControlUnavailable
	}
	return approvalceremony.ControlIdentity{
		Subject: identity.Subject, TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID,
	}, nil
}

type approvalDispatchAdmitter interface {
	Claim(context.Context, approvalceremony.DispatchAdmissionRequest) (approvalceremony.DispatchAdmissionRecord, error)
	Recover(context.Context, approvalceremony.DispatchAdmissionRequest) (approvalceremony.DispatchAdmissionRecord, error)
}

type effectDispositionRecorder interface {
	Record(context.Context, contracts.EffectDispositionCommandEnvelope) (approvalceremony.EffectDispositionRecord, error)
	Recover(context.Context, string) (approvalceremony.EffectDispositionRecord, error)
}

type effectReconciliationCandidateProvider interface {
	ListReconciliationCandidates(context.Context) (contracts.EffectReconciliationCandidates, error)
}

type approvalConsumerTokenValidator interface {
	ValidateAuthorization(string) (*mcppkg.OAuthTokenClaims, error)
}

type approvalConsumptionRuntime struct {
	consumer                 approvalGrantConsumer
	admitter                 approvalDispatchAdmitter
	controller               approvalCeremonyController
	validator                approvalConsumerTokenValidator
	dispatchValidator        approvalConsumerTokenValidator
	controlValidator         approvalConsumerTokenValidator
	disposition              effectDispositionRecorder
	dispositionValidator     approvalConsumerTokenValidator
	reconciliationCandidates effectReconciliationCandidateProvider
	reconciliationValidator  approvalConsumerTokenValidator
	stops                    kernel.ScopedStopReader
	audience                 string
	maxTokenTTL              time.Duration
}

type approvalGrantConsumptionRequest struct {
	ApprovalID string `json:"approval_id"`
	GrantID    string `json:"grant_id"`
	GrantHash  string `json:"grant_hash"`
	Nonce      string `json:"nonce"`
}

type approvalCeremonyBeginRequest struct {
	BindingRef string `json:"binding_ref"`
}

type approvalCeremonyAssertionsRequest struct {
	Assertions []contracts.ApprovalAssertion `json:"assertions"`
}

type approvalCeremonyControlResponse struct {
	State                   approvalceremony.State       `json:"state"`
	ApprovalID              string                       `json:"approval_id"`
	TenantID                string                       `json:"tenant_id"`
	WorkspaceID             string                       `json:"workspace_id"`
	BindingRef              string                       `json:"binding_ref"`
	Challenge               *contracts.ApprovalChallenge `json:"challenge,omitempty"`
	Grant                   *contracts.ApprovalGrant     `json:"grant,omitempty"`
	GrantSignatureAlgorithm string                       `json:"grant_signature_algorithm,omitempty"`
	GrantSignature          string                       `json:"grant_signature,omitempty"`
	HoldStartedAt           time.Time                    `json:"hold_started_at"`
	ExpiresAt               *time.Time                   `json:"expires_at,omitempty"`
	ConsumedAt              *time.Time                   `json:"consumed_at,omitempty"`
	ConsumedBy              string                       `json:"consumed_by,omitempty"`
	Version                 int64                        `json:"version"`
}

type approvalGrantConsumptionResponse struct {
	State                         approvalceremony.State             `json:"state"`
	ApprovalID                    string                             `json:"approval_id"`
	GrantID                       string                             `json:"grant_id"`
	GrantHash                     string                             `json:"grant_hash"`
	TenantID                      string                             `json:"tenant_id"`
	WorkspaceID                   string                             `json:"workspace_id"`
	Audience                      string                             `json:"audience"`
	ConsumedBy                    string                             `json:"consumed_by"`
	Consumption                   contracts.ApprovalGrantConsumption `json:"consumption"`
	ConsumptionSignatureAlgorithm string                             `json:"consumption_signature_algorithm"`
	ConsumptionSignature          string                             `json:"consumption_signature"`
	Version                       int64                              `json:"version"`
}

type approvalDispatchAdmissionResponse struct {
	Admission                   contracts.ApprovalDispatchAdmission `json:"admission"`
	AdmissionSignatureAlgorithm string                              `json:"admission_signature_algorithm"`
	AdmissionSignature          string                              `json:"admission_signature"`
}

func registerApprovalGrantConsumptionRoutes(mux *http.ServeMux, runtime *approvalConsumptionRuntime) {
	if mux == nil || runtime == nil {
		return
	}
	mux.HandleFunc(approvalGrantConsumePath, runtime.protect(runtime.handle(false)))
	mux.HandleFunc(approvalGrantConsumptionRecoverPath, runtime.protect(runtime.handle(true)))
	mux.HandleFunc(approvalDispatchAdmissionPath, runtime.protectDispatch(runtime.handleDispatch(false)))
	mux.HandleFunc(approvalDispatchAdmissionRecoverPath, runtime.protectDispatch(runtime.handleDispatch(true)))
	if runtime.controller != nil {
		mux.HandleFunc(approvalCeremoniesPath, runtime.protectControl(runtime.handleApprovalCeremonyCollection))
		mux.HandleFunc(approvalCeremoniesPath+"/", runtime.protectControl(runtime.handleApprovalCeremonyItem))
	}
	if runtime.disposition != nil {
		mux.HandleFunc(effectDispositionPath, runtime.protectDisposition(runtime.handleEffectDispositionRecord))
		mux.HandleFunc(effectDispositionRecoverPath, runtime.protectDisposition(runtime.handleEffectDispositionRecover))
	}
	if runtime.reconciliationCandidates != nil {
		mux.HandleFunc(effectReconciliationCandidatesPath, runtime.protectReconciliationCandidates(runtime.handleEffectReconciliationCandidates))
	}
}

func (runtime *approvalConsumptionRuntime) protectControl(next http.HandlerFunc) http.HandlerFunc {
	protected := runtime.protectWorkload(
		runtime.controlValidator, runtime != nil && runtime.controller != nil && runtime.stops != nil,
		"helm-approval-control", "approval-controller", "approval control", next,
	)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Helm-Contract-Status", approvalCeremonyControlStatus)
		protected(w, r)
	}
}

func (runtime *approvalConsumptionRuntime) handleApprovalCeremonyCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.WriteMethodNotAllowed(w)
		return
	}
	if !approvalCeremonyRequestHasNoQuery(w, r) || !requireApprovalCeremonyJSON(w, r) {
		return
	}
	var request approvalCeremonyBeginRequest
	if decodeApprovalCeremonyRequest(w, r, &request) != nil || !validWorkloadClaim(request.BindingRef) {
		api.WriteBadRequest(w, "Invalid approval ceremony binding reference")
		return
	}
	if err := runtime.requireUnfencedConsumerScope(r.Context()); err != nil {
		writeApprovalCeremonyError(w, err)
		return
	}
	record, err := runtime.controller.BeginOrResume(r.Context(), request.BindingRef)
	writeApprovalCeremonyResult(w, record, err)
}

func (runtime *approvalConsumptionRuntime) handleApprovalCeremonyItem(w http.ResponseWriter, r *http.Request) {
	if !approvalCeremonyRequestHasNoQuery(w, r) {
		return
	}
	approvalID, action, ok := approvalCeremonyPath(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		if !requireEmptyApprovalCeremonyBody(w, r) {
			return
		}
		record, err := runtime.controller.Get(r.Context(), approvalID)
		writeApprovalCeremonyResult(w, record, err)
	case action == "challenge" && r.Method == http.MethodPost:
		if !requireEmptyApprovalCeremonyBody(w, r) {
			return
		}
		if err := runtime.requireUnfencedConsumerScope(r.Context()); err != nil {
			writeApprovalCeremonyError(w, err)
			return
		}
		record, err := runtime.issueApprovalChallenge(r.Context(), approvalID)
		writeApprovalCeremonyResult(w, record, err)
	case action == "assertions" && r.Method == http.MethodPost:
		if !requireApprovalCeremonyJSON(w, r) {
			return
		}
		var request approvalCeremonyAssertionsRequest
		if decodeApprovalCeremonyRequest(w, r, &request) != nil || len(request.Assertions) == 0 {
			api.WriteBadRequest(w, "Invalid approval ceremony assertions")
			return
		}
		if err := runtime.requireUnfencedConsumerScope(r.Context()); err != nil {
			writeApprovalCeremonyError(w, err)
			return
		}
		record, err := runtime.submitApprovalAssertions(r.Context(), approvalID, request.Assertions)
		writeApprovalCeremonyResult(w, record, err)
	default:
		api.WriteMethodNotAllowed(w)
	}
}

func (runtime *approvalConsumptionRuntime) issueApprovalChallenge(ctx context.Context, approvalID string) (approvalceremony.Record, error) {
	for range 3 {
		record, err := runtime.controller.Get(ctx, approvalID)
		if err != nil {
			return approvalceremony.Record{}, err
		}
		switch record.State {
		case approvalceremony.StateHoldPending:
			record, err = runtime.controller.IssueChallenge(ctx, approvalID)
			if errors.Is(err, approvalceremony.ErrTransitionConflict) {
				continue
			}
			return record, err
		case approvalceremony.StateChallengeIssued, approvalceremony.StateQuorumVerified,
			approvalceremony.StateGrantIssued, approvalceremony.StateConsumed:
			return record, nil
		default:
			return approvalceremony.Record{}, approvalceremony.ErrTransitionConflict
		}
	}
	return approvalceremony.Record{}, approvalceremony.ErrTransitionConflict
}

func (runtime *approvalConsumptionRuntime) submitApprovalAssertions(ctx context.Context, approvalID string, assertions []contracts.ApprovalAssertion) (approvalceremony.Record, error) {
	for range 5 {
		record, err := runtime.controller.Get(ctx, approvalID)
		if err != nil {
			return approvalceremony.Record{}, err
		}
		switch record.State {
		case approvalceremony.StateChallengeIssued:
			_, err = runtime.controller.VerifyQuorum(ctx, approvalID, assertions)
			if errors.Is(err, approvalceremony.ErrTransitionConflict) {
				continue
			}
			if err != nil {
				return approvalceremony.Record{}, err
			}
		case approvalceremony.StateQuorumVerified:
			_, err = runtime.controller.IssueGrant(ctx, approvalID)
			if errors.Is(err, approvalceremony.ErrTransitionConflict) {
				continue
			}
			if err != nil {
				return approvalceremony.Record{}, err
			}
		case approvalceremony.StateGrantIssued, approvalceremony.StateConsumed:
			return record, nil
		default:
			return approvalceremony.Record{}, approvalceremony.ErrTransitionConflict
		}
	}
	return approvalceremony.Record{}, approvalceremony.ErrTransitionConflict
}

func approvalCeremonyRequestHasNoQuery(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery == "" && !r.URL.ForceQuery {
		return true
	}
	api.WriteBadRequest(w, "Approval ceremony routes do not accept caller-selected scope")
	return false
}

func approvalCeremonyPath(r *http.Request) (string, string, bool) {
	if r.URL.RawPath != "" || !strings.HasPrefix(r.URL.Path, approvalCeremoniesPath+"/") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, approvalCeremoniesPath+"/"), "/")
	if len(parts) == 1 && validWorkloadClaim(parts[0]) {
		return parts[0], "", true
	}
	if len(parts) == 2 && validWorkloadClaim(parts[0]) && (parts[1] == "challenge" || parts[1] == "assertions") {
		return parts[0], parts[1], true
	}
	return "", "", false
}

func requireApprovalCeremonyJSON(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		api.WriteError(w, http.StatusUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json")
		return false
	}
	return true
}

func decodeApprovalCeremonyRequest(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, approvalCeremonyControlMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON object")
	}
	return nil
}

func requireEmptyApprovalCeremonyBody(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) != 0 {
		api.WriteBadRequest(w, "Approval ceremony route does not accept a request body")
		return false
	}
	return true
}

func writeApprovalCeremonyResult(w http.ResponseWriter, record approvalceremony.Record, err error) {
	if err != nil {
		writeApprovalCeremonyError(w, err)
		return
	}
	response := approvalCeremonyControlResponse{
		State: record.State, ApprovalID: record.ApprovalID, TenantID: record.TenantID,
		WorkspaceID: record.WorkspaceID, BindingRef: record.Spec.BindingRef,
		Challenge: record.Challenge, Grant: record.Grant,
		GrantSignatureAlgorithm: record.GrantSignatureAlgorithm, GrantSignature: record.GrantSignature,
		HoldStartedAt: record.HoldStartedAt, ExpiresAt: record.ExpiresAt,
		ConsumedAt: record.ConsumedAt, ConsumedBy: record.ConsumedBy, Version: record.Version,
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Helm-Contract-Status", approvalCeremonyControlStatus)
	_ = json.NewEncoder(w).Encode(response)
}

func writeApprovalCeremonyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, approvalceremony.ErrInvalidRecord):
		api.WriteBadRequest(w, "Invalid approval ceremony request")
	case errors.Is(err, approvalceremony.ErrNotFound):
		api.WriteError(w, http.StatusNotFound, "Approval ceremony not found", "no matching ceremony exists in this workload scope")
	case errors.Is(err, approvalceremony.ErrHoldPending), errors.Is(err, approvalceremony.ErrTransitionConflict),
		errors.Is(err, approvalverify.ErrDuplicateSigner), errors.Is(err, approvalverify.ErrQuorumNotMet):
		api.WriteConflict(w, "Approval ceremony conflicts with current authority state")
	case errors.Is(err, approvalverify.ErrVerificationFailed):
		api.WriteBadRequest(w, "Approval assertion verification failed")
	case errors.Is(err, approvalceremony.ErrControlUnavailable), errors.Is(err, approvalverify.ErrAuthorityRejected),
		errors.Is(err, approvalverify.ErrSignatureRejected):
		api.WriteForbidden(w, "Approval ceremony authority rejected the request")
	case errors.Is(err, approvalceremony.ErrEmergencyStopFenced):
		w.Header().Set(approvalConsumptionReasonHeader, approvalConsumptionFencedReason)
		api.WriteConflict(w, "Approval ceremony is emergency-stop fenced")
	case errors.Is(err, errApprovalConsumptionStopUnverified):
		w.Header().Set(approvalConsumptionReasonHeader, approvalConsumptionUnverifiedReason)
		api.WriteError(w, http.StatusServiceUnavailable, "Approval ceremony unavailable", approvalConsumptionUnverifiedReason)
	default:
		api.WriteError(w, http.StatusServiceUnavailable, "Approval ceremony unavailable", "durable approval authority rejected the operation")
	}
}

func (runtime *approvalConsumptionRuntime) protect(next http.HandlerFunc) http.HandlerFunc {
	return runtime.protectWorkload(
		runtime.validator, runtime != nil && runtime.consumer != nil && runtime.stops != nil,
		"helm-approval-consumer", "approval-consumer", "approval consumption", next,
	)
}

func (runtime *approvalConsumptionRuntime) protectDispatch(next http.HandlerFunc) http.HandlerFunc {
	return runtime.protectWorkload(
		runtime.dispatchValidator, runtime != nil && runtime.admitter != nil && runtime.stops != nil,
		"helm-approval-dispatch", "approval-dispatcher", "approval dispatch", next,
	)
}

func (runtime *approvalConsumptionRuntime) protectDisposition(next http.HandlerFunc) http.HandlerFunc {
	protected := runtime.protectWorkload(
		runtime.dispositionValidator, runtime != nil && runtime.disposition != nil,
		"helm-effect-disposition", "effect-disposition-recorder", "effect disposition", next,
	)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Helm-Contract-Status", "internal_non_production")
		protected(w, r)
	}
}

func (runtime *approvalConsumptionRuntime) protectReconciliationCandidates(next http.HandlerFunc) http.HandlerFunc {
	protected := runtime.protectWorkload(
		runtime.reconciliationValidator, runtime != nil && runtime.reconciliationCandidates != nil,
		"helm-effect-reconciliation", "effect-reconciliation-reader", "effect reconciliation observation", next,
	)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Helm-Contract-Status", "internal_non_production")
		protected(w, r)
	}
}

func (runtime *approvalConsumptionRuntime) handleEffectDispositionRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.WriteMethodNotAllowed(w)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		api.WriteError(w, http.StatusUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json")
		return
	}
	var envelope contracts.EffectDispositionCommandEnvelope
	r.Body = http.MaxBytesReader(w, r.Body, approvalGrantConsumptionMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.Validate() != nil {
		api.WriteBadRequest(w, "Invalid effect disposition command")
		return
	}
	record, err := runtime.disposition.Record(r.Context(), envelope)
	if err != nil {
		writeEffectDispositionError(w, err)
		return
	}
	writeEffectDispositionRecord(w, record)
}

func (runtime *approvalConsumptionRuntime) handleEffectDispositionRecover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.WriteMethodNotAllowed(w)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		api.WriteError(w, http.StatusUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json")
		return
	}
	var request struct {
		CommandID string `json:"command_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, approvalGrantConsumptionMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validWorkloadClaim(request.CommandID) {
		api.WriteBadRequest(w, "Invalid effect disposition command id")
		return
	}
	record, err := runtime.disposition.Recover(r.Context(), request.CommandID)
	if err != nil {
		writeEffectDispositionError(w, err)
		return
	}
	writeEffectDispositionRecord(w, record)
}

func (runtime *approvalConsumptionRuntime) handleEffectReconciliationCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.WriteMethodNotAllowed(w)
		return
	}
	// The workload identity is the only scope input. Never let a caller select
	// a FENCE, tenant, workspace, reservation, or connector tuple here.
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		api.WriteBadRequest(w, "Effect reconciliation candidates do not accept caller-selected scope")
		return
	}
	projection, err := runtime.reconciliationCandidates.ListReconciliationCandidates(r.Context())
	if err != nil {
		writeEffectDispositionError(w, err)
		return
	}
	if err := projection.Validate(); err != nil {
		api.WriteError(w, http.StatusServiceUnavailable, "Effect reconciliation candidates unavailable", "Kernel projection is incomplete")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(projection)
}

func writeEffectDispositionRecord(w http.ResponseWriter, record approvalceremony.EffectDispositionRecord) {
	if record.Validate() != nil {
		api.WriteError(w, http.StatusServiceUnavailable, "Effect disposition unavailable", "signed disposition record is incomplete")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Helm-Contract-Status", "internal_non_production")
	_ = json.NewEncoder(w).Encode(record)
}

func writeEffectDispositionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, approvalceremony.ErrInvalidRecord):
		api.WriteBadRequest(w, "Invalid effect disposition command")
	case errors.Is(err, approvalceremony.ErrConsumerUnavailable), errors.Is(err, approvalceremony.ErrEffectDispositionCommandRejected):
		api.WriteForbidden(w, "Effect disposition authority rejected the request")
	case errors.Is(err, approvalceremony.ErrNotFound):
		api.WriteError(w, http.StatusNotFound, "Effect disposition not found", "no signed disposition exists for this workload scope")
	case errors.Is(err, approvalceremony.ErrEffectDispositionConflict), errors.Is(err, approvalceremony.ErrEffectDispositionTerminal),
		errors.Is(err, approvalceremony.ErrEffectDispositionRequiresFence), errors.Is(err, approvalceremony.ErrTransitionConflict):
		api.WriteConflict(w, "Effect disposition conflicts with current authority state")
	default:
		api.WriteError(w, http.StatusServiceUnavailable, "Effect disposition unavailable", "durable disposition authority rejected the operation")
	}
}

func (runtime *approvalConsumptionRuntime) protectWorkload(validator approvalConsumerTokenValidator, ready bool, realm, role, capability string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if runtime == nil || !ready || validator == nil ||
			!validWorkloadClaim(runtime.audience) || runtime.maxTokenTTL <= 0 {
			api.WriteError(w, http.StatusServiceUnavailable, "Approval grant consumer unavailable", "workload authentication is not configured")
			return
		}
		token, detail, ok := helmauth.BearerToken(r)
		if !ok {
			writeApprovalWorkloadUnauthorized(w, realm, detail)
			return
		}
		claims, err := validator.ValidateAuthorization(token)
		if err != nil {
			var validationErr *mcppkg.JWKSValidationError
			if errors.As(err, &validationErr) && validationErr.Kind == mcppkg.JWKSErrMissingScope {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s", error="insufficient_scope"`, realm))
				api.WriteForbidden(w, "Workload token is missing the "+capability+" scope")
				return
			}
			writeApprovalWorkloadUnauthorized(w, realm, "Invalid or expired workload token")
			return
		}
		if claims == nil || !validWorkloadClaim(claims.RegisteredClaims.Subject) ||
			!validWorkloadClaim(claims.TenantID) || !validWorkloadClaim(claims.WorkspaceID) {
			writeApprovalWorkloadUnauthorized(w, realm, "Workload token subject, tenant, and workspace are required")
			return
		}
		issuedAt := claims.RegisteredClaims.IssuedAt
		expiresAt := claims.RegisteredClaims.ExpiresAt
		if issuedAt == nil || expiresAt == nil || !expiresAt.After(issuedAt.Time) ||
			expiresAt.Sub(issuedAt.Time) > runtime.maxTokenTTL {
			writeApprovalWorkloadUnauthorized(w, realm, "Workload token lifetime is invalid")
			return
		}
		identity := approvalceremony.ConsumerIdentity{
			Subject: claims.RegisteredClaims.Subject, TenantID: claims.TenantID,
			WorkspaceID: claims.WorkspaceID, Audience: runtime.audience,
		}
		ctx := approvalceremony.WithConsumerIdentity(r.Context(), identity)
		ctx = helmauth.WithPrincipal(ctx, &helmauth.BasePrincipal{
			ID: identity.Subject, TenantID: identity.TenantID, Roles: []string{role},
		})
		next(w, r.WithContext(ctx))
	}
}

func (runtime *approvalConsumptionRuntime) handleDispatch(recoverOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		mediaType, _, mediaTypeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaTypeErr != nil || mediaType != "application/json" {
			api.WriteError(w, http.StatusUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json")
			return
		}
		request, err := decodeApprovalDispatchAdmissionRequest(w, r)
		if err != nil {
			api.WriteBadRequest(w, "Invalid approval dispatch admission request")
			return
		}
		var record approvalceremony.DispatchAdmissionRecord
		if recoverOnly {
			record, err = runtime.admitter.Recover(r.Context(), request)
		} else {
			record, err = runtime.admitter.Claim(r.Context(), request)
		}
		if err != nil {
			writeApprovalConsumptionError(w, err)
			return
		}
		if err := record.Validate(); err != nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Approval dispatch admission unavailable", "admission record is incomplete")
			return
		}
		response := approvalDispatchAdmissionResponse{
			Admission:                   record.Admission,
			AdmissionSignatureAlgorithm: record.SignatureAlgorithm,
			AdmissionSignature:          record.Signature,
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Helm-Contract-Status", "internal_non_production")
		_ = json.NewEncoder(w).Encode(response)
	}
}

func (runtime *approvalConsumptionRuntime) handle(recoverOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		mediaType, _, mediaTypeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaTypeErr != nil || mediaType != "application/json" {
			api.WriteError(w, http.StatusUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json")
			return
		}
		request, err := decodeApprovalGrantConsumptionRequest(w, r)
		if err != nil {
			api.WriteBadRequest(w, "Invalid approval grant consumption request")
			return
		}
		var record approvalceremony.Record
		if recoverOnly {
			record, err = runtime.consumer.RecoverGrantConsumption(
				r.Context(), request.ApprovalID, request.GrantID, request.GrantHash, request.Nonce,
			)
		} else {
			if err := runtime.requireUnfencedConsumerScope(r.Context()); err != nil {
				writeApprovalConsumptionError(w, err)
				return
			}
			record, err = runtime.consumer.ConsumeGrant(
				r.Context(), request.ApprovalID, request.GrantID, request.GrantHash, request.Nonce,
			)
		}
		if err != nil {
			writeApprovalConsumptionError(w, err)
			return
		}
		if record.State != approvalceremony.StateConsumed || record.GrantConsumption == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Approval grant consumer unavailable", "consumption record is incomplete")
			return
		}
		consumption := *record.GrantConsumption
		response := approvalGrantConsumptionResponse{
			State: record.State, ApprovalID: consumption.ApprovalID, GrantID: consumption.GrantID,
			GrantHash: consumption.GrantHash, TenantID: consumption.TenantID,
			WorkspaceID: consumption.WorkspaceID, Audience: consumption.Audience,
			ConsumedBy: consumption.ConsumedBy, Consumption: consumption,
			ConsumptionSignatureAlgorithm: record.ConsumptionSignatureAlgorithm,
			ConsumptionSignature:          record.ConsumptionSignature, Version: record.Version,
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Helm-Contract-Status", "internal_non_production")
		_ = json.NewEncoder(w).Encode(response)
	}
}

func (runtime *approvalConsumptionRuntime) requireUnfencedConsumerScope(ctx context.Context) error {
	identity, err := (approvalceremony.ContextConsumerIdentityProvider{}).LoadConsumerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("%w: verified workload scope is absent", errApprovalConsumptionStopUnverified)
	}
	_, fenced, err := runtime.stops.IsFenced(ctx, kernel.StopScope{
		TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID,
	})
	if err != nil {
		return fmt.Errorf("%w: scoped stop reader failed", errApprovalConsumptionStopUnverified)
	}
	if fenced {
		return approvalceremony.ErrEmergencyStopFenced
	}
	return nil
}

func decodeApprovalGrantConsumptionRequest(w http.ResponseWriter, r *http.Request) (approvalGrantConsumptionRequest, error) {
	var request approvalGrantConsumptionRequest
	r.Body = http.MaxBytesReader(w, r.Body, approvalGrantConsumptionMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return approvalGrantConsumptionRequest{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return approvalGrantConsumptionRequest{}, errors.New("request must contain exactly one JSON object")
	}
	if !validWorkloadClaim(request.ApprovalID) || !validWorkloadClaim(request.GrantID) ||
		!validSHA256Reference(request.GrantHash) || !validLowerHex(request.Nonce, 32) {
		return approvalGrantConsumptionRequest{}, errors.New("approval grant tuple is invalid")
	}
	return request, nil
}

func decodeApprovalDispatchAdmissionRequest(w http.ResponseWriter, r *http.Request) (approvalceremony.DispatchAdmissionRequest, error) {
	var request approvalceremony.DispatchAdmissionRequest
	r.Body = http.MaxBytesReader(w, r.Body, approvalGrantConsumptionMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return approvalceremony.DispatchAdmissionRequest{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return approvalceremony.DispatchAdmissionRequest{}, errors.New("request must contain exactly one JSON object")
	}
	if err := request.Validate(); err != nil {
		return approvalceremony.DispatchAdmissionRequest{}, err
	}
	return request, nil
}

func writeApprovalConsumptionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, approvalceremony.ErrInvalidRecord):
		api.WriteBadRequest(w, "Approval grant tuple is invalid")
	case errors.Is(err, approvalceremony.ErrNotFound):
		api.WriteError(w, http.StatusNotFound, "Approval grant not found", "no matching live grant exists for this workload scope")
	case errors.Is(err, approvalceremony.ErrTransitionConflict):
		api.WriteError(w, http.StatusConflict, "Approval grant unavailable", "grant state, tuple, or expiry does not permit this operation")
	case errors.Is(err, approvalceremony.ErrConsumerUnavailable):
		api.WriteForbidden(w, "Workload identity does not match the signed grant")
	case errors.Is(err, approvalceremony.ErrEmergencyStopFenced):
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(approvalConsumptionReasonHeader, approvalConsumptionFencedReason)
		api.WriteError(w, http.StatusConflict, "Approval grant fenced", approvalConsumptionFencedReason)
	case errors.Is(err, errApprovalConsumptionStopUnverified):
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(approvalConsumptionReasonHeader, approvalConsumptionUnverifiedReason)
		api.WriteError(w, http.StatusServiceUnavailable, "Approval grant consumer unavailable", approvalConsumptionUnverifiedReason)
	default:
		api.WriteError(w, http.StatusServiceUnavailable, "Approval grant consumer unavailable", "durable grant authority rejected the operation")
	}
}

func writeApprovalConsumerUnauthorized(w http.ResponseWriter, detail string) {
	writeApprovalWorkloadUnauthorized(w, "helm-approval-consumer", detail)
}

func writeApprovalWorkloadUnauthorized(w http.ResponseWriter, realm, detail string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s"`, realm))
	httperr.WriteUnauthorized(w, detail)
}

func validSHA256Reference(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validLowerHex(strings.TrimPrefix(value, "sha256:"), 32)
}

func validLowerHex(value string, size int) bool {
	if len(value) != size*2 || strings.ToLower(value) != value {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == size
}

func validWorkloadClaim(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
