package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapprovalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

const (
	generatedSpecApprovalBeginPath      = "/internal/v1/generated-spec-approvals/begin"
	generatedSpecApprovalGetPath        = "/internal/v1/generated-spec-approvals/get"
	generatedSpecApprovalChallengePath  = "/internal/v1/generated-spec-approvals/challenge"
	generatedSpecApprovalSubmitPath     = "/internal/v1/generated-spec-approvals/submit"
	generatedSpecApprovalConsumePath    = "/internal/v1/generated-spec-approvals/consume"
	generatedSpecApprovalRecoverPath    = "/internal/v1/generated-spec-approvals/recover"
	generatedSpecApprovalMaxBody        = 256 << 10
	generatedSpecApprovalContractStatus = "generated_spec_approval.v1"
)

type generatedSpecApprovalIdentityContextKey struct{}

type generatedSpecApprovalRouteIdentity struct {
	Subject     string
	TenantID    string
	WorkspaceID string
	Audience    string
}

type generatedSpecApprovalContextIdentityProvider struct{}

func (generatedSpecApprovalContextIdentityProvider) LoadControlIdentity(ctx context.Context) (generatedspecapprovalceremony.ControlIdentity, error) {
	identity, ok := ctx.Value(generatedSpecApprovalIdentityContextKey{}).(generatedSpecApprovalRouteIdentity)
	if !ok || !validWorkloadClaim(identity.Subject) || !validWorkloadClaim(identity.TenantID) || !validWorkloadClaim(identity.WorkspaceID) {
		return generatedspecapprovalceremony.ControlIdentity{}, generatedspecapprovalceremony.ErrControlUnavailable
	}
	return generatedspecapprovalceremony.ControlIdentity{Subject: identity.Subject, TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID}, nil
}

func (generatedSpecApprovalContextIdentityProvider) LoadConsumerIdentity(ctx context.Context) (generatedspecapprovalceremony.ConsumerIdentity, error) {
	identity, ok := ctx.Value(generatedSpecApprovalIdentityContextKey{}).(generatedSpecApprovalRouteIdentity)
	if !ok || !validWorkloadClaim(identity.Subject) || !validWorkloadClaim(identity.TenantID) ||
		!validWorkloadClaim(identity.WorkspaceID) || identity.Audience != contracts.GeneratedSpecApprovalAudienceV1 {
		return generatedspecapprovalceremony.ConsumerIdentity{}, generatedspecapprovalceremony.ErrConsumerUnavailable
	}
	return generatedspecapprovalceremony.ConsumerIdentity{
		Subject: identity.Subject, TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID, Audience: identity.Audience,
	}, nil
}

type generatedSpecApprovalIDRequest struct {
	ApprovalID string `json:"approval_id"`
}

type generatedSpecApprovalBeginRequest struct {
	BindingRef string `json:"binding_ref"`
}

type generatedSpecApprovalSubmitRequest struct {
	ApprovalID string                                     `json:"approval_id"`
	Assertions []contracts.GeneratedSpecApprovalAssertion `json:"assertions"`
}

type generatedSpecApprovalConsumeRequest struct {
	ApprovalID string `json:"approval_id"`
	GrantID    string `json:"grant_id"`
	GrantHash  string `json:"grant_hash"`
	Nonce      string `json:"nonce"`
}

type generatedSpecApprovalRecordResponse struct {
	State         generatedspecapprovalceremony.State       `json:"state"`
	ApprovalID    string                                    `json:"approval_id"`
	TenantID      string                                    `json:"tenant_id"`
	WorkspaceID   string                                    `json:"workspace_id"`
	Challenge     *contracts.GeneratedSpecApprovalChallenge `json:"challenge,omitempty"`
	Grant         *generatedspecapproval.SignedGrant        `json:"grant,omitempty"`
	Consumption   *generatedspecapproval.SignedConsumption  `json:"consumption,omitempty"`
	HoldStartedAt time.Time                                 `json:"hold_started_at"`
	ExpiresAt     *time.Time                                `json:"expires_at,omitempty"`
	ConsumedAt    *time.Time                                `json:"consumed_at,omitempty"`
	ConsumedBy    string                                    `json:"consumed_by,omitempty"`
	Version       int64                                     `json:"version"`
}

func registerGeneratedSpecApprovalRoutes(mux *http.ServeMux, runtime *generatedSpecApprovalRuntime) {
	if mux == nil || runtime == nil {
		return
	}
	mux.HandleFunc(generatedSpecApprovalBeginPath, runtime.protectControl(runtime.handleBegin))
	mux.HandleFunc(generatedSpecApprovalGetPath, runtime.protectControl(runtime.handleGet))
	mux.HandleFunc(generatedSpecApprovalChallengePath, runtime.protectControl(runtime.handleChallenge))
	mux.HandleFunc(generatedSpecApprovalSubmitPath, runtime.protectControl(runtime.handleSubmit))
	mux.HandleFunc(generatedSpecApprovalConsumePath, runtime.protectConsumer(runtime.handleConsume(false)))
	mux.HandleFunc(generatedSpecApprovalRecoverPath, runtime.protectConsumer(runtime.handleConsume(true)))
}

func (runtime *generatedSpecApprovalRuntime) protectControl(next http.HandlerFunc) http.HandlerFunc {
	return runtime.protect(runtime.controlValidator, "helm-generated-spec-approval-control", "generated-spec-approval-controller", "control", next)
}

func (runtime *generatedSpecApprovalRuntime) protectConsumer(next http.HandlerFunc) http.HandlerFunc {
	return runtime.protect(runtime.consumerValidator, "helm-generated-spec-approval-consumer", "generated-spec-approval-consumer", "consume", next)
}

func (runtime *generatedSpecApprovalRuntime) protect(validator approvalConsumerTokenValidator, realm, role, capability string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if runtime == nil || runtime.service == nil || validator == nil || runtime.audience != contracts.GeneratedSpecApprovalAudienceV1 || runtime.maxTokenTTL <= 0 {
			api.WriteError(w, http.StatusServiceUnavailable, "GeneratedSpec approval unavailable", "workload authentication is not configured")
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
				api.WriteForbidden(w, "Workload token is missing the GeneratedSpec approval "+capability+" scope")
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
		issuedAt, expiresAt := claims.RegisteredClaims.IssuedAt, claims.RegisteredClaims.ExpiresAt
		if issuedAt == nil || expiresAt == nil || !expiresAt.After(issuedAt.Time) || expiresAt.Sub(issuedAt.Time) > runtime.maxTokenTTL {
			writeApprovalWorkloadUnauthorized(w, realm, "Workload token lifetime is invalid")
			return
		}
		identity := generatedSpecApprovalRouteIdentity{
			Subject: claims.RegisteredClaims.Subject, TenantID: claims.TenantID,
			WorkspaceID: claims.WorkspaceID, Audience: runtime.audience,
		}
		ctx := context.WithValue(r.Context(), generatedSpecApprovalIdentityContextKey{}, identity)
		ctx = helmauth.WithPrincipal(ctx, &helmauth.BasePrincipal{ID: identity.Subject, TenantID: identity.TenantID, Roles: []string{role}})
		next(w, r.WithContext(ctx))
	}
}

func (runtime *generatedSpecApprovalRuntime) handleBegin(w http.ResponseWriter, r *http.Request) {
	if !requireGeneratedSpecApprovalPOST(w, r) {
		return
	}
	var request generatedSpecApprovalBeginRequest
	if decodeGeneratedSpecApprovalRequest(w, r, &request) != nil || !validWorkloadClaim(request.BindingRef) {
		api.WriteBadRequest(w, "Invalid GeneratedSpec approval binding reference")
		return
	}
	record, err := runtime.service.BeginHold(r.Context(), request.BindingRef)
	writeGeneratedSpecApprovalResult(w, record, err)
}

func (runtime *generatedSpecApprovalRuntime) handleGet(w http.ResponseWriter, r *http.Request) {
	if !requireGeneratedSpecApprovalPOST(w, r) {
		return
	}
	var request generatedSpecApprovalIDRequest
	if decodeGeneratedSpecApprovalRequest(w, r, &request) != nil || !validWorkloadClaim(request.ApprovalID) {
		api.WriteBadRequest(w, "Invalid GeneratedSpec approval id")
		return
	}
	record, err := runtime.service.Get(r.Context(), request.ApprovalID)
	writeGeneratedSpecApprovalResult(w, record, err)
}

func (runtime *generatedSpecApprovalRuntime) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if !requireGeneratedSpecApprovalPOST(w, r) {
		return
	}
	var request generatedSpecApprovalIDRequest
	if decodeGeneratedSpecApprovalRequest(w, r, &request) != nil || !validWorkloadClaim(request.ApprovalID) {
		api.WriteBadRequest(w, "Invalid GeneratedSpec approval id")
		return
	}
	record, err := runtime.service.IssueChallenge(r.Context(), request.ApprovalID)
	writeGeneratedSpecApprovalResult(w, record, err)
}

func (runtime *generatedSpecApprovalRuntime) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if !requireGeneratedSpecApprovalPOST(w, r) {
		return
	}
	var request generatedSpecApprovalSubmitRequest
	if decodeGeneratedSpecApprovalRequest(w, r, &request) != nil || !validWorkloadClaim(request.ApprovalID) || len(request.Assertions) == 0 {
		api.WriteBadRequest(w, "Invalid GeneratedSpec approval assertions")
		return
	}
	record, err := runtime.service.Get(r.Context(), request.ApprovalID)
	if err == nil && record.State == generatedspecapprovalceremony.StateChallengeIssued {
		record, err = runtime.service.VerifyQuorum(r.Context(), request.ApprovalID, request.Assertions)
	}
	if err == nil && record.State == generatedspecapprovalceremony.StateQuorumVerified {
		record, err = runtime.service.IssueGrant(r.Context(), request.ApprovalID)
	}
	if err == nil && record.State != generatedspecapprovalceremony.StateGrantIssued && record.State != generatedspecapprovalceremony.StateConsumed {
		err = generatedspecapprovalceremony.ErrTransitionConflict
	}
	writeGeneratedSpecApprovalResult(w, record, err)
}

func (runtime *generatedSpecApprovalRuntime) handleConsume(recoverOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireGeneratedSpecApprovalPOST(w, r) {
			return
		}
		var request generatedSpecApprovalConsumeRequest
		if decodeGeneratedSpecApprovalRequest(w, r, &request) != nil || !validWorkloadClaim(request.ApprovalID) ||
			!validWorkloadClaim(request.GrantID) || !validSHA256Reference(request.GrantHash) || !validLowerHex(request.Nonce, 32) {
			api.WriteBadRequest(w, "Invalid GeneratedSpec approval grant tuple")
			return
		}
		var record generatedspecapprovalceremony.Record
		var err error
		if recoverOnly {
			record, err = runtime.service.RecoverGrantConsumption(r.Context(), request.ApprovalID, request.GrantID, request.GrantHash, request.Nonce)
		} else {
			record, err = runtime.service.ConsumeGrant(r.Context(), request.ApprovalID, request.GrantID, request.GrantHash, request.Nonce)
		}
		writeGeneratedSpecApprovalResult(w, record, err)
	}
}

func requireGeneratedSpecApprovalPOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		api.WriteMethodNotAllowed(w)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		api.WriteError(w, http.StatusUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json")
		return false
	}
	return true
}

func decodeGeneratedSpecApprovalRequest(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, generatedSpecApprovalMaxBody)
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

func writeGeneratedSpecApprovalResult(w http.ResponseWriter, record generatedspecapprovalceremony.Record, err error) {
	if err != nil {
		writeGeneratedSpecApprovalError(w, err)
		return
	}
	response := generatedSpecApprovalRecordResponse{
		State: record.State, ApprovalID: record.ApprovalID, TenantID: record.TenantID, WorkspaceID: record.WorkspaceID,
		Challenge: record.Challenge, Grant: record.SignedGrant, Consumption: record.SignedConsumption,
		HoldStartedAt: record.HoldStartedAt, ExpiresAt: record.ExpiresAt, ConsumedAt: record.ConsumedAt,
		ConsumedBy: record.ConsumedBy, Version: record.Version,
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Helm-Contract-Status", generatedSpecApprovalContractStatus)
	_ = json.NewEncoder(w).Encode(response)
}

func writeGeneratedSpecApprovalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, generatedspecapprovalceremony.ErrInvalidRecord):
		api.WriteBadRequest(w, "Invalid GeneratedSpec approval request")
	case errors.Is(err, generatedspecapprovalceremony.ErrNotFound):
		api.WriteError(w, http.StatusNotFound, "GeneratedSpec approval not found", "no matching ceremony exists in this workload scope")
	case errors.Is(err, generatedspecapprovalceremony.ErrHoldPending), errors.Is(err, generatedspecapprovalceremony.ErrTransitionConflict):
		api.WriteConflict(w, "GeneratedSpec approval conflicts with current ceremony state")
	case errors.Is(err, generatedspecapprovalceremony.ErrExpired):
		api.WriteError(w, http.StatusGone, "GeneratedSpec approval expired", "the challenge or grant is no longer active")
	case errors.Is(err, approvalverify.ErrVerificationFailed), errors.Is(err, generatedspecapproval.ErrVerificationFailed):
		api.WriteBadRequest(w, "GeneratedSpec approval verification failed")
	case errors.Is(err, approvalverify.ErrDuplicateSigner), errors.Is(err, approvalverify.ErrQuorumNotMet),
		errors.Is(err, generatedspecapproval.ErrDuplicateSigner), errors.Is(err, generatedspecapproval.ErrQuorumNotMet):
		api.WriteConflict(w, "GeneratedSpec approval quorum is not satisfied")
	case errors.Is(err, generatedspecapprovalceremony.ErrControlUnavailable), errors.Is(err, generatedspecapprovalceremony.ErrConsumerUnavailable),
		errors.Is(err, approvalverify.ErrAuthorityRejected), errors.Is(err, generatedspecapproval.ErrAuthorityRejected),
		errors.Is(err, approvalverify.ErrSignatureRejected), errors.Is(err, generatedspecapproval.ErrAssertionRejected),
		errors.Is(err, generatedspecapproval.ErrSignatureRejected):
		api.WriteForbidden(w, "GeneratedSpec approval authority rejected the request")
	case errors.Is(err, generatedspecapprovalceremony.ErrEmergencyStopFenced):
		w.Header().Set(approvalConsumptionReasonHeader, approvalConsumptionFencedReason)
		api.WriteConflict(w, "GeneratedSpec approval is emergency-stop fenced")
	default:
		api.WriteError(w, http.StatusServiceUnavailable, "GeneratedSpec approval unavailable", "durable approval authority rejected the operation")
	}
}

var _ generatedspecapprovalceremony.ControlIdentityProvider = generatedSpecApprovalContextIdentityProvider{}
var _ generatedspecapprovalceremony.ConsumerIdentityProvider = generatedSpecApprovalContextIdentityProvider{}
