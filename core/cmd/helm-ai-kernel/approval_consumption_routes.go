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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

const (
	approvalGrantConsumePath            = "/internal/v1/approval-grants/consume"
	approvalGrantConsumptionRecoverPath = "/internal/v1/approval-grants/recover"
	approvalGrantConsumptionMaxBody     = 32 << 10
	approvalConsumptionReasonHeader     = "X-Helm-Reason-Code"
	approvalConsumptionFencedReason     = "EMERGENCY_STOP_FENCED"
	approvalConsumptionUnverifiedReason = "EMERGENCY_STOP_UNVERIFIED"
)

var errApprovalConsumptionStopUnverified = errors.New("approval consumption emergency-stop status is unverified")

type approvalGrantConsumer interface {
	ConsumeGrant(context.Context, string, string, string, string) (approvalceremony.Record, error)
	RecoverGrantConsumption(context.Context, string, string, string, string) (approvalceremony.Record, error)
}

type approvalConsumerTokenValidator interface {
	ValidateAuthorization(string) (*mcppkg.OAuthTokenClaims, error)
}

type approvalConsumptionRuntime struct {
	consumer    approvalGrantConsumer
	validator   approvalConsumerTokenValidator
	stops       kernel.ScopedStopReader
	audience    string
	maxTokenTTL time.Duration
}

type approvalGrantConsumptionRequest struct {
	ApprovalID string `json:"approval_id"`
	GrantID    string `json:"grant_id"`
	GrantHash  string `json:"grant_hash"`
	Nonce      string `json:"nonce"`
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

func registerApprovalGrantConsumptionRoutes(mux *http.ServeMux, runtime *approvalConsumptionRuntime) {
	if mux == nil || runtime == nil {
		return
	}
	mux.HandleFunc(approvalGrantConsumePath, runtime.protect(runtime.handle(false)))
	mux.HandleFunc(approvalGrantConsumptionRecoverPath, runtime.protect(runtime.handle(true)))
}

func (runtime *approvalConsumptionRuntime) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if runtime == nil || runtime.consumer == nil || runtime.validator == nil || runtime.stops == nil ||
			!validWorkloadClaim(runtime.audience) || runtime.maxTokenTTL <= 0 {
			api.WriteError(w, http.StatusServiceUnavailable, "Approval grant consumer unavailable", "workload authentication is not configured")
			return
		}
		token, detail, ok := helmauth.BearerToken(r)
		if !ok {
			writeApprovalConsumerUnauthorized(w, detail)
			return
		}
		claims, err := runtime.validator.ValidateAuthorization(token)
		if err != nil {
			var validationErr *mcppkg.JWKSValidationError
			if errors.As(err, &validationErr) && validationErr.Kind == mcppkg.JWKSErrMissingScope {
				w.Header().Set("WWW-Authenticate", `Bearer realm="helm-approval-consumer", error="insufficient_scope"`)
				api.WriteForbidden(w, "Workload token is missing the approval consumption scope")
				return
			}
			writeApprovalConsumerUnauthorized(w, "Invalid or expired workload token")
			return
		}
		if claims == nil || !validWorkloadClaim(claims.RegisteredClaims.Subject) ||
			!validWorkloadClaim(claims.TenantID) || !validWorkloadClaim(claims.WorkspaceID) {
			writeApprovalConsumerUnauthorized(w, "Workload token subject, tenant, and workspace are required")
			return
		}
		issuedAt := claims.RegisteredClaims.IssuedAt
		expiresAt := claims.RegisteredClaims.ExpiresAt
		if issuedAt == nil || expiresAt == nil || !expiresAt.After(issuedAt.Time) ||
			expiresAt.Sub(issuedAt.Time) > runtime.maxTokenTTL {
			writeApprovalConsumerUnauthorized(w, "Workload token lifetime is invalid")
			return
		}
		identity := approvalceremony.ConsumerIdentity{
			Subject: claims.RegisteredClaims.Subject, TenantID: claims.TenantID,
			WorkspaceID: claims.WorkspaceID, Audience: runtime.audience,
		}
		ctx := approvalceremony.WithConsumerIdentity(r.Context(), identity)
		ctx = helmauth.WithPrincipal(ctx, &helmauth.BasePrincipal{
			ID: identity.Subject, TenantID: identity.TenantID, Roles: []string{"approval-consumer"},
		})
		next(w, r.WithContext(ctx))
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
	w.Header().Set("WWW-Authenticate", `Bearer realm="helm-approval-consumer"`)
	api.WriteUnauthorized(w, detail)
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
