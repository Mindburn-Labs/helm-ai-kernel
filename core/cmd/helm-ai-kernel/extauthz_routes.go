package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/extauthz"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	kernelotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
)

const extauthzAuthorizePath = "/api/v1/extauthz/authorize"
const extauthzPolicyBindingMismatchReason = "EXTAUTHZ_POLICY_BINDING_MISMATCH"

func registerExtAuthzRoutes(mux *http.ServeMux, svc *Services) {
	mux.HandleFunc(extauthzAuthorizePath, protectRuntimeHandler(RouteAuthService, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc == nil || svc.Guardian == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Guardian unavailable", "guardian not initialized")
			return
		}
		if svc.ReceiptSigner == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Kernel signer unavailable", "receipt signer not initialized")
			return
		}

		var req extauthz.AuthorizationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid JSON body")
			return
		}

		ctx := kernelotel.ExtractTraceparent(r.Context(), r.Header)
		resp, err := authorizeExtAuthzRequest(ctx, svc, req, time.Now().UTC())
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Helm-Contract-Status", string(RouteContractInternal))
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func authorizeExtAuthzRequest(ctx context.Context, svc *Services, req extauthz.AuthorizationRequest, now time.Time) (extauthz.AuthorizationResponse, error) {
	decision, err := svc.Guardian.EvaluateDecision(ctx, guardian.DecisionRequest{
		Principal: req.PrincipalID,
		Action:    req.ActionURN,
		Resource:  req.ToolURN,
		Context: map[string]interface{}{
			"request_id":               req.RequestID,
			"tenant_id":                req.TenantID,
			"workspace_id":             req.WorkspaceID,
			"connector_id":             req.ConnectorID,
			"connector_contract_hash":  req.ConnectorContractHash,
			"executor_kind":            req.ExecutorKind,
			"effect_class":             req.EffectClass,
			"risk_class":               req.RiskClass,
			"args_c14n_hash":           req.ArgsC14NHash,
			"request_body_hash":        req.RequestBodyHash,
			"plan_hash":                req.PlanHash,
			"policy_hash":              req.PolicyHash,
			"p0_hash":                  req.P0Hash,
			"policy_epoch":             req.PolicyEpoch,
			"payload_class":            req.PayloadClass,
			"redaction_profile":        req.RedactionProfile,
			"risk_context_hash":        req.RiskContextHash,
			"extauthz_contract_status": "internal_non_production",
		},
	})
	if err != nil {
		decision = &contracts.DecisionRecord{
			ID:            "dec-" + randomHex(16),
			Timestamp:     now,
			Verdict:       string(contracts.VerdictDeny),
			ReasonCode:    "KERNEL_EVALUATION_ERROR",
			Reason:        err.Error(),
			PolicyVersion: req.PolicyHash,
			PolicyEpoch:   req.PolicyEpoch,
		}
	}
	if reason, mismatch := extAuthzPolicyBindingMismatch(req, decision); mismatch {
		decision = &contracts.DecisionRecord{
			ID:            "dec-" + randomHex(16),
			Timestamp:     now,
			Verdict:       string(contracts.VerdictDeny),
			ReasonCode:    extauthzPolicyBindingMismatchReason,
			Reason:        reason,
			PolicyVersion: req.PolicyHash,
			PolicyEpoch:   req.PolicyEpoch,
		}
	}

	resp := baseExtAuthzResponse(req, decision, now)
	if resp.Verdict == extauthz.VerdictAllow {
		resp.EffectPermitRef = "effect-permit:" + randomHex(16)
		resp.PermitNonce = "permit-nonce:" + randomHex(16)
		resp.PermitExpiry = now.Add(30 * time.Second).Format(time.RFC3339Nano)
		resp.ProofSessionRef = "proof-session:" + req.RequestID
		resp.EvidenceReservationRef = "evidence-reservation:" + req.RequestID
		resp.BudgetReservationRef = "budget-reservation:" + req.RequestID
		resp.ProofObligation = "connector_receipt+evidence_pack+proofgraph_edge"
		resp.ConnectorReceiptPolicy = "required"
		resp.ProofFinalizationPolicy = "required_before_terminal_success"
	}
	if resp.Verdict == extauthz.VerdictDeny {
		resp.DenialReceiptRef = "denial:" + resp.KernelVerdictRef
	}
	if resp.Verdict == extauthz.VerdictEscalate {
		resp.EscalationRef = "escalation:" + resp.KernelVerdictRef
		resp.EscalationReceiptRef = "escalation-receipt:" + resp.KernelVerdictRef
	}
	return signExtAuthzResponse(resp, svc)
}

func extAuthzPolicyBindingMismatch(req extauthz.AuthorizationRequest, decision *contracts.DecisionRecord) (string, bool) {
	if decision == nil {
		return "", false
	}
	if decision.PolicyContentHash != "" && decision.PolicyContentHash != req.PolicyHash {
		return fmt.Sprintf("policy hash mismatch: request=%s evaluated=%s", req.PolicyHash, decision.PolicyContentHash), true
	}
	if decision.PolicyEpoch != "" && decision.PolicyEpoch != req.PolicyEpoch {
		return fmt.Sprintf("policy epoch mismatch: request=%s evaluated=%s", req.PolicyEpoch, decision.PolicyEpoch), true
	}
	return "", false
}

func baseExtAuthzResponse(req extauthz.AuthorizationRequest, decision *contracts.DecisionRecord, now time.Time) extauthz.AuthorizationResponse {
	verdict := normalizeExtAuthzVerdict(decision.Verdict)
	reason := decision.ReasonCode
	if reason == "" {
		if verdict == extauthz.VerdictAllow {
			reason = "ALLOW_POLICY_MATCH"
		} else if decision.Reason != "" {
			reason = strings.ToUpper(strings.ReplaceAll(decision.Reason, " ", "_"))
		} else {
			reason = "POLICY_DENY"
		}
	}
	decisionID := decision.ID
	if decisionID == "" {
		decisionID = "dec-" + randomHex(16)
	}

	return extauthz.AuthorizationResponse{
		SchemaVersion:           req.SchemaVersion,
		ContractVersion:         req.ContractVersion,
		RequestID:               req.RequestID,
		TenantID:                req.TenantID,
		WorkspaceID:             req.WorkspaceID,
		PrincipalID:             req.PrincipalID,
		PrincipalSeq:            req.PrincipalSeq,
		AgentIdentityProfileRef: req.AgentIdentityProfileRef,
		Protocol:                req.Protocol,
		ActionURN:               req.ActionURN,
		ToolURN:                 req.ToolURN,
		ConnectorID:             req.ConnectorID,
		ConnectorContractHash:   req.ConnectorContractHash,
		ExecutorKind:            req.ExecutorKind,
		EffectClass:             req.EffectClass,
		RiskClass:               req.RiskClass,
		ArgsC14NHash:            req.ArgsC14NHash,
		RequestBodyHash:         req.RequestBodyHash,
		PlanHash:                req.PlanHash,
		PolicyHash:              req.PolicyHash,
		P0Hash:                  req.P0Hash,
		PolicyEpoch:             req.PolicyEpoch,
		IdempotencyKeyCandidate: req.IdempotencyKeyCandidate,
		PayloadClass:            req.PayloadClass,
		RedactionProfile:        req.RedactionProfile,
		UpstreamTraceID:         req.UpstreamTraceID,
		UpstreamRunID:           req.UpstreamRunID,
		DeadlineMS:              req.DeadlineMS,
		RiskContextHash:         req.RiskContextHash,
		Verdict:                 verdict,
		ReasonCode:              reason,
		KernelTrustRootID:       extauthzTrustRootID(),
		SigningKeyRef:           extauthzSigningKeyRefFromEnv(),
		KernelVerdictRef:        "kernel-verdict:" + decisionID,
		KernelVerdictIssuedAt:   now.Format(time.RFC3339Nano),
		KernelVerdictExpiresAt:  now.Add(45 * time.Second).Format(time.RFC3339Nano),
		CachePolicy:             extauthz.CachePolicyNoStore,
		ReplayHint:              extauthz.ReplayHintSingleUse,
	}
}

func signExtAuthzResponse(resp extauthz.AuthorizationResponse, svc *Services) (extauthz.AuthorizationResponse, error) {
	if resp.SigningKeyRef == "" {
		resp.SigningKeyRef = svc.ReceiptSigner.PublicKey()
	}
	payload, err := extauthz.CanonicalResponsePayload(resp)
	if err != nil {
		return resp, err
	}
	sum := sha256.Sum256(payload)
	resp.KernelVerdictHash = hex.EncodeToString(sum[:])
	resp.KernelVerdictSignature, err = svc.ReceiptSigner.Sign(payload)
	if err != nil {
		return resp, fmt.Errorf("sign extauthz response: %w", err)
	}
	return resp, nil
}

func normalizeExtAuthzVerdict(verdict string) string {
	switch strings.ToUpper(strings.TrimSpace(verdict)) {
	case extauthz.VerdictAllow:
		return extauthz.VerdictAllow
	case extauthz.VerdictEscalate:
		return extauthz.VerdictEscalate
	default:
		return extauthz.VerdictDeny
	}
}

func extauthzTrustRootID() string {
	if v := strings.TrimSpace(os.Getenv("HELM_EXTAUTHZ_TRUST_ROOT_ID")); v != "" {
		return v
	}
	return "kernel-local-dev"
}

func extauthzSigningKeyRefFromEnv() string {
	return strings.TrimSpace(os.Getenv("HELM_EXTAUTHZ_SIGNING_KEY_REF"))
}

func randomHex(size int) string {
	if size <= 0 {
		size = 16
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(sum[:size])
	}
	return hex.EncodeToString(buf)
}
