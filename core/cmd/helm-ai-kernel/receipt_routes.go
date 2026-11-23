package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/agentruntime"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

type organizationRuntimeEvaluationContextKey struct{}

func bindOrganizationRuntimeEvaluation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), organizationRuntimeEvaluationContextKey{}, true)
		next(w, r.WithContext(ctx))
	}
}

func isOrganizationRuntimeEvaluation(ctx context.Context) bool {
	value, _ := ctx.Value(organizationRuntimeEvaluationContextKey{}).(bool)
	return value
}

func registerReceiptRoutes(mux routeMux, svc *Services) {
	evaluateHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.Guardian == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Guardian unavailable", "guardian not initialized")
			return
		}
		// V0.8 retains the public direct-daemon action/resource envelope while
		// generated SDKs use the canonical V5 tool/effect_level/session_id
		// fields. Authentication remains authoritative for principal and tenant.
		var req api.EvaluateRequest
		r.Body = http.MaxBytesReader(w, r.Body, evaluateRequestMaxBodyBytes)
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			writeEvaluateDecodeError(w, err)
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			writeEvaluateDecodeError(w, err)
			return
		}
		principal, err := helmauth.GetPrincipal(r.Context())
		if err != nil || principal == nil {
			api.WriteForbidden(w, "Evaluate route requires authenticated tenant principal context")
			return
		}
		principalID := strings.TrimSpace(principal.GetID())
		tenantID := strings.TrimSpace(principal.GetTenantID())
		if principalID == "" || tenantID == "" {
			api.WriteForbidden(w, "Evaluate route requires authenticated tenant and principal identifiers")
			return
		}
		workspaceID, err := bindRuntimeScope(r, svc, tenantID, workspaceMustBeAsserted)
		if err != nil {
			api.WriteForbidden(w, "Evaluate route "+err.Error())
			return
		}
		organizationRuntime := isOrganizationRuntimeEvaluation(r.Context())
		executionProfile := strings.TrimSpace(r.Header.Get(companyActivationExecutionProfileHeader))
		if (organizationRuntime && executionProfile != companyActivationOrganizationRuntimeProfile) ||
			(!organizationRuntime && executionProfile != "") {
			api.WriteBadRequest(w, "Evaluate route execution profile does not match the selected route")
			return
		}
		var normalizeErr error
		if organizationRuntime {
			normalizeErr = api.NormalizeOrganizationRuntimeEvaluateRequest(&req)
		} else {
			normalizeErr = api.NormalizeEvaluateRequest(&req)
		}
		if normalizeErr != nil {
			api.WriteBadRequest(w, "Evaluate route "+normalizeErr.Error())
			return
		}
		resource := req.EffectLevel
		if organizationRuntime {
			resource = req.Resource
		}
		if isMemoryEvaluateAction(req.Tool) {
			if workspaceID == "" {
				api.WriteForbidden(w, "Evaluate route memory actions require an explicit authenticated workspace binding")
				return
			}
			if err := validateMemoryEvaluateContext(req.Context); err != nil {
				api.WriteBadRequest(w, "Evaluate route "+err.Error())
				return
			}
			if err := validateMemoryEvaluateArgs(req.Args, req.Tool); err != nil {
				api.WriteBadRequest(w, "Evaluate route "+err.Error())
				return
			}
		}
		if err := validateEvaluateAuthorityArgs(req.Args, evaluateAuthorityBinding{
			TenantID: tenantID, PrincipalID: principalID, WorkspaceID: workspaceID,
			SessionID: req.SessionID, Tool: req.Tool, EffectLevel: req.EffectLevel,
		}); err != nil {
			api.WriteBadRequest(w, "Evaluate route "+err.Error())
			return
		}
		if req.Context == nil {
			req.Context = make(map[string]interface{})
		}
		effectClass, effectClassSource, effectClassDeclared := resolveEffectClass(req.Tool, resource, req.EffectLevel)
		if err := bindAuthenticatedGuardianContext(r.Context(), req.Context, guardianTransportBinding{
			EffectClass:         effectClass,
			EffectClassSource:   effectClassSource,
			EffectClassDeclared: effectClassDeclared,
			SessionID:           req.SessionID,
			SourceChannel:       contracts.SourceChannelAPIRequest,
			TrustLevel:          contracts.InputTrustExternalUntrusted,
		}); err != nil {
			api.WriteInternalR(w, r, fmt.Errorf("bind evaluate transport evidence: %w", err))
			return
		}
		// Authentication is the only authority for identity and scope. Remove
		// every authority-bearing spelling recognized by this boundary or
		// Guardian before publishing canonical authenticated values to policy.
		for _, key := range []string{
			"principal", "principal_id", "agent_id",
			"tenant", "tenantId", "tenant_id",
			"workspace", "workspaceId", "workspace_id",
		} {
			delete(req.Context, key)
		}
		req.AgentID = principalID
		req.Context["principal_id"] = principalID
		req.Context["tenant_id"] = tenantID
		// The external session ID remains a signed field. Durable storage may
		// derive a private tenant-qualified ordering key from this authenticated
		// context, but that key is not part of the public API contract.
		if req.Args != nil {
			req.Context["args"] = req.Args
		}
		if workspaceID != "" {
			req.Context["workspace_id"] = workspaceID
		}
		originator, err := bindOrganizationRuntimeOriginator(&req, organizationRuntime, principalID)
		if err != nil {
			api.WriteBadRequest(w, "Evaluate route "+err.Error())
			return
		}
		args, err := json.Marshal(req.Args)
		if err != nil {
			api.WriteBadRequest(w, "Invalid evaluate args")
			return
		}
		argsHash, err := agentruntime.ComputeArgsHash(args)
		if err != nil {
			api.WriteBadRequest(w, "Invalid evaluate args")
			return
		}
		var decision *contracts.DecisionRecord
		var activationEvidence *organizationRuntimeActivationEvidence
		evaluationTime := time.Now().UTC()
		if reasonCode, reason, evidence := organizationRuntimeActivationDenial(svc, &req, organizationRuntime, tenantID, workspaceID, evaluationTime); reasonCode != "" {
			activationEvidence = evidence
			decision, err = signedActivationDenyDecision(svc, &req, principalID, reasonCode, reason, evaluationTime)
			if err != nil {
				api.WriteInternalR(w, r, err)
				return
			}
		} else {
			decision, err = svc.Guardian.EvaluateDecision(r.Context(), guardian.DecisionRequest{
				Principal: principalID,
				Action:    req.Tool,
				Resource:  resource,
				Context:   req.Context,
			})
			if err != nil {
				api.WriteInternalR(w, r, err)
				return
			}
			activationEvidence = evidence
		}
		metadata := map[string]any{
			"source":    "api.evaluate",
			"action":    req.Tool,
			"resource":  resource,
			"reason":    decision.Reason,
			"args_hash": argsHash,
		}
		if organizationRuntime {
			if originator == nil || activationEvidence == nil {
				api.WriteInternalR(w, r, fmt.Errorf("organization runtime receipt provenance is unavailable"))
				return
			}
			err = persistOrganizationRuntimeDecisionReceiptForTenant(r.Context(), svc, decision, principalID, tenantID, args, metadata, organizationRuntimeReceiptProvenance{
				Originator:  *originator,
				Activation:  *activationEvidence,
				TenantID:    tenantID,
				WorkspaceID: workspaceID,
				Reason:      decision.Reason,
			})
		} else {
			err = persistDecisionReceiptForTenant(r.Context(), svc, decision, principalID, tenantID, args, metadata)
		}
		if err != nil {
			api.WriteInternalR(w, r, err)
			return
		}
		receiptID := executor.ReceiptIDForDecision(tenantID, decision.ID)
		receipt, err := receiptForTenant(r.Context(), svc, tenantID, receiptID)
		if err != nil {
			api.WriteInternalR(w, r, fmt.Errorf("load persisted receipt %s: %w", receiptID, err))
			return
		}
		if receipt == nil {
			api.WriteInternalR(w, r, fmt.Errorf("persisted receipt %s is unavailable", receiptID))
			return
		}
		if organizationRuntime {
			if err := contracts.VerifyOrganizationRuntimeReceiptAttestation(receipt, svc.ReceiptSigner.PublicKeyBytes()); err != nil {
				api.WriteInternalR(w, r, fmt.Errorf("verify organization runtime receipt %s: %w", receiptID, err))
				return
			}
		}
		policyRef := decision.PolicyVersion
		if policyRef == "" {
			policyRef = decision.PolicyContentHash
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.EvaluateResponse{
			Allow:                                  contracts.Verdict(decision.Verdict) == contracts.VerdictAllow,
			Verdict:                                decision.Verdict,
			ReceiptID:                              receipt.ReceiptID,
			DecisionID:                             decision.ID,
			DecisionHash:                           receipt.DecisionHash,
			ReasonCode:                             decision.ReasonCode,
			PolicyRef:                              policyRef,
			LamportClock:                           receipt.LamportClock,
			OrganizationRuntimeDecisionAttestation: receipt.OrganizationRuntimeDecisionAttestation,
			ID:                                     decision.ID,
			Action:                                 req.Tool,
			Resource:                               resource,
			Reason:                                 decision.Reason,
			PolicyVersion:                          decision.PolicyVersion,
			PolicyDecisionHash:                     decision.PolicyDecisionHash,
			Signature:                              decision.Signature,
		})
	}
	mux.HandleFunc("/api/v1/evaluate", protectControlPlaneTokenOr(svc, RouteAuthTenant, "/api/v1/evaluate", cpScopeEvaluate, evaluateHandler))
	mux.HandleFunc(companyActivationOrganizationRuntimePath, protectControlPlaneTokenOr(svc, RouteAuthOrganizationRuntime, companyActivationOrganizationRuntimePath, cpScopeOrganizationRuntime, bindOrganizationRuntimeEvaluation(evaluateHandler)))

	mux.HandleFunc("/api/v1/receipts/tail", protectControlPlaneTokenOr(svc, RouteAuthTenant, "/api/v1/receipts/tail", cpScopeReceiptsRead, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.ReceiptStore == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt store unavailable", "receipt store not initialized")
			return
		}
		tenantID, err := authenticatedReceiptTenantScope(r, svc)
		if err != nil {
			api.WriteForbidden(w, "Receipt route requires authenticated tenant and workspace context")
			return
		}
		sessionID, err := requestedReceiptSessionID(r)
		if err != nil {
			api.WriteBadRequest(w, "Invalid session_id")
			return
		}
		rawCursor := r.URL.Query().Get("since")
		if strings.TrimSpace(rawCursor) == "" {
			rawCursor = r.Header.Get("Last-Event-ID")
		}
		cursor, err := parseReceiptCursor(rawCursor, sessionID)
		if err != nil {
			api.WriteBadRequest(w, "Invalid since cursor")
			return
		}
		limit := parseLimit(r.URL.Query().Get("limit"), 100, 1000)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			api.WriteError(w, http.StatusInternalServerError, "Streaming unsupported", "response writer cannot flush")
			return
		}

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			receipts, err := listReceiptsForCursor(r.Context(), svc, tenantID, sessionID, cursor, store.ReceiptQueryFilter{}, limit)
			if err != nil {
				fmt.Fprintf(w, "event: error\ndata: %q\n\n", err.Error())
				flusher.Flush()
			} else {
				for _, receipt := range receipts {
					nextCursor, cursorErr := receiptCursorForReceipt(sessionID, receipt)
					if cursorErr != nil {
						fmt.Fprintf(w, "event: error\ndata: %q\n\n", cursorErr.Error())
						flusher.Flush()
						break
					}
					eventID, cursorErr := formatReceiptCursor(sessionID, nextCursor)
					if cursorErr != nil {
						fmt.Fprintf(w, "event: error\ndata: %q\n\n", cursorErr.Error())
						flusher.Flush()
						break
					}
					cursor = nextCursor
					data, _ := json.Marshal(receipt)
					fmt.Fprintf(w, "id: %s\nevent: receipt\ndata: %s\n\n", eventID, data)
					flusher.Flush()
				}
			}

			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	}))

	mux.HandleFunc("/api/v1/receipts", protectControlPlaneTokenOr(svc, RouteAuthTenant, "/api/v1/receipts", cpScopeReceiptsRead, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.ReceiptStore == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt store unavailable", "receipt store not initialized")
			return
		}
		tenantID, err := authenticatedReceiptTenantScope(r, svc)
		if err != nil {
			api.WriteForbidden(w, "Receipt route requires authenticated tenant and workspace context")
			return
		}
		limit := parseLimit(r.URL.Query().Get("limit"), 100, 1000)
		sessionID, err := requestedReceiptSessionID(r)
		if err != nil {
			api.WriteBadRequest(w, "Invalid session_id")
			return
		}
		cursor, err := parseReceiptCursor(r.URL.Query().Get("since"), sessionID)
		if err != nil {
			api.WriteBadRequest(w, "Invalid since cursor")
			return
		}
		filter, err := parseReceiptQueryFilter(r)
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		receipts, err := listReceiptsForCursor(r.Context(), svc, tenantID, sessionID, cursor, filter, limit+1)
		if err != nil {
			api.WriteInternalR(w, r, err)
			return
		}
		hasMore := len(receipts) > limit
		if hasMore {
			receipts = receipts[:limit]
		}
		nextCursor, err := nextReceiptCursor(sessionID, receipts)
		if err != nil {
			api.WriteInternalR(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receipts":    receipts,
			"count":       len(receipts),
			"next_cursor": nextCursor,
			"has_more":    hasMore,
		})
	}))

	mux.HandleFunc("/api/v1/receipts/", protectControlPlaneTokenOr(svc, RouteAuthTenant, "/api/v1/receipts/", cpScopeReceiptsRead, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc.ReceiptStore == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt store unavailable", "receipt store not initialized")
			return
		}
		tenantID, err := authenticatedReceiptTenantScope(r, svc)
		if err != nil {
			api.WriteForbidden(w, "Receipt route requires authenticated tenant and workspace context")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/receipts/")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid receipt id")
			return
		}
		receipt, err := receiptForTenant(r.Context(), svc, tenantID, id)
		if err != nil {
			api.WriteError(w, http.StatusNotFound, "Receipt not found", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	}))
}

func writeEvaluateDecodeError(w http.ResponseWriter, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		api.WriteError(w, http.StatusRequestEntityTooLarge, "Request Too Large", fmt.Sprintf("request body exceeds %d MiB", evaluateRequestMaxBodyBytes>>20))
		return
	}
	api.WriteBadRequest(w, "Invalid JSON body")
}
