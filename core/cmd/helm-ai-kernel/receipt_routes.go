package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/agentruntime"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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

func registerReceiptRoutes(mux *http.ServeMux, svc *Services) {
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
		workspaceID := strings.TrimSpace(r.Header.Get(workspaceHeader))
		if svc.EmergencyStops != nil {
			configuredTenantID := strings.TrimSpace(os.Getenv(runtimeTenantIDEnv))
			if configuredTenantID == "" || tenantID != configuredTenantID {
				api.WriteForbidden(w, "Evaluate route tenant binding could not be verified")
				return
			}
			if workspaceID == "" {
				api.WriteForbidden(w, "Evaluate route requires an explicit authenticated workspace binding")
				return
			}
			if configuredWorkspaceID := configuredRuntimeWorkspaceID(); configuredWorkspaceID == "" || workspaceID != configuredWorkspaceID {
				api.WriteForbidden(w, "Evaluate route workspace binding could not be verified")
				return
			}
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
		if err := bindAuthenticatedGuardianContext(r.Context(), req.Context, guardianTransportBinding{
			EffectClass:   req.EffectLevel,
			SessionID:     req.SessionID,
			SourceChannel: contracts.SourceChannelAPIRequest,
			TrustLevel:    contracts.InputTrustExternalUntrusted,
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
	mux.HandleFunc("/api/v1/evaluate", protectRuntimeHandler(RouteAuthTenant, evaluateHandler))
	mux.HandleFunc(companyActivationOrganizationRuntimePath, protectRuntimeHandler(RouteAuthOrganizationRuntime, bindOrganizationRuntimeEvaluation(evaluateHandler)))

	mux.HandleFunc("/api/v1/receipts/tail", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/api/v1/receipts", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/api/v1/receipts/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
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

const (
	evaluateAuthorityArgsKey             = "__helm_evaluate_authority_v1"
	evaluateAuthorityExecutionProfileKey = "execution_profile"
	evaluateRequestMaxBodyBytes          = 1 << 20
	evaluateAuthorityMaxDepth            = 64
	evaluateAuthorityMaxNodes            = 4096
)

type evaluateAuthorityBinding struct {
	TenantID    string
	PrincipalID string
	WorkspaceID string
	SessionID   string
	Tool        string
	EffectLevel string
}

// validateEvaluateAuthorityArgs keeps the CP's reserved authority envelope
// bound to the authenticated route identity. Ordinary direct-daemon requests
// remain valid without the envelope; when present, it must be the exact
// six-field memory binding. The additive organization-runtime execution
// profile is accepted only for non-memory bindings, and may not be shadowed
// inside source args.
func validateEvaluateAuthorityArgs(args map[string]any, expected evaluateAuthorityBinding) error {
	state := evaluateAuthorityWalkState{}
	return walkEvaluateAuthorityArgs(args, true, expected, &state)
}

type evaluateAuthorityWalkState struct {
	depth int
	nodes int
}

func (s *evaluateAuthorityWalkState) enter(composite bool) error {
	s.nodes++
	if s.nodes > evaluateAuthorityMaxNodes {
		return fmt.Errorf("evaluate args exceed authority validation node limit")
	}
	if composite {
		if s.depth >= evaluateAuthorityMaxDepth {
			return fmt.Errorf("evaluate args exceed authority validation depth limit")
		}
		s.depth++
	}
	return nil
}

func (s *evaluateAuthorityWalkState) leave(composite bool) {
	if composite {
		s.depth--
	}
}

func walkEvaluateAuthorityArgs(value any, topLevel bool, expected evaluateAuthorityBinding, state *evaluateAuthorityWalkState) error {
	composite := false
	switch value.(type) {
	case map[string]any, []any:
		composite = true
	}
	if err := state.enter(composite); err != nil {
		return err
	}
	if composite {
		defer state.leave(true)
	}

	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if key == evaluateAuthorityArgsKey {
				if !topLevel {
					return fmt.Errorf("evaluate args reserved authority key may only appear at the top level")
				}
				binding, ok := nested.(map[string]any)
				if !ok {
					return fmt.Errorf("evaluate args reserved authority binding must be an object")
				}
				if err := validateEvaluateAuthorityBinding(binding, expected); err != nil {
					return err
				}
				continue
			}
			if err := walkEvaluateAuthorityArgs(nested, false, expected, state); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range typed {
			if err := walkEvaluateAuthorityArgs(nested, false, expected, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateEvaluateAuthorityBinding(binding map[string]any, expected evaluateAuthorityBinding) error {
	if strings.TrimSpace(expected.WorkspaceID) == "" {
		return fmt.Errorf("evaluate args reserved authority binding requires an authenticated workspace")
	}
	want := map[string]string{
		"tenant_id":    expected.TenantID,
		"workspace_id": expected.WorkspaceID,
		"principal_id": expected.PrincipalID,
		"session_id":   expected.SessionID,
		"tool":         expected.Tool,
		"effect_level": expected.EffectLevel,
	}
	if profile, present := binding[evaluateAuthorityExecutionProfileKey]; present {
		if profile != "organization-runtime" || isMemoryEvaluateAction(expected.Tool) {
			return fmt.Errorf("evaluate args reserved authority binding has an invalid execution profile")
		}
	}
	expectedFields := len(want)
	if _, present := binding[evaluateAuthorityExecutionProfileKey]; present {
		expectedFields++
	}
	if len(binding) != expectedFields {
		return fmt.Errorf("evaluate args reserved authority binding has unexpected fields")
	}
	for key, wantValue := range want {
		got, ok := binding[key].(string)
		if !ok || got != wantValue {
			return fmt.Errorf("evaluate args reserved authority binding does not match authenticated request")
		}
	}
	return nil
}

func writeEvaluateDecodeError(w http.ResponseWriter, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		api.WriteError(w, http.StatusRequestEntityTooLarge, "Request Too Large", fmt.Sprintf("request body exceeds %d MiB", evaluateRequestMaxBodyBytes>>20))
		return
	}
	api.WriteBadRequest(w, "Invalid JSON body")
}

func isMemoryEvaluateAction(tool string) bool {
	return strings.HasPrefix(strings.TrimSpace(tool), "memory.")
}

var memoryEvaluateArgKeys = map[string]struct{}{
	"schema_version":  {},
	"operation":       {},
	"memory_class":    {},
	"scope":           {},
	"target_scope":    {},
	"data_class":      {},
	"data_boundary":   {},
	"purpose":         {},
	"content_hash":    {},
	"query_hash":      {},
	"record_id":       {},
	"entry_id":        {},
	"provenance_hash": {},
	"retention_days":  {},
	"provider_id":     {},
	"model_id":        {},
	"budget":          {},
}

var memoryEvaluateBudgetKeys = map[string]struct{}{
	"decision":     {},
	"receipt_hash": {},
}

const memorySchemaVersion = "memory-policy/v1"

var (
	memoryHashPattern     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	memoryProviderPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	memoryModelPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

	memoryOperationValues = map[string]struct{}{
		"memory.read":    {},
		"memory.write":   {},
		"memory.promote": {},
		"memory.egress":  {},
	}
	memoryClassValues = map[string]struct{}{
		"M0_EPHEMERAL":  {},
		"M1_EPISODIC":   {},
		"M2_ENTITY":     {},
		"M3_SEMANTIC":   {},
		"M4_PROCEDURAL": {},
	}
	memoryScopeValues = map[string]struct{}{
		"PRIVATE":   {},
		"WORKSPACE": {},
		"COMPANY":   {},
	}
	memoryTargetScopeValues = map[string]struct{}{
		"WORKSPACE": {},
		"COMPANY":   {},
	}
	memoryDataClassValues = map[string]struct{}{
		"PUBLIC":       {},
		"INTERNAL":     {},
		"CONFIDENTIAL": {},
		"PII":          {},
		"REGULATED":    {},
	}
	memoryDataBoundaryValues = map[string]struct{}{
		"local_only":   {},
		"org_boundary": {},
		"external":     {},
	}
	memoryBudgetDecisionValues = map[string]struct{}{
		"ALLOW": {},
		"DENY":  {},
	}
)

// validateMemoryEvaluateArgs enforces the source-owned memory policy input
// schema at the HTTP edge. The reserved Control Plane authority envelope is
// an additive wire binding and is validated separately. Keeping this
// validation typed and closed prevents policy text patterns from interpreting
// unknown siblings or nested values as source fields.
func validateMemoryEvaluateArgs(args map[string]any, tool string) error {
	if args == nil {
		return fmt.Errorf("evaluate memory args must be an object")
	}
	if _, ok := args["budget"]; !ok {
		return fmt.Errorf("evaluate memory args field %q is required", "budget")
	}
	for key, value := range args {
		if key == evaluateAuthorityArgsKey {
			continue
		}
		if _, ok := memoryEvaluateArgKeys[key]; !ok {
			return fmt.Errorf("evaluate memory args field %q is not permitted", key)
		}
		if key == "budget" {
			if err := validateMemoryBudget(value); err != nil {
				return err
			}
		} else if isCompositeEvaluateValue(value) {
			return fmt.Errorf("evaluate memory args field %q must be a scalar", key)
		}
	}

	schemaVersion, err := requireMemoryString(args, "schema_version")
	if err != nil {
		return err
	}
	if schemaVersion != memorySchemaVersion {
		return fmt.Errorf("evaluate memory args field %q has an invalid value", "schema_version")
	}
	operation, err := requireMemoryEnum(args, "operation", memoryOperationValues)
	if err != nil {
		return err
	}
	if operation != strings.TrimSpace(tool) {
		return fmt.Errorf("evaluate memory args operation does not match tool")
	}
	if _, err := requireMemoryEnum(args, "memory_class", memoryClassValues); err != nil {
		return err
	}
	if _, err := requireMemoryEnum(args, "scope", memoryScopeValues); err != nil {
		return err
	}
	if _, err := optionalMemoryEnum(args, "target_scope", memoryTargetScopeValues); err != nil {
		return err
	}
	if _, err := requireMemoryEnum(args, "data_class", memoryDataClassValues); err != nil {
		return err
	}
	dataBoundary, err := requireMemoryEnum(args, "data_boundary", memoryDataBoundaryValues)
	if err != nil {
		return err
	}
	if purpose, err := requireMemoryString(args, "purpose"); err != nil {
		return err
	} else if err := validateMemoryStringLength("purpose", purpose, 1, 512); err != nil {
		return err
	}
	if _, err := requireMemoryHash(args, "content_hash"); err != nil {
		return err
	}
	if _, err := optionalMemoryHash(args, "query_hash"); err != nil {
		return err
	}
	if _, err := optionalMemoryBoundedString(args, "record_id", 1, 256); err != nil {
		return err
	}
	if _, err := optionalMemoryBoundedString(args, "entry_id", 1, 256); err != nil {
		return err
	}
	if _, err := optionalMemoryHash(args, "provenance_hash"); err != nil {
		return err
	}
	if _, err := optionalMemoryInteger(args, "retention_days"); err != nil {
		return err
	}
	if _, err := optionalMemoryPattern(args, "provider_id", memoryProviderPattern); err != nil {
		return err
	}
	if _, err := optionalMemoryPattern(args, "model_id", memoryModelPattern); err != nil {
		return err
	}

	switch operation {
	case "memory.read":
		if _, err := requireMemoryHash(args, "query_hash"); err != nil {
			return err
		}
		if dataBoundary != "local_only" && dataBoundary != "org_boundary" {
			return fmt.Errorf("evaluate memory args field %q is incompatible with operation", "data_boundary")
		}
	case "memory.write":
		if _, err := requireMemoryBoundedString(args, "record_id", 1, 256); err != nil {
			return err
		}
		if _, err := requireMemoryHash(args, "provenance_hash"); err != nil {
			return err
		}
		if _, err := requireMemoryInteger(args, "retention_days"); err != nil {
			return err
		}
		if dataBoundary != "local_only" && dataBoundary != "org_boundary" {
			return fmt.Errorf("evaluate memory args field %q is incompatible with operation", "data_boundary")
		}
	case "memory.promote":
		if _, err := requireMemoryBoundedString(args, "entry_id", 1, 256); err != nil {
			return err
		}
		if _, err := requireMemoryHash(args, "provenance_hash"); err != nil {
			return err
		}
		targetScope, err := requireMemoryEnum(args, "target_scope", memoryTargetScopeValues)
		if err != nil {
			return err
		}
		scope, err := requireMemoryEnum(args, "scope", memoryScopeValues)
		if err != nil {
			return err
		}
		if scope != "PRIVATE" || dataBoundary != "org_boundary" || targetScope == "" {
			return fmt.Errorf("evaluate memory args scope and boundary are incompatible with operation")
		}
	case "memory.egress":
		if _, err := requireMemoryPattern(args, "provider_id", memoryProviderPattern); err != nil {
			return err
		}
		if _, err := requireMemoryPattern(args, "model_id", memoryModelPattern); err != nil {
			return err
		}
		if dataBoundary != "external" {
			return fmt.Errorf("evaluate memory args field %q is incompatible with operation", "data_boundary")
		}
	}
	return nil
}

func validateMemoryBudget(value any) error {
	budget, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("evaluate memory args budget must be an object")
	}
	for key, nested := range budget {
		if _, ok := memoryEvaluateBudgetKeys[key]; !ok {
			return fmt.Errorf("evaluate memory args budget field %q is not permitted", key)
		}
		if isCompositeEvaluateValue(nested) {
			return fmt.Errorf("evaluate memory args budget field %q must be a scalar", key)
		}
	}
	decision, err := requireMemoryEnumFromObject(budget, "decision", memoryBudgetDecisionValues)
	if err != nil {
		return err
	}
	if decision == "" {
		return fmt.Errorf("evaluate memory args budget field %q is required", "decision")
	}
	if _, err := requireMemoryHashFromObject(budget, "receipt_hash"); err != nil {
		return err
	}
	return nil
}

func requireMemoryString(args map[string]any, key string) (string, error) {
	value, ok := args[key]
	if !ok {
		return "", fmt.Errorf("evaluate memory args field %q is required", key)
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("evaluate memory args field %q must be a string", key)
	}
	return stringValue, nil
}

func optionalMemoryString(args map[string]any, key string) (string, bool, error) {
	value, ok := args[key]
	if !ok {
		return "", false, nil
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", true, fmt.Errorf("evaluate memory args field %q must be a string", key)
	}
	return stringValue, true, nil
}

func requireMemoryEnum(args map[string]any, key string, allowed map[string]struct{}) (string, error) {
	value, err := requireMemoryString(args, key)
	if err != nil {
		return "", err
	}
	if _, ok := allowed[value]; !ok {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid value", key)
	}
	return value, nil
}

func optionalMemoryEnum(args map[string]any, key string, allowed map[string]struct{}) (string, error) {
	value, present, err := optionalMemoryString(args, key)
	if err != nil || !present {
		return value, err
	}
	if _, ok := allowed[value]; !ok {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid value", key)
	}
	return value, nil
}

func requireMemoryEnumFromObject(object map[string]any, key string, allowed map[string]struct{}) (string, error) {
	value, err := requireMemoryStringFromObject(object, key)
	if err != nil {
		return "", err
	}
	if _, ok := allowed[value]; !ok {
		return "", fmt.Errorf("evaluate memory args budget field %q has an invalid value", key)
	}
	return value, nil
}

func requireMemoryStringFromObject(object map[string]any, key string) (string, error) {
	value, ok := object[key]
	if !ok {
		return "", fmt.Errorf("evaluate memory args budget field %q is required", key)
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("evaluate memory args budget field %q must be a string", key)
	}
	return stringValue, nil
}

func requireMemoryHash(args map[string]any, key string) (string, error) {
	value, err := requireMemoryString(args, key)
	if err != nil {
		return "", err
	}
	if !memoryHashPattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid hash", key)
	}
	return value, nil
}

func optionalMemoryHash(args map[string]any, key string) (string, error) {
	value, present, err := optionalMemoryString(args, key)
	if err != nil || !present {
		return value, err
	}
	if !memoryHashPattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid hash", key)
	}
	return value, nil
}

func requireMemoryHashFromObject(object map[string]any, key string) (string, error) {
	value, err := requireMemoryStringFromObject(object, key)
	if err != nil {
		return "", err
	}
	if !memoryHashPattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args budget field %q has an invalid hash", key)
	}
	return value, nil
}

func validateMemoryStringLength(key, value string, min, max int) error {
	length := utf8.RuneCountInString(value)
	if length < min || length > max {
		return fmt.Errorf("evaluate memory args field %q has an invalid length", key)
	}
	return nil
}

func requireMemoryBoundedString(args map[string]any, key string, min, max int) (string, error) {
	value, err := requireMemoryString(args, key)
	if err != nil {
		return "", err
	}
	if err := validateMemoryStringLength(key, value, min, max); err != nil {
		return "", err
	}
	return value, nil
}

func optionalMemoryBoundedString(args map[string]any, key string, min, max int) (string, error) {
	value, present, err := optionalMemoryString(args, key)
	if err != nil || !present {
		return value, err
	}
	if err := validateMemoryStringLength(key, value, min, max); err != nil {
		return "", err
	}
	return value, nil
}

func requireMemoryPattern(args map[string]any, key string, pattern *regexp.Regexp) (string, error) {
	value, err := requireMemoryString(args, key)
	if err != nil {
		return "", err
	}
	if !pattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid value", key)
	}
	return value, nil
}

func optionalMemoryPattern(args map[string]any, key string, pattern *regexp.Regexp) (string, error) {
	value, present, err := optionalMemoryString(args, key)
	if err != nil || !present {
		return value, err
	}
	if !pattern.MatchString(value) {
		return "", fmt.Errorf("evaluate memory args field %q has an invalid value", key)
	}
	return value, nil
}

func requireMemoryInteger(args map[string]any, key string) (float64, error) {
	value, ok := args[key]
	if !ok {
		return 0, fmt.Errorf("evaluate memory args field %q is required", key)
	}
	return validateMemoryInteger(key, value)
}

func optionalMemoryInteger(args map[string]any, key string) (float64, error) {
	value, ok := args[key]
	if !ok {
		return 0, nil
	}
	return validateMemoryInteger(key, value)
}

func validateMemoryInteger(key string, value any) (float64, error) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < 1 || number > 3650 {
		return 0, fmt.Errorf("evaluate memory args field %q must be an integer from 1 through 3650", key)
	}
	return number, nil
}

func isCompositeEvaluateValue(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}

var evaluateAuthorityContextKeys = map[string]struct{}{
	"principal":    {},
	"principal_id": {},
	"agent_id":     {},
	"tenant":       {},
	"tenantId":     {},
	"tenant_id":    {},
	"workspace":    {},
	"workspaceId":  {},
	"workspace_id": {},
}

// validateMemoryEvaluateContext rejects nested identity aliases that could
// satisfy a policy pattern without being the route's authenticated binding.
// Top-level aliases retain the legacy route behavior: they are stripped and
// replaced below with authenticated values.
func validateMemoryEvaluateContext(context map[string]any) error {
	state := evaluateAuthorityWalkState{}
	return walkMemoryEvaluateContext(context, true, &state)
}

func walkMemoryEvaluateContext(value any, topLevel bool, state *evaluateAuthorityWalkState) error {
	composite := false
	switch value.(type) {
	case map[string]any, []any:
		composite = true
	}
	if err := state.enter(composite); err != nil {
		return err
	}
	if composite {
		defer state.leave(true)
	}

	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if !topLevel {
				if _, authorityKey := evaluateAuthorityContextKeys[key]; authorityKey {
					return fmt.Errorf("evaluate memory context authority keys may only appear at the top level")
				}
			}
			if err := walkMemoryEvaluateContext(nested, false, state); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range typed {
			if err := walkMemoryEvaluateContext(nested, false, state); err != nil {
				return err
			}
		}
	}
	return nil
}

func authenticatedReceiptTenantID(ctx context.Context) (string, error) {
	principal, err := helmauth.GetPrincipal(ctx)
	if err != nil || principal == nil {
		return "", fmt.Errorf("authenticated tenant principal is required")
	}
	tenantID := strings.TrimSpace(principal.GetTenantID())
	if tenantID == "" {
		return "", fmt.Errorf("authenticated tenant id is required")
	}
	return tenantID, nil
}

func authenticatedReceiptTenantScope(r *http.Request, svc *Services) (string, error) {
	tenantID, err := authenticatedReceiptTenantID(r.Context())
	if err != nil {
		return "", err
	}
	if svc.EmergencyStops == nil {
		return tenantID, nil
	}
	workspaceID := strings.TrimSpace(r.Header.Get(workspaceHeader))
	configuredWorkspaceID := configuredRuntimeWorkspaceID()
	if workspaceID == "" || configuredWorkspaceID == "" || workspaceID != configuredWorkspaceID {
		return "", fmt.Errorf("authenticated workspace binding is required")
	}
	return tenantID, nil
}

func requestedReceiptSessionID(r *http.Request) (string, error) {
	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID != "" {
		return api.NormalizePublicSessionID(sessionID)
	}
	// Retain the old query spelling as an alias only. It is interpreted as a
	// signed session ID, never as an executor filter.
	agent := strings.TrimSpace(r.URL.Query().Get("agent"))
	if agent == "" {
		return "", nil
	}
	return api.NormalizePublicSessionID(agent)
}

func tenantScopedReceiptReader(svc *Services) (store.TenantScopedReceiptReader, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptReader)
	if !ok {
		return nil, fmt.Errorf("receipt store lacks tenant-scoped V5 read capability")
	}
	return reader, nil
}

func tenantScopedReceiptFilterReader(svc *Services) (store.TenantScopedReceiptFilterReader, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptFilterReader)
	if !ok {
		return nil, fmt.Errorf("receipt store lacks tenant-scoped predicate-query capability")
	}
	return reader, nil
}

// listReceiptsForCursor selects the tenant-scoped reader path. A non-empty
// filter routes through the predicate-query capability; an empty filter keeps
// the exact prior behaviour (and does not require the filter capability), so
// the SSE tail loop is unaffected.
func listReceiptsForCursor(ctx context.Context, svc *Services, tenantID, sessionID string, cursor store.TenantReceiptCursor, filter store.ReceiptQueryFilter, limit int) ([]*contracts.Receipt, error) {
	if strings.TrimSpace(sessionID) != "" {
		if !filter.IsZero() {
			reader, err := tenantScopedReceiptFilterReader(svc)
			if err != nil {
				return nil, err
			}
			return reader.ListByTenantSessionFiltered(ctx, tenantID, sessionID, cursor.LamportClock, filter, limit)
		}
		reader, err := tenantScopedReceiptReader(svc)
		if err != nil {
			return nil, err
		}
		return reader.ListByTenantSession(ctx, tenantID, sessionID, cursor.LamportClock, limit)
	}
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	if !filter.IsZero() {
		reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptFilterReader)
		if !ok {
			return nil, fmt.Errorf("receipt store lacks tenant-wide predicate-query capability")
		}
		return reader.ListByTenantCursorFiltered(ctx, tenantID, cursor, filter, limit)
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedReceiptCursorReader)
	if !ok {
		return nil, fmt.Errorf("receipt store lacks tenant-wide keyset cursor capability")
	}
	return reader.ListByTenantCursor(ctx, tenantID, cursor, limit)
}

// parseReceiptQueryFilter reads the optional predicate dimensions from the
// query string so a caller can answer "everything denied for reason X in
// period Y" in one request. Time bounds are RFC3339Nano with at most nine
// fractional-second digits (from inclusive, to exclusive). principal/executor
// and effect/resource are accepted as synonyms. Absent params impose no
// constraint on that dimension.
func parseReceiptQueryFilter(r *http.Request) (store.ReceiptQueryFilter, error) {
	q := r.URL.Query()
	executor := strings.TrimSpace(q.Get("principal"))
	if executor == "" {
		executor = strings.TrimSpace(q.Get("executor"))
	}
	effect := strings.TrimSpace(q.Get("effect"))
	if effect == "" {
		effect = strings.TrimSpace(q.Get("resource"))
	}
	filter := store.ReceiptQueryFilter{
		Verdict:    strings.TrimSpace(q.Get("verdict")),
		ReasonCode: strings.TrimSpace(q.Get("reason_code")),
		Executor:   executor,
		Effect:     effect,
	}
	from, err := parseReceiptFilterTime(q.Get("from"))
	if err != nil {
		return store.ReceiptQueryFilter{}, fmt.Errorf("invalid from timestamp: %w", err)
	}
	to, err := parseReceiptFilterTime(q.Get("to"))
	if err != nil {
		return store.ReceiptQueryFilter{}, fmt.Errorf("invalid to timestamp: %w", err)
	}
	filter.From = from
	filter.To = to
	if !filter.From.IsZero() && !filter.To.IsZero() && !filter.To.After(filter.From) {
		return store.ReceiptQueryFilter{}, fmt.Errorf("to must be after from")
	}
	return filter, nil
}

func parseReceiptFilterTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	const formatError = "must be RFC3339Nano with at most 9 fractional digits"
	if strings.ContainsRune(raw, ',') {
		return time.Time{}, fmt.Errorf(formatError)
	}
	if dot := strings.IndexByte(raw, '.'); dot >= 0 {
		fractionalDigits := 0
		for i := dot + 1; i < len(raw) && raw[i] >= '0' && raw[i] <= '9'; i++ {
			fractionalDigits++
		}
		if fractionalDigits > 9 {
			return time.Time{}, fmt.Errorf(formatError)
		}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf(formatError)
	}
	return parsed.UTC(), nil
}

func receiptForTenant(ctx context.Context, svc *Services, tenantID, receiptID string) (*contracts.Receipt, error) {
	reader, err := tenantScopedReceiptReader(svc)
	if err != nil {
		return nil, err
	}
	return reader.GetByReceiptIDForTenant(ctx, tenantID, receiptID)
}

const tenantReceiptCursorVersionPrefix = "v1."

type tenantReceiptCursorWire struct {
	LamportClock uint64 `json:"l"`
	Timestamp    string `json:"t"`
	ReceiptID    string `json:"r"`
}

// parseReceiptCursor preserves scalar Lamport cursors for one signed session.
// Tenant-wide listings require an opaque composite cursor because each session
// owns its own Lamport clock.
func parseReceiptCursor(raw, sessionID string) (store.TenantReceiptCursor, error) {
	raw = strings.TrimSpace(raw)
	if strings.TrimSpace(sessionID) != "" {
		return parseSessionReceiptCursor(raw)
	}
	if raw == "" {
		return store.TenantReceiptCursor{}, nil
	}
	if !strings.HasPrefix(raw, tenantReceiptCursorVersionPrefix) {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor must be an opaque v1 cursor")
	}
	encoded := strings.TrimPrefix(raw, tenantReceiptCursorVersionPrefix)
	if encoded == "" {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor payload is required")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return store.TenantReceiptCursor{}, fmt.Errorf("decode tenant-wide receipt cursor: %w", err)
	}
	var wire tenantReceiptCursorWire
	if err := json.Unmarshal(decoded, &wire); err != nil {
		return store.TenantReceiptCursor{}, fmt.Errorf("decode tenant-wide receipt cursor payload: %w", err)
	}
	wire.ReceiptID = strings.TrimSpace(wire.ReceiptID)
	if wire.ReceiptID == "" || strings.TrimSpace(wire.Timestamp) == "" {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor is incomplete")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, wire.Timestamp)
	if err != nil || timestamp.IsZero() {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor timestamp is invalid")
	}
	return store.TenantReceiptCursor{LamportClock: wire.LamportClock, Timestamp: timestamp.UTC(), ReceiptID: wire.ReceiptID}, nil
}

func parseSessionReceiptCursor(raw string) (store.TenantReceiptCursor, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "lamport:"))
	if raw == "" {
		return store.TenantReceiptCursor{}, nil
	}
	lamport, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return store.TenantReceiptCursor{}, err
	}
	return store.TenantReceiptCursor{LamportClock: lamport}, nil
}

func receiptCursorForReceipt(sessionID string, receipt *contracts.Receipt) (store.TenantReceiptCursor, error) {
	if receipt == nil {
		return store.TenantReceiptCursor{}, fmt.Errorf("receipt cursor requires a receipt")
	}
	cursor := store.TenantReceiptCursor{LamportClock: receipt.LamportClock}
	if strings.TrimSpace(sessionID) != "" {
		return cursor, nil
	}
	cursor.ReceiptID = strings.TrimSpace(receipt.ReceiptID)
	cursor.Timestamp = receipt.Timestamp.UTC()
	if cursor.ReceiptID == "" || cursor.Timestamp.IsZero() {
		return store.TenantReceiptCursor{}, fmt.Errorf("tenant-wide receipt cursor requires receipt id and timestamp")
	}
	return cursor, nil
}

func formatReceiptCursor(sessionID string, cursor store.TenantReceiptCursor) (string, error) {
	if strings.TrimSpace(sessionID) != "" {
		if cursor.LamportClock == 0 {
			return "", nil
		}
		return fmt.Sprintf("lamport:%d", cursor.LamportClock), nil
	}
	cursor.ReceiptID = strings.TrimSpace(cursor.ReceiptID)
	if cursor.ReceiptID == "" || cursor.Timestamp.IsZero() {
		return "", fmt.Errorf("tenant-wide receipt cursor is incomplete")
	}
	payload, err := json.Marshal(tenantReceiptCursorWire{
		LamportClock: cursor.LamportClock,
		Timestamp:    cursor.Timestamp.UTC().Format(time.RFC3339Nano),
		ReceiptID:    cursor.ReceiptID,
	})
	if err != nil {
		return "", fmt.Errorf("encode tenant-wide receipt cursor: %w", err)
	}
	return tenantReceiptCursorVersionPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func nextReceiptCursor(sessionID string, receipts []*contracts.Receipt) (string, error) {
	if len(receipts) == 0 {
		return "", nil
	}
	cursor, err := receiptCursorForReceipt(sessionID, receipts[len(receipts)-1])
	if err != nil {
		return "", err
	}
	return formatReceiptCursor(sessionID, cursor)
}

func parseLimit(raw string, fallback, max int) int {
	limit := fallback
	if raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	if limit <= 0 {
		return fallback
	}
	if limit > max {
		return max
	}
	return limit
}

func persistDecisionReceipt(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID string, body []byte, metadata map[string]any) error {
	return persistDecisionReceiptForTenant(ctx, svc, decision, agentID, "", body, metadata)
}

// persistDecisionReceiptForTenant may use the tenant-qualified causal-store
// capability only when the caller supplies an independently authenticated
// tenant ID. Generic paths intentionally remain unscoped rather than deriving
// a durable namespace from caller-controlled decision context.
func persistDecisionReceiptForTenant(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID, authenticatedTenantID string, body []byte, metadata map[string]any) error {
	return persistDecisionReceiptForTenantWithProvenance(ctx, svc, decision, agentID, authenticatedTenantID, body, metadata, nil)
}

func persistOrganizationRuntimeDecisionReceiptForTenant(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID, authenticatedTenantID string, body []byte, metadata map[string]any, provenance organizationRuntimeReceiptProvenance) error {
	return persistDecisionReceiptForTenantWithProvenance(ctx, svc, decision, agentID, authenticatedTenantID, body, metadata, &provenance)
}

func persistDecisionReceiptForTenantWithProvenance(ctx context.Context, svc *Services, decision *contracts.DecisionRecord, agentID, authenticatedTenantID string, body []byte, metadata map[string]any, provenance *organizationRuntimeReceiptProvenance) error {
	if svc == nil || svc.ReceiptStore == nil || decision == nil {
		return fmt.Errorf("receipt persistence unavailable")
	}
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		agentID = "anonymous"
	}
	argsHash := sha256HexBytes(body)
	if metadata != nil {
		if override, ok := metadata["args_hash"].(string); ok && strings.TrimSpace(override) != "" {
			argsHash = strings.TrimSpace(override)
		}
	}
	receiptID := "rcpt_" + decision.ID
	if tenantID := strings.TrimSpace(authenticatedTenantID); tenantID != "" {
		receiptID = executor.ReceiptIDForDecision(tenantID, decision.ID)
	}
	effectID := decision.Action
	if effectID == "" {
		if action, ok := metadata["action"].(string); ok {
			effectID = action
		}
	}
	timestamp := decision.Timestamp.UTC()
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	if svc.ReceiptSigner == nil {
		return fmt.Errorf("receipt signer unavailable")
	}
	decisionHash, hashErr := helmcrypto.DecisionSemanticHash(decision)
	if hashErr != nil {
		return fmt.Errorf("derive semantic decision hash: %w", hashErr)
	}
	sessionID := ""
	if decision.InputContext != nil {
		if value, ok := decision.InputContext["session_id"].(string); ok {
			sessionID = strings.TrimSpace(value)
		}
	}
	if sessionID == "" {
		sessionID = agentID
	}
	if normalizer, ok := svc.ReceiptStore.(store.ReceiptTimestampNormalizer); ok {
		// The timestamp is part of the signed V5 receipt. Normalize it before
		// signing and transparency anchoring so a durable reload retains the
		// same chain hash.
		timestamp = normalizer.NormalizeReceiptTimestamp(timestamp)
	}
	var issued *contracts.Receipt
	build := func(_ *contracts.Receipt, lamport uint64, prevHash string) (*contracts.Receipt, error) {
		receipt := &contracts.Receipt{
			ReceiptID:    receiptID,
			DecisionID:   decision.ID,
			EffectID:     effectID,
			Status:       decision.Verdict,
			BlobHash:     argsHash,
			OutputHash:   decisionHash,
			DecisionHash: decisionHash,
			Timestamp:    timestamp,
			ExecutorID:   agentID,
			Verdict:      decision.Verdict,
			ReasonCode:   decision.ReasonCode,
			PolicyHash:   decision.PolicyContentHash,
			SessionID:    sessionID,
			Metadata:     metadata,
			PrevHash:     prevHash,
			LamportClock: lamport,
			ArgsHash:     argsHash,
		}
		if provenance != nil {
			attestation, err := signOrganizationRuntimeDecisionAttestation(ctx, svc, receipt, *provenance)
			if err != nil {
				return nil, err
			}
			receipt.OrganizationRuntimeDecisionAttestation = attestation
		}
		if err := svc.ReceiptSigner.SignReceipt(receipt); err != nil {
			return nil, fmt.Errorf("sign receipt %s: %w", receiptID, err)
		}
		// Anchor the signed receipt hash in the transparency log before it is
		// persisted. Fail-closed: an append failure aborts the builder, which
		// rolls back AppendCausal so no receipt is stored. Degrade mode is the
		// only escape and must be explicitly enabled in config.
		if err := anchorReceiptTransparency(svc, receipt); err != nil {
			return nil, err
		}
		issued = receipt
		return receipt, nil
	}
	var err error
	if scoped, ok := svc.ReceiptStore.(store.TenantScopedCausalReceiptAppender); ok && strings.TrimSpace(authenticatedTenantID) != "" {
		err = scoped.AppendCausalScoped(ctx, strings.TrimSpace(authenticatedTenantID), sessionID, build)
	} else {
		err = svc.ReceiptStore.AppendCausal(ctx, sessionID, build)
	}
	if err != nil {
		return fmt.Errorf("store receipt %s: %w", receiptID, err)
	}
	if err := writePortableEvaluateEvidencePack(svc, issued); err != nil {
		return fmt.Errorf("write portable evaluate evidence pack %s: %w", receiptID, err)
	}
	return nil
}

// TransparencyAppender is the subset of the receipt transparency log needed at
// issuance time: append a receipt-hash leaf and report its assigned index.
type TransparencyAppender interface {
	Append(leafInput []byte) (uint64, error)
}

// anchorReceiptTransparency appends the signed receipt's content hash to the
// transparency log and records the resulting leaf on the receipt. It is
// fail-closed by default: if the log is configured but the append fails,
// issuance is aborted. When svc.TranspLogDegrade is set, an append failure
// instead records a deferred anchor so the receipt can be backfilled later.
// A nil log leaves the receipt unanchored (no transparency configured).
func anchorReceiptTransparency(svc *Services, receipt *contracts.Receipt) error {
	if svc == nil || svc.TranspLog == nil {
		return nil
	}
	leafHashHex, err := contracts.ReceiptChainHash(receipt)
	if err != nil {
		return fmt.Errorf("transparency leaf hash for %s: %w", receipt.ReceiptID, err)
	}
	leafInput, err := hex.DecodeString(leafHashHex)
	if err != nil {
		return fmt.Errorf("decode transparency leaf hash for %s: %w", receipt.ReceiptID, err)
	}
	index, appendErr := svc.TranspLog.Append(leafInput)
	if appendErr != nil {
		if !svc.TranspLogDegrade {
			return fmt.Errorf("transparency log append for %s: %w", receipt.ReceiptID, appendErr)
		}
		receipt.LogID = svc.TranspLogID
		receipt.Transparency = &contracts.TransparencyAnchor{
			Backend:  "translog",
			LogID:    svc.TranspLogID,
			Deferred: true,
		}
		return nil
	}
	receipt.LogID = svc.TranspLogID
	receipt.LeafIndex = index
	receipt.Transparency = &contracts.TransparencyAnchor{
		Backend: "translog",
		LogID:   svc.TranspLogID,
	}
	return nil
}

func receiptLinkHash(receipt *contracts.Receipt) string {
	if hash, err := contracts.ReceiptChainHash(receipt); err == nil {
		return hash
	}
	if receipt.MerkleRoot != "" {
		return sha256HexBytes([]byte(receipt.MerkleRoot))
	}
	return sha256HexBytes([]byte(receipt.ReceiptID))
}

func sha256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
