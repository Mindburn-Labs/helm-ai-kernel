package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
)

func registerAuthorityContractRoutes(mux routeMux, svc *Services, surfaces *boundarypkg.SurfaceRegistry) {
	mux.HandleFunc("/api/v1/identity/agents", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListAgents())
	}))

	mux.HandleFunc("/api/v1/authz/health", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		hash := ""
		if svc != nil && svc.Authz != nil {
			hash, _ = svc.Authz.RelationshipSnapshotHash()
		}
		writeContractJSON(w, http.StatusOK, contracts.AuthzHealth{
			Status:           "ready",
			Resolver:         "helm-rebac",
			ModelID:          "helm-local-v1",
			RelationshipHash: hash,
			CheckedAt:        time.Now().UTC(),
		})
	}))

	mux.HandleFunc("/api/v1/authz/snapshots", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListSnapshots())
	}))

	mux.HandleFunc("/api/v1/authz/snapshots/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		snapshotID := strings.TrimPrefix(r.URL.Path, "/api/v1/authz/snapshots/")
		if snapshotID == "" || strings.Contains(snapshotID, "/") {
			api.WriteBadRequest(w, "Invalid authz snapshot id")
			return
		}
		snapshot, ok := surfaces.GetSnapshot(snapshotID)
		if !ok {
			api.WriteNotFound(w, "authz snapshot not found")
			return
		}
		writeContractJSON(w, http.StatusOK, snapshot)
	}))

	mux.HandleFunc("/api/v1/approvals", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListApprovals())
		case http.MethodPost:
			var req struct {
				ApprovalID    string    `json:"approval_id"`
				Subject       string    `json:"subject"`
				Action        string    `json:"action"`
				RequestedBy   string    `json:"requested_by"`
				Approvers     []string  `json:"approvers"`
				Quorum        int       `json:"quorum"`
				TimelockUntil time.Time `json:"timelock_until"`
				ExpiresAt     time.Time `json:"expires_at"`
				Reason        string    `json:"reason"`
				ReceiptID     string    `json:"receipt_id"`
				BreakGlass    bool      `json:"break_glass"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				api.WriteBadRequest(w, "Invalid approval request")
				return
			}
			if req.ApprovalID == "" {
				req.ApprovalID = contracts.SurfaceID("approval", req.Subject+"-"+req.Action)
			}
			if req.TimelockUntil.IsZero() || req.ExpiresAt.IsZero() {
				api.WriteBadRequest(w, "timelock_until and expires_at are required")
				return
			}
			now := time.Now().UTC()
			approval, err := surfaces.PutApproval(contracts.ApprovalCeremony{
				ApprovalID:    req.ApprovalID,
				Subject:       req.Subject,
				Action:        req.Action,
				State:         contracts.ApprovalCeremonyPending,
				RequestedBy:   req.RequestedBy,
				Approvers:     req.Approvers,
				Quorum:        req.Quorum,
				TimelockUntil: req.TimelockUntil,
				ExpiresAt:     req.ExpiresAt,
				BreakGlass:    req.BreakGlass,
				Reason:        req.Reason,
				ReceiptID:     req.ReceiptID,
				CreatedAt:     now,
				UpdatedAt:     now,
			})
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, approval)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/v1/approvals/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/approvals/")
		approvalID, action, ok := strings.Cut(suffix, "/")
		if !ok || approvalID == "" {
			api.WriteBadRequest(w, "Invalid approval route")
			return
		}
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if action == "webauthn/challenge" {
			var req struct {
				Method string `json:"method"`
				TTLMS  int64  `json:"ttl_ms"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			challenge, err := surfaces.CreateApprovalChallenge(approvalID, req.Method, time.Duration(req.TTLMS)*time.Millisecond)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, challenge)
			return
		}
		if action == "webauthn/assert" {
			var req contracts.ApprovalWebAuthnAssertion
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				api.WriteBadRequest(w, "Invalid WebAuthn assertion request")
				return
			}
			approval, err := surfaces.AssertApprovalChallenge(req)
			if err != nil {
				if errors.Is(err, boundarypkg.ErrApprovalVerificationUnavailable) {
					api.WriteError(w, http.StatusServiceUnavailable, "Approval verification unavailable", err.Error())
					return
				}
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusOK, approval)
			return
		}
		var req struct {
			ReceiptID            string `json:"receipt_id"`
			Reason               string `json:"reason"`
			ExpectedCeremonyHash string `json:"expected_ceremony_hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid approval transition request")
			return
		}
		if strings.TrimSpace(req.ExpectedCeremonyHash) == "" {
			api.WriteError(w, http.StatusPreconditionRequired, "Precondition Required", "expected_ceremony_hash is required; refresh and review the approval before transitioning it")
			return
		}
		state := contracts.ApprovalCeremonyPending
		switch action {
		case "approve":
			state = contracts.ApprovalCeremonyAllowed
		case "deny":
			state = contracts.ApprovalCeremonyDenied
		case "revoke":
			state = contracts.ApprovalCeremonyRevoked
		default:
			api.WriteNotFound(w, "approval action not found")
			return
		}
		principal, err := helmauth.GetPrincipal(r.Context())
		if err != nil || principal == nil || strings.TrimSpace(principal.GetID()) == "" {
			httperr.WriteUnauthorized(w, "Authenticated principal is required for approval transition")
			return
		}
		approval, err := surfaces.TransitionApprovalIfCurrent(approvalID, state, principal.GetID(), req.ReceiptID, req.Reason, req.ExpectedCeremonyHash)
		if err != nil {
			if errors.Is(err, boundarypkg.ErrApprovalTransitionConflict) {
				api.WriteConflict(w, "Approval changed; refresh and review again")
				return
			}
			api.WriteBadRequest(w, err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, approval)
	}))

	mux.HandleFunc("/api/v1/budgets", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListBudgets())
	}))

	mux.HandleFunc("/api/v1/budgets/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		budgetID := strings.TrimPrefix(r.URL.Path, "/api/v1/budgets/")
		if budgetID == "" || strings.Contains(budgetID, "/") {
			api.WriteBadRequest(w, "Invalid budget id")
			return
		}
		if r.Method != http.MethodPut {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.BudgetCeiling
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid budget request")
			return
		}
		req.BudgetID = budgetID
		if req.Subject == "" {
			req.Subject = "tenant:default"
		}
		if req.Window == "" {
			req.Window = "24h"
		}
		budget, err := surfaces.PutBudget(req)
		if err != nil {
			api.WriteError(w, http.StatusInternalServerError, "Boundary registry persistence failed", err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, budget)
	}))
}
