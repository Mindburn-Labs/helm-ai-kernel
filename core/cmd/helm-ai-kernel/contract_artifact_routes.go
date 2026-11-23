package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func registerArtifactContractRoutes(mux routeMux, svc *Services, surfaces *boundarypkg.SurfaceRegistry) {
	mux.HandleFunc("/api/v1/telemetry/harness-traces", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListHarnessTraces())
		case http.MethodPost:
			var trace contracts.HarnessTrace
			if err := json.NewDecoder(r.Body).Decode(&trace); err != nil {
				api.WriteBadRequest(w, "Invalid harness trace JSON")
				return
			}
			tenantID, err := authenticatedReceiptTenantID(r.Context())
			if err != nil {
				api.WriteForbidden(w, "Artifact receipt references require authenticated tenant principal context")
				return
			}
			if err := authorizeArtifactReceiptReferences(r.Context(), svc, tenantID, trace.ReceiptRefs...); err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			sealed, err := surfaces.PutHarnessTrace(trace)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, sealed)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))
	mux.HandleFunc("/api/v1/telemetry/harness-traces/", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/telemetry/harness-traces/")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid harness trace id")
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		trace, ok := surfaces.GetHarnessTrace(id)
		if !ok {
			api.WriteNotFound(w, "harness trace not found")
			return
		}
		writeContractJSON(w, http.StatusOK, trace)
	}))

	mux.HandleFunc("/api/v1/plans/transactions", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListPlanTransactions())
		case http.MethodPost:
			var tx contracts.PlanTransaction
			if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
				api.WriteBadRequest(w, "Invalid plan transaction JSON")
				return
			}
			tenantID, err := authenticatedReceiptTenantID(r.Context())
			if err != nil {
				api.WriteForbidden(w, "Artifact receipt references require authenticated tenant principal context")
				return
			}
			if err := authorizeArtifactReceiptReferences(r.Context(), svc, tenantID, tx.ReceiptRefs...); err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			sealed, err := surfaces.PutPlanTransaction(tx)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, sealed)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))
	mux.HandleFunc("/api/v1/plans/transactions/", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/plans/transactions/")
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid plan transaction id")
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		tx, ok := surfaces.GetPlanTransaction(id)
		if !ok {
			api.WriteNotFound(w, "plan transaction not found")
			return
		}
		writeContractJSON(w, http.StatusOK, tx)
	}))

	mux.HandleFunc("/api/v1/harness/change-contracts", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListHarnessChanges())
		case http.MethodPost:
			var contract contracts.HarnessChangeContract
			if err := json.NewDecoder(r.Body).Decode(&contract); err != nil {
				api.WriteBadRequest(w, "Invalid harness change contract JSON")
				return
			}
			tenantID, err := authenticatedReceiptTenantID(r.Context())
			if err != nil {
				api.WriteForbidden(w, "Artifact receipt references require authenticated tenant principal context")
				return
			}
			if receiptRef := strings.TrimSpace(contract.ActivationReceiptRef); receiptRef != "" {
				if err := authorizeArtifactReceiptReferences(r.Context(), svc, tenantID, receiptRef); err != nil {
					api.WriteBadRequest(w, err.Error())
					return
				}
			}
			sealed, err := surfaces.PutHarnessChange(contract)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusCreated, sealed)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))
	mux.HandleFunc("/api/v1/harness/change-contracts/", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/harness/change-contracts/")
		id, approve := strings.CutSuffix(suffix, "/approve")
		if approve {
			if id == "" || strings.Contains(id, "/") || r.Method != http.MethodPost {
				api.WriteMethodNotAllowed(w)
				return
			}
			var req struct {
				ReceiptRef string `json:"receipt_ref"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			tenantID, err := authenticatedReceiptTenantID(r.Context())
			if err != nil {
				api.WriteForbidden(w, "Artifact receipt references require authenticated tenant principal context")
				return
			}
			if err := authorizeArtifactReceiptReferences(r.Context(), svc, tenantID, req.ReceiptRef); err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			contract, err := surfaces.ApproveHarnessChange(id, req.ReceiptRef)
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			writeContractJSON(w, http.StatusOK, contract)
			return
		}
		if id == "" || strings.Contains(id, "/") {
			api.WriteBadRequest(w, "Invalid harness change contract id")
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		contract, ok := surfaces.GetHarnessChange(id)
		if !ok {
			api.WriteNotFound(w, "harness change contract not found")
			return
		}
		writeContractJSON(w, http.StatusOK, contract)
	}))
}
