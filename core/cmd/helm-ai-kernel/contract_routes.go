package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

// protectConfiguredTenantStore guards a tenant_scoped route whose store has no
// tenant dimension: the boundary SurfaceRegistry and the Launchpad run store are
// each one process-wide store. Such a store belongs to the tenant this Kernel is
// configured for (HELM_RUNTIME_TENANT_ID, "default" when unset), so any other
// bound tenant is refused rather than shown or allowed to change that tenant's
// records (S-05). Partitioning these stores per tenant would need a tenant
// field on their records and persisted ownership; it is not done.
func protectConfiguredTenantStore(handler http.HandlerFunc) http.HandlerFunc {
	return protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := authenticatedReceiptTenantID(r.Context())
		if err != nil || tenantID != configuredRuntimeTenantID() {
			api.WriteForbidden(w, "This surface is not partitioned by tenant; it serves only the Kernel's configured tenant")
			return
		}
		handler(w, r)
	})
}

func registerContractRoutes(mux routeMux, svc *Services) {
	mcpQuarantine := mcppkg.NewQuarantineRegistry()
	surfaces := boundarypkg.NewSurfaceRegistry(time.Now)
	if svc != nil && svc.BoundarySurfaces != nil {
		surfaces = svc.BoundarySurfaces
	}
	hydrateMCPQuarantine(context.Background(), mcpQuarantine, surfaces.ListMCPServers())

	mux.HandleFunc("/api/v1/boundary/status", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.Status(displayVersion(), svc != nil && svc.ReceiptStore != nil, svc != nil && svc.ReceiptSigner != nil, countMCPQuarantined(mcpQuarantine.List(r.Context()))))
	}))

	mux.HandleFunc("/api/v1/boundary/capabilities", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.Capabilities())
	}))

	mux.HandleFunc("/api/v1/boundary/records", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		query := contracts.BoundarySearchRequest{
			Verdict:     r.URL.Query().Get("verdict"),
			ReasonCode:  r.URL.Query().Get("reason_code"),
			ToolName:    r.URL.Query().Get("tool_name"),
			MCPServerID: r.URL.Query().Get("mcp_server_id"),
			PolicyEpoch: r.URL.Query().Get("policy_epoch"),
			ReceiptID:   r.URL.Query().Get("receipt_id"),
			Limit:       parseLimit(r.URL.Query().Get("limit"), 50, 1000),
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListRecords(query))
	}))

	mux.HandleFunc("/api/v1/boundary/records/", protectConfiguredTenantStore(func(w http.ResponseWriter, r *http.Request) {
		recordID := strings.TrimPrefix(r.URL.Path, "/api/v1/boundary/records/")
		if recordID == "" || strings.Contains(recordID, "/") {
			api.WriteBadRequest(w, "Invalid boundary record id")
			return
		}
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		record, ok := surfaces.GetRecord(recordID)
		if !ok {
			api.WriteNotFound(w, "boundary record not found")
			return
		}
		writeContractJSON(w, http.StatusOK, record)
	}))

	mux.HandleFunc("/api/v1/boundary/checkpoints", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListCheckpoints())
		case http.MethodPost:
			receiptCount := 0
			if svc != nil && svc.ReceiptStore != nil {
				// SurfaceRegistry checkpoints are process-global, so this count must
				// cover every durable receipt rather than the admin principal's
				// synthetic "system" tenant.
				counter, ok := svc.ReceiptStore.(store.ReceiptCounter)
				if !ok {
					api.WriteInternalR(w, r, fmt.Errorf("receipt store does not support durable receipt counting"))
					return
				}
				var err error
				receiptCount, err = counter.CountReceipts(r.Context())
				if err != nil {
					api.WriteInternalR(w, r, err)
					return
				}
			}
			checkpoint, err := surfaces.CreateCheckpoint(receiptCount)
			if err != nil {
				api.WriteInternalR(w, r, err)
				return
			}
			writeContractJSON(w, http.StatusCreated, checkpoint)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	registerProofGraphContractRoutes(mux, svc)
	registerEvidenceContractRoutes(mux, svc, surfaces)
	registerArtifactContractRoutes(mux, svc, surfaces)
	registerEvidenceEnvelopeContractRoutes(mux, surfaces)

	mux.HandleFunc("/api/v1/conformance/vectors", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, map[string]any{
			"levels":   []string{"L1", "L2", "L3", "L4"},
			"negative": conformance.DefaultNegativeBoundaryVectors(),
			"profiles": []string{"receipts", "mcp", "sandbox", "authz", "approval", "telemetry", "envelopes", "checkpoints"},
		})
	})

	mux.HandleFunc("/api/v1/conformance/negative", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, conformance.DefaultNegativeBoundaryVectors())
	})

	registerMCPContractRoutes(mux, surfaces, mcpQuarantine)
	registerSandboxContractRoutes(mux, surfaces)
	registerAuthorityContractRoutes(mux, svc, surfaces)

	mux.HandleFunc("/api/v1/coexistence/capabilities", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, contracts.CoexistenceCapabilityManifest{
			ManifestID:      "helm-coexistence-oss",
			Authority:       "helm-native-receipts",
			BoundaryRole:    "inner-proof-bearing-execution-boundary",
			SupportedInputs: []string{"mcp", "openai-compatible-proxy", "framework-middleware", "gateway-export"},
			ExportSurfaces:  []string{"evidencepack", "dsse", "jws", "in-toto", "slsa", "sigstore", "otel-genai", "cloudevents"},
			ReceiptBindings: []string{"receipt_id", "record_hash", "sandbox_grant_hash", "authz_snapshot_hash"},
			GeneratedAt:     time.Now().UTC(),
		})
	}))

	mux.HandleFunc("/api/v1/telemetry/otel/config", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, telemetryConfig())
	}))

	mux.HandleFunc("/api/v1/telemetry/export", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.TelemetryExportRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Format == "" {
			req.Format = "otel-genai"
		}
		writeContractJSON(w, http.StatusAccepted, contracts.TelemetryExportResult{
			ExportID:      contracts.SurfaceID("telemetry", req.Format+"-"+req.ReceiptID+"-"+req.RecordHash),
			Format:        req.Format,
			Authoritative: false,
			Attributes:    req.Attributes,
			ExportedAt:    time.Now().UTC(),
		})
	}))
}

func writeContractJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func telemetryConfig() contracts.TelemetryOTelConfig {
	return contracts.TelemetryOTelConfig{
		ServiceName:   "helm-ai-kernel",
		SignalType:    "otel",
		Authoritative: false,
		SpanAttributes: map[string]string{
			"service.name":         "helm-ai-kernel",
			"helm.boundary.role":   "execution-kernel",
			"helm.evidence.source": "runtime-export",
		},
		ExportedSignals: []string{"traces", "metrics", "logs"},
	}
}
