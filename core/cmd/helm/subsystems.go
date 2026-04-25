package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/memory"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/replay"
	trustregistry "github.com/Mindburn-Labs/helm-oss/core/pkg/trust/registry"
)

// RegisterSubsystemRoutes registers all subsystem API routes on the given mux.
// This wires kernel-critical packages into the HTTP API surface.
// Non-TCB enterprise subsystems have been removed from OSS.
//
//nolint:gocyclo,gocognit // Route registration is linear and intentionally exhaustive.
func RegisterSubsystemRoutes(mux *http.ServeMux, svc *Services) {
	log.Println("[helm] routes: Registering API routes...")

	ctx := context.Background()
	versionInfo := map[string]any{
		"version":    displayVersion(),
		"commit":     displayCommit(),
		"build_time": displayBuildTime(),
		"go_version": runtime.Version(),
	}

	// --- OpenAI-Compatible Proxy (governed inference) ---
	// Wraps api.HandleOpenAIProxy with Guardian governance enforcement and receipt headers.
	// Requires HELM_UPSTREAM_URL to be set for real upstream forwarding.
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}

		// Pre-flight: Guardian governance check
		if svc.Guardian != nil {
			// Read and buffer the body so it can be re-read by the proxy
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				api.WriteBadRequest(w, "Failed to read request body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			var body map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				api.WriteBadRequest(w, "Invalid JSON body")
				return
			}

			model, _ := body["model"].(string)
			req := guardian.DecisionRequest{
				Principal: r.Header.Get("X-Helm-Principal"),
				Action:    "LLM_INFERENCE",
				Resource:  model,
				Context:   body,
			}
			if req.Principal == "" {
				req.Principal = "anonymous"
			}

			decision, err := svc.Guardian.EvaluateDecision(r.Context(), req)
			if err != nil {
				api.WriteInternal(w, err)
				return
			}

			// Emit receipt headers on every response (allow or deny)
			w.Header().Set("X-Helm-Decision-ID", decision.ID)
			w.Header().Set("X-Helm-Verdict", decision.Verdict)
			w.Header().Set("X-Helm-Policy-Version", decision.PolicyVersion)
			if decision.PolicyDecisionHash != "" {
				w.Header().Set("X-Helm-Decision-Hash", decision.PolicyDecisionHash)
			}

			if contracts.Verdict(decision.Verdict) != contracts.VerdictAllow {
				api.WriteError(w, http.StatusForbidden, "Governance Blocked", decision.Reason)
				return
			}

			// Re-buffer body for the proxy handler
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// Delegate to the real upstream proxy handler
		api.HandleOpenAIProxy(w, r)
	})

	// --- Evidence Export ---
	mux.HandleFunc("/api/v1/evidence/soc2", func(w http.ResponseWriter, r *http.Request) {
		bundle, err := svc.Evidence.ExportSOC2(r.Context(), "trace-"+time.Now().Format("20060102"), nil)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	})

	// --- Merkle Root ---
	mux.HandleFunc("/api/v1/merkle/root", func(w http.ResponseWriter, r *http.Request) {
		root := "uninitialized"
		if svc.MerkleTree != nil {
			root = svc.MerkleTree.Root
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"root": root})
	})

	// --- Budget ---
	mux.HandleFunc("/api/v1/budget/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enforcer": "postgres",
			"status":   "active",
		})
	})

	// --- Authz ---
	mux.HandleFunc("/api/v1/authz/check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"engine": "rebac",
			"status": "active",
		})
	})

	// --- Version ---
	versionHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(versionInfo)
	}
	mux.HandleFunc("/api/v1/version", versionHandler)
	mux.HandleFunc("/version", versionHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"version": displayVersion(),
		})
	})

	// --- Obligation ---
	mux.HandleFunc("/api/v1/obligation/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req struct {
			GoalSpec string `json:"goal_spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid body")
			return
		}
		obl, err := svc.Obligation.CreateObligation(req.GoalSpec)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(obl)
	})

	// --- Boundary ---
	mux.HandleFunc("/api/v1/boundary/check", func(w http.ResponseWriter, r *http.Request) {
		if svc.BoundaryEnforcer == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "disabled"})
			return
		}
		targetURL := r.URL.Query().Get("url")
		if targetURL != "" {
			err := svc.BoundaryEnforcer.CheckNetwork(r.Context(), targetURL)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"allowed": false, "reason": err.Error()})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true})
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"enforcer": "active", "status": "ready"})
	})

	// --- Sandbox ---
	mux.HandleFunc("/api/v1/sandbox/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sandbox": "in-process", "status": "active"})
	})

	// --- Config ---
	mux.HandleFunc("/api/v1/config/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"port":      svc.Config.Port,
			"log_level": svc.Config.LogLevel,
		})
	})

	// --- Credentials ---
	if svc.Creds != nil {
		svc.Creds.RegisterRoutes(mux)
		log.Println("[helm] routes: Credential management routes registered")
	}

	// --- Trust Keys (C-2: require admin auth — fail-closed if HELM_ADMIN_API_KEY unset) ---
	trustKeys := &api.TrustKeyHandler{Registry: trustregistry.NewTrustRegistry()}
	mux.Handle("/api/v1/trust/keys/add", auth.RequireAdminAuth(trustKeys.HandleAddKey))
	mux.Handle("/api/v1/trust/keys/revoke", auth.RequireAdminAuth(trustKeys.HandleRevokeKey))

	// --- MCP Gateway ---
	mcpGateway, err := newLocalMCPGateway()
	if err != nil {
		log.Printf("[helm] routes: MCP gateway unavailable: %v", err)
	} else {
		mcpGateway.RegisterRoutes(mux)
		log.Println("[helm] routes: MCP gateway routes registered")
	}

	// ═══════════════════════════════════════════════════════════════
	// NEW SUBSYSTEM ROUTES (v7/v9 gap implementations)
	// ═══════════════════════════════════════════════════════════════

	// --- Governed Memory (LKS/CKS) ---
	mux.HandleFunc("/api/v1/memory/list", func(w http.ResponseWriter, r *http.Request) {
		tier := memory.MemoryTier(r.URL.Query().Get("tier"))
		if tier == "" {
			tier = memory.TierLKS
		}
		ns := r.URL.Query().Get("namespace")
		entries, err := svc.GovMemory.List(tier, ns)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tier": tier, "entries": entries, "count": len(entries)})
	})

	mux.HandleFunc("/api/v1/memory/promote", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req memory.PromotionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid body")
			return
		}
		result, err := memory.Promote(svc.GovMemory, req)
		if err != nil {
			api.WriteError(w, http.StatusConflict, "Promotion Failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})

	// --- Context Bundles ---
	mux.HandleFunc("/api/v1/context/bundles", func(w http.ResponseWriter, r *http.Request) {
		bundles := svc.BundleStore.ListContexts()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"bundles": bundles, "count": len(bundles)})
	})

	// --- Economic Ledger ---
	mux.HandleFunc("/api/v1/economic/authorities", func(w http.ResponseWriter, r *http.Request) {
		authorities := svc.EconLedger.ListAuthorities()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"authorities": authorities, "count": len(authorities)})
	})

	mux.HandleFunc("/api/v1/economic/charges", func(w http.ResponseWriter, r *http.Request) {
		charges := svc.EconLedger.ListCharges()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"charges": charges, "count": len(charges)})
	})

	mux.HandleFunc("/api/v1/economic/allocations", func(w http.ResponseWriter, r *http.Request) {
		allocations := svc.EconLedger.ListAllocations()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"allocations": allocations, "count": len(allocations)})
	})

	// --- Edge Governance ---
	mux.HandleFunc("/api/v1/governance/edge/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"mode":           svc.EdgeAssistant.Config.Mode,
			"fallback":       svc.EdgeAssistant.Fallback.Strategy,
			"max_latency_ms": svc.EdgeAssistant.Config.MaxLatencyMs,
		})
	})

	// --- Replay Visualizer ---
	mux.HandleFunc("/api/v1/replay/timeline", func(w http.ResponseWriter, r *http.Request) {
		// Build timeline from receipt store (empty if no receipts)
		timeline, err := replay.BuildTimeline("live-"+time.Now().Format("20060102-150405"), nil)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "empty", "message": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(timeline)
	})

	// --- Compatibility Matrix ---
	mux.HandleFunc("/api/v1/compatibility", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(svc.CompatMatrix)
	})

	// Suppress unused variable
	_ = ctx

	log.Println("[helm] routes: All subsystem routes registered")
}
