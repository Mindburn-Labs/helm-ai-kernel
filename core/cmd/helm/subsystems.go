package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/a2a"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	mcppkg "github.com/Mindburn-Labs/helm-oss/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/memory"
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

	registerPolicyReconcileRoutes(mux, svc)

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
			agentID := r.Header.Get("X-Helm-Agent")
			if agentID == "" {
				agentID = r.Header.Get("X-Agent-ID")
			}
			if agentID == "" {
				agentID = req.Principal
			}
			persistDecisionReceipt(r.Context(), svc, decision, agentID, bodyBytes, map[string]any{
				"source":   "openai.proxy",
				"action":   req.Action,
				"resource": req.Resource,
				"reason":   decision.Reason,
			})

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
	mux.HandleFunc("/api/v1/evidence/soc2", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		bundle, err := svc.Evidence.ExportSOC2(r.Context(), "trace-"+time.Now().Format("20060102"), nil)
		if err != nil {
			api.WriteInternal(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))

	// --- Merkle Root ---
	mux.HandleFunc("/api/v1/merkle/root", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		root := "uninitialized"
		if svc.MerkleTree != nil {
			root = svc.MerkleTree.Root
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"root": root})
	}))

	// --- Budget ---
	mux.HandleFunc("/api/v1/budget/status", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enforcer": "postgres",
			"status":   "active",
		})
	}))

	// --- Authz ---
	mux.HandleFunc("/api/v1/authz/check", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			hash := ""
			if svc.Authz != nil {
				hash, _ = svc.Authz.RelationshipSnapshotHash()
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"engine":            "rebac",
				"status":            "active",
				"relationship_hash": hash,
			})
			return
		}
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req struct {
			Resolver      string `json:"resolver"`
			ModelID       string `json:"model_id"`
			Object        string `json:"object"`
			Relation      string `json:"relation"`
			Subject       string `json:"subject"`
			Stale         bool   `json:"stale"`
			ModelMismatch bool   `json:"model_mismatch"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid authz check request")
			return
		}
		if req.Resolver == "" {
			req.Resolver = "helm-rebac"
		}
		if req.ModelID == "" {
			req.ModelID = "helm-local-v1"
		}
		if svc.Authz == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Authz unavailable", "relationship resolver is not initialized")
			return
		}
		snapshot, err := svc.Authz.SnapshotCheck(r.Context(), req.Resolver, req.ModelID, req.Object, req.Relation, req.Subject, time.Now().UTC(), req.Stale, req.ModelMismatch)
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		if svc.BoundarySurfaces != nil {
			if sealed, putErr := svc.BoundarySurfaces.PutSnapshot(snapshot); putErr == nil {
				snapshot = sealed
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot)
	}))

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
	a2a.RegisterWellKnownRoute(mux, a2a.NewKernelCardProvider(a2a.KernelCardConfig{}))
	registerDemoRoutes(mux, svc)

	// --- Durable receipt API ---
	registerReceiptRoutes(mux, svc)
	approveHandler := api.NewApproveHandler(csvEnv("HELM_APPROVER_PUBLIC_KEYS"))
	mux.HandleFunc("/api/v1/kernel/approve", protectRuntimeHandler(RouteAuthService, approveHandler.HandleApprove))
	registerContractRoutes(mux, svc)

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
	var (
		mcpGateway *mcppkg.Gateway
		err        error
	)
	if svc.ReceiptSigner != nil {
		mcpGateway, err = newConfiguredLocalMCPGatewayWithSigner(mcppkg.GatewayConfig{}, svc.ReceiptSigner)
	} else {
		mcpGateway, err = newLocalMCPGateway()
	}
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

	// --- Compatibility Matrix ---
	mux.HandleFunc("/api/v1/compatibility", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(svc.CompatMatrix)
	})

	// Suppress unused variable
	_ = ctx

	log.Println("[helm] routes: All subsystem routes registered")
}

func csvEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}
