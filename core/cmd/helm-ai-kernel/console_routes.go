package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type consoleBootstrapResponse struct {
	Version     consoleVersionInfo     `json:"version"`
	Workspace   consoleWorkspace       `json:"workspace"`
	Health      consoleHealth          `json:"health"`
	Counts      consoleCounts          `json:"counts"`
	Receipts    []*contracts.Receipt   `json:"receipts"`
	Conformance consoleConformanceInfo `json:"conformance"`
	MCP         consoleMCPInfo         `json:"mcp"`
}

type consoleVersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

type consoleWorkspace struct {
	Organization string `json:"organization"`
	Project      string `json:"project"`
	Environment  string `json:"environment"`
	Mode         string `json:"mode"`
}

type consoleHealth struct {
	Kernel      string `json:"kernel"`
	Policy      string `json:"policy"`
	Store       string `json:"store"`
	Conformance string `json:"conformance"`
}

type consoleCounts struct {
	Receipts         int `json:"receipts"`
	PendingApprovals int `json:"pending_approvals"`
	OpenIncidents    int `json:"open_incidents"`
	MCPTools         int `json:"mcp_tools"`
}

type consoleConformanceInfo struct {
	Level    string `json:"level"`
	Status   string `json:"status"`
	ReportID string `json:"report_id,omitempty"`
}

type consoleMCPInfo struct {
	Authorization string   `json:"authorization"`
	Scopes        []string `json:"scopes"`
}

type consoleDiagnosticsResponse struct {
	GeneratedAt string                   `json:"generated_at"`
	Runtime     map[string]any           `json:"runtime"`
	Access      map[string]any           `json:"access"`
	Stores      []consoleStoreDiagnostic `json:"stores"`
	Routes      []consoleRouteDiagnostic `json:"routes"`
}

type consoleStoreDiagnostic struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"`
	Backend string `json:"backend"`
	Source  string `json:"source,omitempty"`
	Path    string `json:"path,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type consoleSurfaceDefinition struct {
	ID                string
	Label             string
	Group             string
	Source            string
	Status            string
	UnsupportedReason string
}

// RegisterConsoleRoutes exposes the small platform state surface required by
// the HELM AI Kernel Console. The handler is read-only and derives state from kernel
// services; it does not create demonstration data.
func RegisterConsoleRoutes(mux routeMux, svc *Services, opts serverOptions) {
	metaCapabilitiesHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entitlements": []string{"OSS_CORE"},
			"version":      "1.25",
		})
	}
	mux.HandleFunc("/v1/meta/capabilities", metaCapabilitiesHandler)
	mux.HandleFunc("/api/v1/meta/capabilities", metaCapabilitiesHandler)

	mux.HandleFunc("/api/v1/console/bootstrap", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}

		receipts := listConsoleReceipts(r.Context(), svc, 100)
		policyStatus := "unconfigured"
		if strings.TrimSpace(opts.PolicyPath) != "" {
			policyStatus = "ready"
		}
		storeStatus := "unavailable"
		if svc != nil && svc.ReceiptStore != nil {
			storeStatus = "ready"
		}

		response := consoleBootstrapResponse{
			Version: consoleVersionInfo{
				Version:   displayVersion(),
				Commit:    displayCommit(),
				BuildTime: displayBuildTime(),
				GoVersion: runtime.Version(),
			},
			Workspace: consoleWorkspace{
				Organization: envOrDefault("HELM_ORG", "local"),
				Project:      envOrDefault("HELM_PROJECT", "default"),
				Environment:  envOrDefault("HELM_ENV", "production"),
				Mode:         "self-hosted-oss",
			},
			Health: consoleHealth{
				Kernel:      "ready",
				Policy:      policyStatus,
				Store:       storeStatus,
				Conformance: envOrDefault("HELM_CONFORMANCE_STATUS", "unreported"),
			},
			Counts: consoleCounts{
				Receipts:         len(receipts),
				PendingApprovals: 0,
				OpenIncidents:    0,
				MCPTools:         0,
			},
			Receipts: receipts,
			Conformance: consoleConformanceInfo{
				Level:    envOrDefault("HELM_CONFORMANCE_LEVEL", "L0"),
				Status:   envOrDefault("HELM_CONFORMANCE_STATUS", "unreported"),
				ReportID: os.Getenv("HELM_CONFORMANCE_REPORT_ID"),
			},
			MCP: consoleMCPInfo{
				Authorization: envOrDefault("HELM_MCP_AUTHORIZATION", "local"),
				Scopes:        consoleScopes(),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))

	mux.HandleFunc("/api/v1/console/diagnostics", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(buildConsoleDiagnostics(svc, opts, r))
	}))

	mux.HandleFunc("/api/v1/console/surfaces", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"surfaces": consoleSurfaceCatalog(),
			"routes":   consoleRouteDiagnostics(),
		})
	}))

	mux.HandleFunc("/api/v1/console/surfaces/", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		surface := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/console/surfaces/"), "/")
		if surface == "" || strings.Contains(surface, "/") {
			api.WriteBadRequest(w, "Invalid console surface")
			return
		}
		state, ok := buildConsoleSurfaceState(r.Context(), svc, opts, surface)
		if !ok {
			api.WriteError(w, http.StatusNotFound, "Console surface not found", surface)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	}))

	RegisterConsoleAGUIRoutes(mux, svc, opts)
}

func consoleSurfaceCatalog() []map[string]any {
	defs := consoleSurfaceDefinitions()
	out := make([]map[string]any, 0, len(defs))
	for _, def := range defs {
		routes := consoleRouteDiagnosticsForSurface(def.ID)
		entry := map[string]any{
			"id":     def.ID,
			"label":  def.Label,
			"group":  def.Group,
			"source": def.Source,
			"status": firstNonEmpty(def.Status, "ready"),
			"routes": routes,
		}
		if len(routes) > 0 {
			entry["auth"] = routes[0].Auth
			entry["contract_status"] = routes[0].ContractStatus
			entry["operation_id"] = routes[0].OperationID
		}
		if def.UnsupportedReason != "" {
			entry["unsupported_reason"] = def.UnsupportedReason
		}
		out = append(out, entry)
	}
	return out
}

func consoleSurfaceDefinitions() []consoleSurfaceDefinition {
	return []consoleSurfaceDefinition{
		{ID: "overview", Label: "Overview", Group: "Core", Source: "/api/v1/console/bootstrap"},
		{ID: "agents", Label: "Agents", Group: "Core", Source: "/api/v1/console/surfaces/agents"},
		{ID: "actions", Label: "Actions", Group: "Core", Source: "/api/v1/console/surfaces/actions"},
		{ID: "approvals", Label: "Approvals", Group: "Core", Source: "/api/v1/approvals"},
		{ID: "policies", Label: "Policies", Group: "Policy", Source: "/api/v1/console/surfaces/policies"},
		{ID: "boundary", Label: "Boundary", Group: "Runtime", Source: "/api/v1/boundary/status"},
		{ID: "mcp", Label: "MCP Firewall", Group: "Connectors", Source: "/api/v1/mcp/registry"},
		{ID: "sandbox", Label: "Sandbox", Group: "Runtime", Source: "/api/v1/sandbox/grants"},
		{ID: "authz", Label: "Authorization", Group: "Policy", Source: "/api/v1/authz/health"},
		{ID: "budgets", Label: "Budgets", Group: "Policy", Source: "/api/v1/budgets"},
		{ID: "connectors", Label: "Connectors", Group: "Connectors", Source: "/mcp/v1/capabilities"},
		{ID: "receipts", Label: "Receipts", Group: "Proof", Source: "/api/v1/receipts"},
		{ID: "evidence", Label: "Evidence", Group: "Proof", Source: "/api/v1/evidence/export"},
		// The surface id stays "replay" for existing Console links; nothing is
		// replayed, so the label and source name the bundle verifier.
		{ID: "replay", Label: "Verify", Group: "Proof", Source: "/api/v1/evidence/verify"},
		{ID: "proofgraph", Label: "ProofGraph", Group: "Proof", Source: "/api/v1/proofgraph/sessions"},
		{ID: "harness", Label: "Harness", Group: "Developer", Source: "/api/v1/harness/change-contracts"},
		{ID: "telemetry", Label: "Telemetry", Group: "Developer", Source: "/api/v1/telemetry/otel/config"},
		{ID: "coexistence", Label: "Coexistence", Group: "Developer", Source: "/api/v1/coexistence/capabilities"},
		{ID: "audit", Label: "Audit", Group: "Proof", Source: "/api/v1/console/surfaces/audit"},
		{ID: "developer", Label: "Developer", Group: "Developer", Source: "/api/v1/console/surfaces/developer"},
		{ID: "settings", Label: "Settings", Group: "Core", Source: "/api/v1/console/surfaces/settings"},
		{ID: "diagnostics", Label: "Diagnostics", Group: "Developer", Source: "/api/v1/console/diagnostics"},
	}
}

func buildConsoleSurfaceState(ctx context.Context, svc *Services, opts serverOptions, surface string) (map[string]any, bool) {
	receipts := listConsoleReceipts(ctx, svc, 250)
	base := map[string]any{
		"id":           surface,
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	switch surface {
	case "overview":
		base["status"] = "ready"
		base["source"] = "/api/v1/console/bootstrap"
		base["summary"] = map[string]any{
			"version":  displayVersion(),
			"commit":   displayCommit(),
			"receipts": len(receipts),
			"policy":   policyStatus(opts),
		}
		base["records"] = receipts
	case "agents":
		base["status"] = statusFromStore(svc)
		base["source"] = "/api/v1/receipts"
		base["records"] = aggregateAgents(receipts)
	case "actions":
		base["status"] = statusFromStore(svc)
		base["source"] = "/api/v1/receipts"
		base["records"] = aggregateActions(receipts)
	case "approvals":
		base["status"] = "not_configured"
		base["source"] = "/api/v1/approvals"
		base["summary"] = map[string]any{
			"reason": "this surface does not read the approval ceremony store; list ceremonies through GET /api/v1/approvals",
		}
		base["records"] = []any{}
	case "policies":
		base["status"] = policyStatus(opts)
		base["source"] = opts.PolicyPath
		base["summary"] = map[string]any{
			"policy_path": opts.PolicyPath,
			"mode":        opts.Mode,
			"store":       statusFromStore(svc),
		}
		base["records"] = policyRecords(opts)
	case "replay":
		base["status"] = statusFromStore(svc)
		base["source"] = "/api/v1/evidence/verify"
		base["summary"] = map[string]any{
			"verifier":        "evidence bundle verifier",
			"receipt_count":   len(receipts),
			"storage_status":  statusFromStore(svc),
			"verification_io": "operator-provided evidence bundle",
		}
		base["records"] = replayConsoleRecords(receipts)
	case "audit":
		base["status"] = statusFromStore(svc)
		base["source"] = "/api/v1/receipts"
		base["records"] = receiptAuditRecords(receipts)
	case "developer":
		base["status"] = "ready"
		base["source"] = "/version"
		base["summary"] = map[string]any{
			"go_version": runtime.Version(),
		}
		base["records"] = consoleSurfaceCatalog()
	case "settings":
		base["status"] = "ready"
		base["source"] = "environment"
		base["summary"] = map[string]any{
			"organization": envOrDefault("HELM_ORG", "local"),
			"project":      envOrDefault("HELM_PROJECT", "default"),
			"environment":  envOrDefault("HELM_ENV", "production"),
			"bind":         opts.BindAddr,
			"port":         opts.Port,
		}
		base["records"] = []map[string]string{
			{"key": "HELM_ORG", "value": envOrDefault("HELM_ORG", "local")},
			{"key": "HELM_PROJECT", "value": envOrDefault("HELM_PROJECT", "default")},
			{"key": "HELM_ENV", "value": envOrDefault("HELM_ENV", "production")},
		}
	case "diagnostics":
		base["status"] = "ready"
		base["source"] = "/api/v1/console/diagnostics"
		base["summary"] = buildConsoleDiagnostics(svc, opts, nil)
		base["records"] = consoleRouteDiagnostics()
	default:
		if def, ok := consoleSurfaceDefinitionByID(surface); ok {
			base["status"] = firstNonEmpty(def.Status, "ready")
			base["source"] = def.Source
			base["summary"] = map[string]any{
				"label":              def.Label,
				"group":              def.Group,
				"unsupported_reason": def.UnsupportedReason,
			}
			base["records"] = consoleRouteDiagnosticsForSurface(surface)
			return base, true
		}
		return nil, false
	}
	return base, true
}

func buildConsoleDiagnostics(svc *Services, opts serverOptions, r *http.Request) consoleDiagnosticsResponse {
	dataDir := "data"
	dbMode := "unknown"
	dbStatus := "unavailable"
	sqlitePath := ""
	artifactPath := ""
	if svc != nil {
		dataDir = normalizedDataDir(svc.DataDir)
		dbMode = firstNonEmpty(svc.DatabaseMode, "unknown")
		dbStatus = firstNonEmpty(svc.DatabaseStatus, statusFromStore(svc))
		sqlitePath = svc.SQLitePath
		artifactPath = svc.ArtifactStorePath
	}
	if sqlitePath == "" {
		sqlitePath = filepath.Join(dataDir, "helm.db")
	}
	if artifactPath == "" {
		artifactPath = filepath.Join(dataDir, "artifacts")
	}
	tenant := ""
	if r != nil {
		tenant = selectedTenantID(r)
	}
	return consoleDiagnosticsResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Runtime: map[string]any{
			"version":    displayVersion(),
			"commit":     displayCommit(),
			"build_time": displayBuildTime(),
			"go_version": runtime.Version(),
			"mode":       firstNonEmpty(opts.Mode, "serve"),
			"data_dir":   dataDir,
			"bind":       opts.BindAddr,
			"port":       opts.Port,
		},
		Access: map[string]any{
			"admin_key_configured": strings.TrimSpace(os.Getenv("HELM_ADMIN_API_KEY")) != "",
			"tenant_id":            tenant,
			"tenant_header":        tenantHeader,
			"principal_header":     principalHeader,
		},
		Stores: []consoleStoreDiagnostic{
			{
				ID:      "database",
				Label:   "Database",
				Status:  dbStatus,
				Backend: dbMode,
				Source:  databaseSource(dbMode),
				Path:    pathForDatabaseMode(dbMode, sqlitePath),
				Detail:  databaseDetail(dbMode),
			},
			{
				ID:      "receipt_store",
				Label:   "Receipt Store",
				Status:  statusFromStore(svc),
				Backend: dbMode,
				Source:  "/api/v1/receipts",
			},
			{
				ID:      "boundary_surface_registry",
				Label:   "Boundary Surface Registry",
				Status:  statusFromBoundaryRegistry(svc),
				Backend: boundaryRegistryBackend(svc),
				Source:  "/api/v1/boundary/status",
			},
			{
				ID:      "policy_snapshot_store",
				Label:   "Policy Snapshot Store",
				Status:  statusFromPolicyStore(svc),
				Backend: "atomic-memory",
				Source:  "/internal/policy/reconcile",
			},
			{
				ID:      "artifact_store",
				Label:   "Artifact Store",
				Status:  "ready",
				Backend: "file",
				Path:    artifactPath,
			},
		},
		Routes: consoleRouteDiagnostics(),
	}
}

func databaseSource(mode string) string {
	if mode == "postgres" {
		return "DATABASE_URL"
	}
	if mode == "sqlite" {
		return "sqlite"
	}
	return "runtime"
}

func pathForDatabaseMode(mode, sqlitePath string) string {
	if mode == "sqlite" {
		return sqlitePath
	}
	return ""
}

func databaseDetail(mode string) string {
	if mode == "postgres" {
		return "DATABASE_URL configured; DSN redacted"
	}
	if mode == "sqlite" {
		return "lite mode"
	}
	return "database mode unavailable"
}

func statusFromBoundaryRegistry(svc *Services) string {
	if svc != nil && svc.BoundarySurfaces != nil {
		return "ready"
	}
	return "unavailable"
}

func boundaryRegistryBackend(svc *Services) string {
	if svc != nil && svc.BoundarySurfaces != nil {
		return svc.BoundarySurfaces.StorageBackend()
	}
	return "unavailable"
}

func statusFromPolicyStore(svc *Services) string {
	if svc != nil && svc.PolicySnapshotStore != nil {
		return "ready"
	}
	return "unconfigured"
}

func consoleSurfaceDefinitionByID(id string) (consoleSurfaceDefinition, bool) {
	for _, def := range consoleSurfaceDefinitions() {
		if def.ID == id {
			return def, true
		}
	}
	return consoleSurfaceDefinition{}, false
}

func routeSurfaceGroup(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/v1/console/diagnostics"):
		return "diagnostics"
	case strings.HasPrefix(path, "/api/v1/console/bootstrap"):
		return "overview"
	case strings.HasPrefix(path, "/api/v1/console/surfaces"):
		return "settings"
	case strings.HasPrefix(path, "/api/v1/agent-ui") || strings.HasPrefix(path, "/api/ag-ui"):
		return "agents"
	case strings.HasPrefix(path, "/api/v1/receipts"):
		return "receipts"
	case strings.HasPrefix(path, "/api/v1/proofgraph"):
		return "proofgraph"
	case strings.HasPrefix(path, "/api/v1/evidence"):
		return "evidence"
	case strings.HasPrefix(path, "/api/v1/replay"):
		return "replay"
	case strings.HasPrefix(path, "/api/v1/conformance"):
		return "conformance"
	case strings.HasPrefix(path, "/api/v1/boundary"):
		return "boundary"
	case strings.HasPrefix(path, "/api/v1/mcp") || strings.HasPrefix(path, "/mcp"):
		return "mcp"
	case strings.HasPrefix(path, "/api/v1/sandbox"):
		return "sandbox"
	case strings.HasPrefix(path, "/api/v1/authz"):
		return "authz"
	case strings.HasPrefix(path, "/api/v1/budgets") || strings.HasPrefix(path, "/api/v1/budget"):
		return "budgets"
	case strings.HasPrefix(path, "/api/v1/approvals") || strings.HasPrefix(path, "/api/v1/kernel/approve"):
		return "approvals"
	case strings.HasPrefix(path, "/api/v1/trust"):
		return "trust"
	case strings.HasPrefix(path, "/api/v1/telemetry"):
		return "telemetry"
	case strings.HasPrefix(path, "/api/v1/harness") || strings.HasPrefix(path, "/api/v1/plans") || strings.HasPrefix(path, "/api/v1/gui"):
		return "harness"
	case strings.HasPrefix(path, "/api/v1/coexistence"):
		return "coexistence"
	case strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/version") || strings.HasPrefix(path, "/health") || strings.HasPrefix(path, "/.well-known"):
		return "developer"
	default:
		return "developer"
	}
}

func policyStatus(opts serverOptions) string {
	if strings.TrimSpace(opts.PolicyPath) == "" {
		return "unconfigured"
	}
	return "ready"
}

func statusFromStore(svc *Services) string {
	if svc != nil && svc.ReceiptStore != nil {
		return "ready"
	}
	return "unavailable"
}

func policyRecords(opts serverOptions) []map[string]string {
	if strings.TrimSpace(opts.PolicyPath) == "" {
		return []map[string]string{{"key": "policy", "value": "unconfigured"}}
	}
	return []map[string]string{
		{"key": "policy_path", "value": opts.PolicyPath},
		{"key": "server_mode", "value": opts.Mode},
	}
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func consoleScopes() []string {
	raw := strings.TrimSpace(os.Getenv("HELM_MCP_SCOPES"))
	if raw == "" {
		return []string{"tools:filesystem.read", "tools:git.status"}
	}
	parts := strings.Split(raw, ",")
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		if scope := strings.TrimSpace(part); scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}
