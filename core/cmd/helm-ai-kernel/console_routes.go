package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

// RegisterConsoleRoutes exposes the small platform state surface required by
// the HELM AI Kernel Console. The handler is read-only and derives state from kernel
// services; it does not create demonstration data.
func RegisterConsoleRoutes(mux *http.ServeMux, svc *Services, opts serverOptions) {
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

	mux.HandleFunc("/api/v1/console/surfaces", protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"surfaces": consoleSurfaceCatalog(),
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

func consoleSurfaceCatalog() []map[string]string {
	return []map[string]string{
		{"id": "overview", "source": "/api/v1/console/bootstrap"},
		{"id": "agents", "source": "/api/v1/console/surfaces/agents"},
		{"id": "actions", "source": "/api/v1/console/surfaces/actions"},
		{"id": "approvals", "source": "/api/v1/console/surfaces/approvals"},
		{"id": "policies", "source": "/api/v1/console/surfaces/policies"},
		{"id": "connectors", "source": "/mcp/v1/capabilities"},
		{"id": "receipts", "source": "/api/v1/receipts"},
		{"id": "evidence", "source": "/api/v1/evidence/soc2"},
		{"id": "replay", "source": "/api/v1/replay/verify"},
		{"id": "audit", "source": "/api/v1/console/surfaces/audit"},
		{"id": "developer", "source": "/api/v1/console/surfaces/developer"},
		{"id": "settings", "source": "/api/v1/console/surfaces/settings"},
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
		base["source"] = "/api/v1/kernel/approve"
		base["summary"] = map[string]any{
			"pending": 0,
			"reason":  "approval submission is wired; pending approval queue persistence is not configured in this runtime",
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
		base["source"] = "/api/v1/replay/verify"
		base["summary"] = map[string]any{
			"verifier":        "evidence bundle replay verifier",
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
			"go_version":  runtime.Version(),
			"console":     opts.Console,
			"console_dir": defaultConsoleDir(),
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
			{"key": "HELM_CONSOLE_DIR", "value": defaultConsoleDir()},
		}
	default:
		return nil, false
	}
	return base, true
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

func aggregateAgents(receipts []*contracts.Receipt) []map[string]any {
	type agentStats struct {
		ID       string
		Count    int
		LastSeen string
		Verdict  string
	}
	stats := map[string]*agentStats{}
	for _, receipt := range receipts {
		id := strings.TrimSpace(receipt.ExecutorID)
		if id == "" {
			id = "anonymous"
		}
		entry := stats[id]
		if entry == nil {
			entry = &agentStats{ID: id}
			stats[id] = entry
		}
		entry.Count++
		entry.Verdict = receipt.Status
		if receipt.Timestamp.After(parseTime(entry.LastSeen)) {
			entry.LastSeen = receipt.Timestamp.UTC().Format(time.RFC3339Nano)
		}
	}
	records := make([]map[string]any, 0, len(stats))
	for _, stat := range stats {
		records = append(records, map[string]any{
			"agent":     stat.ID,
			"receipts":  stat.Count,
			"last_seen": stat.LastSeen,
			"verdict":   stat.Verdict,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		return fmt.Sprint(records[i]["agent"]) < fmt.Sprint(records[j]["agent"])
	})
	return records
}

func aggregateActions(receipts []*contracts.Receipt) []map[string]any {
	type actionStats struct {
		Action string
		Count  int
		Last   string
		Hash   string
	}
	stats := map[string]*actionStats{}
	for _, receipt := range receipts {
		action := strings.TrimSpace(receipt.EffectID)
		if action == "" {
			action = metadataString(receipt.Metadata, "action")
		}
		if action == "" {
			action = "unknown"
		}
		entry := stats[action]
		if entry == nil {
			entry = &actionStats{Action: action}
			stats[action] = entry
		}
		entry.Count++
		entry.Last = receipt.Timestamp.UTC().Format(time.RFC3339Nano)
		entry.Hash = receipt.ReceiptID
	}
	records := make([]map[string]any, 0, len(stats))
	for _, stat := range stats {
		records = append(records, map[string]any{
			"action":       stat.Action,
			"count":        stat.Count,
			"last_seen":    stat.Last,
			"last_receipt": stat.Hash,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		return fmt.Sprint(records[i]["action"]) < fmt.Sprint(records[j]["action"])
	})
	return records
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func receiptAuditRecords(receipts []*contracts.Receipt) []map[string]any {
	records := make([]map[string]any, 0, len(receipts))
	for _, receipt := range receipts {
		records = append(records, map[string]any{
			"event_id":    stableConsoleEventID(receipt),
			"at":          receipt.Timestamp.UTC().Format(time.RFC3339Nano),
			"actor":       receipt.ExecutorID,
			"action":      receipt.EffectID,
			"status":      receipt.Status,
			"receipt_id":  receipt.ReceiptID,
			"decision_id": receipt.DecisionID,
		})
	}
	return records
}

func replayConsoleRecords(receipts []*contracts.Receipt) []map[string]any {
	records := make([]map[string]any, 0, len(receipts))
	for _, receipt := range receipts {
		records = append(records, map[string]any{
			"receipt_id":    receipt.ReceiptID,
			"executor_id":   receipt.ExecutorID,
			"lamport_clock": receipt.LamportClock,
			"prev_hash":     receipt.PrevHash,
			"signature":     receipt.Signature != "",
		})
	}
	return records
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

func stableConsoleEventID(receipt *contracts.Receipt) string {
	sum := sha256.Sum256([]byte(receipt.ReceiptID + receipt.DecisionID + receipt.Timestamp.UTC().Format(time.RFC3339Nano)))
	return "audit_" + fmt.Sprintf("%x", sum[:6])
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func listConsoleReceipts(ctx context.Context, svc *Services, limit int) []*contracts.Receipt {
	if svc == nil || svc.ReceiptStore == nil {
		return nil
	}
	receipts, err := svc.ReceiptStore.List(ctx, limit)
	if err != nil {
		return nil
	}
	return receipts
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

// RegisterConsoleStaticRoutes serves the built Console when explicitly enabled.
// API-like paths never fall through to index.html, which keeps broken contracts
// visible during development and production operation.
func RegisterConsoleStaticRoutes(mux *http.ServeMux, opts serverOptions) {
	if !opts.Console {
		return
	}
	dir := opts.ConsoleDir
	if dir == "" {
		dir = defaultConsoleDir()
	}
	indexPath := filepath.Join(dir, "index.html")
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if isReservedConsolePath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			api.WriteMethodNotAllowed(w)
			return
		}
		if _, err := os.Stat(indexPath); err != nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Console unavailable", "build apps/console before starting with --console")
			return
		}
		requestPath := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if requestPath == "." {
			http.ServeFile(w, r, indexPath)
			return
		}
		candidate := filepath.Join(dir, requestPath)
		if !strings.HasPrefix(candidate, filepath.Clean(dir)+string(os.PathSeparator)) {
			http.NotFound(w, r)
			return
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			http.ServeFile(w, r, candidate)
			return
		}
		http.ServeFile(w, r, indexPath)
	})
}

func defaultConsoleDir() string {
	if dir := strings.TrimSpace(os.Getenv("HELM_CONSOLE_DIR")); dir != "" {
		return dir
	}
	for _, candidate := range []string{
		filepath.Join("apps", "console", "dist"),
		filepath.Join("..", "apps", "console", "dist"),
		filepath.Join("/usr", "share", "helm", "console"),
	} {
		if _, err := os.Stat(filepath.Join(candidate, "index.html")); err == nil {
			return candidate
		}
	}
	return filepath.Join("apps", "console", "dist")
}

func isReservedConsolePath(path string) bool {
	reserved := []string{
		"/api/",
		"/v1/",
		"/mcp",
		"/.well-known/",
		"/health",
		"/healthz",
		"/version",
		"/readiness",
		"/startup",
	}
	for _, prefix := range reserved {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
