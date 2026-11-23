package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

func registerMCPContractRoutes(mux routeMux, surfaces *boundarypkg.SurfaceRegistry, mcpQuarantine *mcppkg.QuarantineRegistry) {
	mux.HandleFunc("/api/v1/mcp/registry", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeContractJSON(w, http.StatusOK, surfaces.ListMCPServers())
		case http.MethodPost:
			var req struct {
				ServerID  string   `json:"server_id"`
				Name      string   `json:"name"`
				Transport string   `json:"transport"`
				Endpoint  string   `json:"endpoint"`
				ToolNames []string `json:"tool_names"`
				Risk      string   `json:"risk"`
				Reason    string   `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				api.WriteBadRequest(w, "Invalid MCP registry request")
				return
			}
			record, err := mcpQuarantine.Discover(r.Context(), mcppkg.DiscoverServerRequest{
				ServerID:  req.ServerID,
				Name:      req.Name,
				Transport: req.Transport,
				Endpoint:  req.Endpoint,
				ToolNames: req.ToolNames,
				Risk:      mcppkg.ServerRisk(req.Risk),
				Reason:    req.Reason,
			})
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			if _, err := surfaces.PutMCPServer(record); err != nil {
				api.WriteInternalR(w, r, err)
				return
			}
			writeContractJSON(w, http.StatusAccepted, record)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/v1/mcp/registry/approve", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		// MCP approval authority must come from a credential-verified approval
		// ceremony, never from caller-supplied body fields. Do not parse the
		// opaque metadata first: it must never influence an approval result or
		// change the public 503 contract. Local CLI metadata is likewise not an
		// approval authority.
		api.WriteError(w, http.StatusServiceUnavailable, "MCP approval verification unavailable", boundarypkg.ErrApprovalVerificationUnavailable.Error())
	}))

	mux.HandleFunc("/api/v1/mcp/registry/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/mcp/registry/")
		serverID := suffix
		action := ""
		if strings.Contains(suffix, "/") {
			parts := strings.SplitN(suffix, "/", 2)
			serverID, action = parts[0], parts[1]
		}
		if serverID == "" {
			api.WriteBadRequest(w, "Invalid MCP server id")
			return
		}
		switch {
		case action == "" && r.Method == http.MethodGet:
			record, ok := surfaces.GetMCPServer(serverID)
			if !ok {
				api.WriteNotFound(w, "MCP server not found")
				return
			}
			writeContractJSON(w, http.StatusOK, record)
		case action == "approve" && r.Method == http.MethodPost:
			// See the collection endpoint: the path-scoped variant must also
			// reject without parsing or trusting caller-provided approval
			// fields.
			api.WriteError(w, http.StatusServiceUnavailable, "MCP approval verification unavailable", boundarypkg.ErrApprovalVerificationUnavailable.Error())
		case action == "revoke" && r.Method == http.MethodPost:
			var req struct {
				Reason string `json:"reason"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			record, err := mcpQuarantine.Revoke(r.Context(), serverID, req.Reason, time.Now().UTC())
			if err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
			if _, err := surfaces.PutMCPServer(record); err != nil {
				api.WriteInternalR(w, r, err)
				return
			}
			writeContractJSON(w, http.StatusOK, record)
		default:
			api.WriteMethodNotAllowed(w)
		}
	}))

	mux.HandleFunc("/api/v1/mcp/scan", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.MCPScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid MCP scan request")
			return
		}
		record, err := mcpQuarantine.Discover(r.Context(), mcppkg.DiscoverServerRequest{
			ServerID:  req.ServerID,
			Name:      req.Name,
			Transport: req.Transport,
			Endpoint:  req.Endpoint,
			ToolNames: req.ToolNames,
			Risk:      mcppkg.ServerRiskHigh,
			Reason:    "scan requires approval before dispatch",
		})
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		if _, err := surfaces.PutMCPServer(record); err != nil {
			api.WriteInternalR(w, r, err)
			return
		}
		writeContractJSON(w, http.StatusAccepted, contracts.MCPScanResult{
			ServerID:            record.ServerID,
			Risk:                string(record.Risk),
			State:               string(record.State),
			ToolCount:           len(record.ToolNames),
			Findings:            []string{"unknown MCP server defaults to quarantine"},
			RecommendedAction:   "approve or revoke after review",
			QuarantineRecordID:  record.ServerID,
			RequiresApproval:    true,
			SchemaPinRequired:   false,
			AuthorizationNeeded: true,
			ScannedAt:           time.Now().UTC(),
		})
	}))

	mux.HandleFunc("/api/v1/mcp/auth-profiles", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		writeContractJSON(w, http.StatusOK, surfaces.ListAuthProfiles())
	}))

	mux.HandleFunc("/api/v1/mcp/auth-profiles/", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		profileID := strings.TrimPrefix(r.URL.Path, "/api/v1/mcp/auth-profiles/")
		if profileID == "" || strings.Contains(profileID, "/") {
			api.WriteBadRequest(w, "Invalid MCP auth profile id")
			return
		}
		if r.Method != http.MethodPut {
			api.WriteMethodNotAllowed(w)
			return
		}
		var profile contracts.MCPAuthorizationProfile
		if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
			api.WriteBadRequest(w, "Invalid MCP auth profile request")
			return
		}
		profile.ProfileID = profileID
		sealed, err := surfaces.PutAuthProfile(profile)
		if err != nil {
			api.WriteBadRequest(w, err.Error())
			return
		}
		writeContractJSON(w, http.StatusOK, sealed)
	}))

	mux.HandleFunc("/api/v1/mcp/authorize-call", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req contracts.MCPAuthorizeCallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid MCP authorize-call request")
			return
		}
		catalog := mcppkg.NewToolCatalog()
		catalog.RegisterCommonTools()
		if req.ToolSchema != nil {
			if err := catalog.Register(r.Context(), mcppkg.ToolRef{
				Name:         req.ToolName,
				ServerID:     req.ServerID,
				Description:  "Discovered MCP tool with caller-supplied pinned schema",
				Schema:       req.ToolSchema,
				OutputSchema: req.OutputSchema,
			}); err != nil {
				api.WriteBadRequest(w, err.Error())
				return
			}
		}
		firewall := mcppkg.NewExecutionFirewall(catalog, mcpQuarantine, "api")
		record, err := firewall.AuthorizeToolCall(r.Context(), mcppkg.ToolCallAuthorization{
			ServerID:      req.ServerID,
			ToolName:      req.ToolName,
			ArgsHash:      req.ArgsHash,
			GrantedScopes: req.GrantedScopes,
			OAuthResource: req.OAuthResource,
			ReceiptID:     req.ReceiptID,
		})
		if err != nil {
			api.WriteInternalR(w, r, err)
			return
		}
		if _, putErr := surfaces.PutRecord(record); putErr != nil {
			api.WriteInternalR(w, r, putErr)
			return
		}
		status := http.StatusOK
		if record.Verdict != contracts.VerdictAllow {
			status = http.StatusForbidden
		}
		writeContractJSON(w, status, record)
	}))
}

func hydrateMCPQuarantine(ctx context.Context, registry *mcppkg.QuarantineRegistry, records []mcppkg.ServerQuarantineRecord) {
	for _, record := range records {
		record = mcppkg.FailClosedUnverifiedApproval(record)
		_, _ = registry.Discover(ctx, mcppkg.DiscoverServerRequest{
			ServerID:     record.ServerID,
			Name:         record.Name,
			Transport:    record.Transport,
			Endpoint:     record.Endpoint,
			ToolNames:    record.ToolNames,
			Risk:         record.Risk,
			DiscoveredAt: record.DiscoveredAt,
			ExpiresAt:    record.ExpiresAt,
			Reason:       record.Reason,
		})
		switch record.State {
		case mcppkg.QuarantineRevoked:
			_, _ = registry.Revoke(ctx, record.ServerID, record.Reason, record.RevokedAt)
		}
	}
}

func countMCPQuarantined(records []mcppkg.ServerQuarantineRecord) int {
	count := 0
	for _, record := range records {
		if record.State == mcppkg.QuarantineQuarantined {
			count++
		}
	}
	return count
}
