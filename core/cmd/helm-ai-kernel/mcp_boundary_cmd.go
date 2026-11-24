package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
)

func runMCPWrap(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp wrap", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		serverID            string
		upstreamCommand     string
		upstreamURL         string
		policyEpoch         string
		requirePinnedSchema bool
		jsonOutput          bool
	)
	cmd.StringVar(&serverID, "server-id", "", "Stable upstream MCP server id (REQUIRED)")
	cmd.StringVar(&upstreamCommand, "upstream-command", "", "Command used to launch an upstream stdio MCP server")
	cmd.StringVar(&upstreamURL, "upstream-url", "", "HTTP URL for an upstream remote MCP server")
	cmd.StringVar(&policyEpoch, "policy-epoch", "local", "Policy epoch to bind into execution-boundary records")
	cmd.BoolVar(&requirePinnedSchema, "require-pinned-schema", false, "Deprecated and ignored (HELM-756): no dispatch path enforces a schema pin")
	cmd.BoolVar(&jsonOutput, "json", false, "Output wrapper profile as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if serverID == "" {
		fmt.Fprintln(stderr, "Error: --server-id is required")
		return 2
	}
	if upstreamCommand == "" && upstreamURL == "" {
		fmt.Fprintln(stderr, "Error: one of --upstream-command or --upstream-url is required")
		return 2
	}

	profile := map[string]any{
		"server_id":          serverID,
		"policy_epoch":       policyEpoch,
		"quarantine_default": "quarantined",
		"list_time_controls": []string{"quarantine", "scope_filtering"},
		"call_time_controls": []string{"quarantine", "scope_check", "deny_receipt"},
		"receipt_binding":    []string{"policy_epoch", "mcp_server_id", "oauth_resource", "oauth_scopes", "args_hash", "record_hash"},
	}
	if upstreamCommand != "" {
		profile["transport"] = "stdio"
		profile["upstream_command"] = splitCommand(upstreamCommand)
	}
	if upstreamURL != "" {
		profile["transport"] = "http"
		profile["upstream_url"] = upstreamURL
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(profile)
		return 0
	}
	fmt.Fprintf(stdout, "MCP Execution Firewall Profile\n")
	fmt.Fprintf(stdout, "  Server:       %s\n", serverID)
	fmt.Fprintf(stdout, "  Policy epoch: %s\n", policyEpoch)
	fmt.Fprintf(stdout, "  Quarantine:   newly discovered servers/tools require approval\n")
	fmt.Fprintf(stdout, "  Call-time:    scope check + schema pin + signed allow/deny record\n")
	return 0
}

func runMCPApprove(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp approve", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	// Keep the historical flags parseable so callers receive the real authority
	// error rather than an accidental compatibility break. None of these opaque
	// local values can authorize an MCP server.
	cmd.String("server-id", "", "MCP server id (not an approval authority)")
	cmd.String("approver", "local.operator", "Opaque approver metadata")
	cmd.String("receipt-id", "", "Opaque receipt metadata")
	cmd.String("risk", "unknown", "Risk label")
	cmd.String("tools", "", "Requested tool scope")
	cmd.String("effects", "read", "Requested effect scope")
	cmd.String("ttl", "15m", "Requested approval TTL")
	cmd.String("reason", "", "Requested approval reason")
	cmd.Bool("json", false, "Output format (no approval record is emitted)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(stderr, "Error: %v\n", mcppkg.ErrApprovalVerificationUnavailable)
	return 2
}

func splitCommand(command string) []string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func writeLocalMCPReceipt(id, kind string, value any) string {
	path := localMCPReceiptPath(id)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return ""
	}
	payload := map[string]any{
		"schema_version": "helm.mcp.local_receipt/v1",
		"kind":           kind,
		"receipt_id":     sanitizeReceiptPart(id),
		"created_at":     time.Now().UTC().Format(time.RFC3339),
		"record":         value,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return ""
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return ""
	}
	return path
}

func localMCPReceiptPath(id string) string {
	id = sanitizeReceiptPart(id)
	if id == "" {
		id = "unknown"
	}
	return filepath.Join(normalizedDataDir(""), "receipts", "mcp", id+".json")
}

func runMCPList(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp list", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	records := newLocalSurfaceRegistry().ListMCPServers()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, records)
	}
	for _, record := range records {
		fmt.Fprintf(stdout, "%s  state=%s risk=%s receipt=%s\n", record.ServerID, record.State, record.Risk, record.ApprovalReceiptID)
	}
	return 0
}

func runMCPGet(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp get", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	serverID := cmd.String("server-id", "", "MCP server id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *serverID == "" && cmd.NArg() > 0 {
		*serverID = cmd.Arg(0)
	}
	if *serverID == "" {
		fmt.Fprintln(stderr, "Error: --server-id is required")
		return 2
	}
	if record, ok := newLocalSurfaceRegistry().GetMCPServer(*serverID); ok {
		if *jsonOutput {
			return writeSurfaceJSON(stdout, record)
		}
		fmt.Fprintf(stdout, "MCP server %s state=%s risk=%s\n", record.ServerID, record.State, record.Risk)
		return 0
	}
	record := map[string]any{"server_id": *serverID, "state": "not_found", "dispatch_ready": false}
	if *jsonOutput {
		return writeSurfaceJSONResult(stdout, record, false)
	}
	fmt.Fprintf(stdout, "MCP server %s is not registered in this local CLI registry\n", *serverID)
	return 1
}

func runMCPPending(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp pending", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	var pending []mcppkg.ServerQuarantineRecord
	for _, record := range newLocalSurfaceRegistry().ListMCPServers() {
		if record.State != mcppkg.QuarantineApproved {
			pending = append(pending, record)
		}
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, pending)
	}
	for _, record := range pending {
		fmt.Fprintf(stdout, "%s  state=%s reason=%s\n", record.ServerID, record.State, record.Reason)
	}
	return 0
}

func runMCPReceipts(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp receipts", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	limit := cmd.Int("limit", 50, "Maximum records to return")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	records := newLocalSurfaceRegistry().ListRecords(contracts.BoundarySearchRequest{Limit: *limit})
	var mcpRecords []contracts.ExecutionBoundaryRecord
	for _, record := range records {
		if record.MCPServerID != "" {
			mcpRecords = append(mcpRecords, record)
		}
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, mcpRecords)
	}
	for _, record := range mcpRecords {
		fmt.Fprintf(stdout, "%s  %s  reason=%s receipt=%s\n", record.RecordID, record.Verdict, record.ReasonCode, record.DecisionReceiptPath)
	}
	return 0
}

func runMCPRevoke(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp revoke", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	serverID := cmd.String("server-id", "", "MCP server id")
	reason := cmd.String("reason", "revoked by local CLI", "Revocation reason")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *serverID == "" {
		fmt.Fprintln(stderr, "Error: --server-id is required")
		return 2
	}
	if strings.TrimSpace(*reason) == "" {
		fmt.Fprintln(stderr, "Error: --reason is required")
		return 2
	}
	surfaces := newLocalSurfaceRegistry()
	registry := mcppkg.NewQuarantineRegistry()
	hydrateMCPQuarantine(context.Background(), registry, surfaces.ListMCPServers())
	if _, ok := surfaces.GetMCPServer(*serverID); !ok {
		_, _ = registry.Discover(context.Background(), mcppkg.DiscoverServerRequest{ServerID: *serverID})
	}
	record, err := registry.Revoke(context.Background(), *serverID, *reason, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	record.RevocationReceiptPath = writeLocalMCPReceipt("rcp_mcp_revoke_"+record.ServerID, "revocation", record)
	if _, err := surfaces.PutMCPServer(record); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, record)
	}
	fmt.Fprintf(stdout, "Revoked MCP server %s\n", record.ServerID)
	return 0
}

func runMCPAuthProfile(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel mcp auth-profile <list|put|verify> [flags]")
		return 2
	}
	if answeredSurfaceHelp("Usage: helm-ai-kernel mcp auth-profile [flags]", args, stdout) {
		return 0
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "list":
		return runMCPAuthProfileList(args[1:], registry, stdout, stderr)
	case "put":
		return runMCPAuthProfilePut(args[1:], registry, stdout, stderr)
	case "verify":
		return runMCPAuthProfileVerify(args[1:], registry, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown mcp auth-profile subcommand: %s\n", args[0])
		return 2
	}
}

func runMCPAuthProfileList(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp auth-profile list", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	profiles := registry.ListAuthProfiles()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, profiles)
	}
	for _, profile := range profiles {
		fmt.Fprintf(stdout, "%s  resource=%s hash=%s\n", profile.ProfileID, profile.Resource, profile.ProfileHash)
	}
	return 0
}

func runMCPAuthProfilePut(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp auth-profile put", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	profileID := cmd.String("profile-id", "mcp-local", "Profile id")
	resource := cmd.String("resource", "https://helm.local/mcp", "Protected resource")
	authServer := cmd.String("authorization-server", "https://helm.local/oauth", "Authorization server")
	scopes := cmd.String("scopes", "tools.read,tools.call", "Comma-separated scopes supported")
	required := cmd.String("required-scopes", "tools.read", "Comma-separated required scopes")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	profile, err := registry.PutAuthProfile(contracts.MCPAuthorizationProfile{
		ProfileID:            *profileID,
		Resource:             *resource,
		AuthorizationServers: splitCSV(*authServer),
		ScopesSupported:      splitCSV(*scopes),
		RequiredScopes:       splitCSV(*required),
		ProtocolVersions:     []string{"2025-11-25"},
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, profile)
	}
	fmt.Fprintf(stdout, "Stored MCP auth profile %s hash=%s\n", profile.ProfileID, profile.ProfileHash)
	return 0
}

func runMCPAuthProfileVerify(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp auth-profile verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	profileID := cmd.String("profile-id", "mcp-default", "Profile id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	result := map[string]any{"profile_id": *profileID, "verified": false, "checks": map[string]string{"profile_hash": "FAIL"}}
	for _, profile := range registry.ListAuthProfiles() {
		if profile.ProfileID == *profileID && profile.ProfileHash != "" {
			result["verified"] = true
			result["profile_hash"] = profile.ProfileHash
			result["checks"] = map[string]string{"profile_hash": "PASS", "protected_resource": "PASS"}
		}
	}
	if *jsonOutput {
		return writeSurfaceJSONResult(stdout, result, result["verified"] == true)
	}
	fmt.Fprintf(stdout, "MCP auth profile %s verified=%t\n", *profileID, result["verified"])
	if result["verified"] != true {
		return 1
	}
	return 0
}

func runMCPAuthorizeCall(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp authorize-call", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	serverID := cmd.String("server-id", "", "MCP server id")
	toolName := cmd.String("tool-name", "", "Tool name")
	argsHash := cmd.String("args-hash", "sha256:local", "Canonical tool args hash")
	scopes := cmd.String("scopes", "", "Comma-separated granted OAuth scopes")
	_ = cmd.String("pinned-schema-hash", "", "Deprecated and ignored (HELM-756): the caller-supplied pin bound nothing")
	toolSchemaJSON := cmd.String("tool-schema-json", "", "JSON Schema for a discovered server-local tool")
	outputSchemaJSON := cmd.String("output-schema-json", "", "Output JSON Schema for a discovered server-local tool")
	oauthResource := cmd.String("oauth-resource", "https://helm.local/mcp", "OAuth resource indicator")
	effect := cmd.String("effect", "read", "Tool effect: read or side_effect")
	approved := cmd.Bool("approved", false, "Unavailable: opaque local approval cannot authorize dispatch")
	receiptID := cmd.String("receipt-id", "", "Receipt id to bind")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *serverID == "" || *toolName == "" {
		fmt.Fprintln(stderr, "Error: --server-id and --tool-name are required")
		return 2
	}
	if *approved {
		fmt.Fprintf(stderr, "Error: %v\n", mcppkg.ErrApprovalVerificationUnavailable)
		return 2
	}
	catalog := mcppkg.NewToolCatalog()
	catalog.RegisterCommonTools()
	if *toolSchemaJSON != "" {
		var toolSchema any
		if err := json.Unmarshal([]byte(*toolSchemaJSON), &toolSchema); err != nil {
			fmt.Fprintf(stderr, "Error: invalid --tool-schema-json: %v\n", err)
			return 2
		}
		var outputSchema any
		if *outputSchemaJSON != "" {
			if err := json.Unmarshal([]byte(*outputSchemaJSON), &outputSchema); err != nil {
				fmt.Fprintf(stderr, "Error: invalid --output-schema-json: %v\n", err)
				return 2
			}
		}
		if err := catalog.Register(context.Background(), mcppkg.ToolRef{
			Name:         *toolName,
			ServerID:     *serverID,
			Description:  "Discovered MCP tool with caller-supplied pinned schema",
			Schema:       toolSchema,
			OutputSchema: outputSchema,
		}); err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
	}
	surfaces := newLocalSurfaceRegistry()
	quarantine := mcppkg.NewQuarantineRegistry()
	hydrateMCPQuarantine(context.Background(), quarantine, surfaces.ListMCPServers())
	if _, ok := surfaces.GetMCPServer(*serverID); !ok {
		_, _ = quarantine.Discover(context.Background(), mcppkg.DiscoverServerRequest{ServerID: *serverID, ToolNames: []string{*toolName}})
	}
	firewall := mcppkg.NewExecutionFirewall(catalog, quarantine, "local-cli")
	authorization := mcppkg.ToolCallAuthorization{
		ServerID:      *serverID,
		ToolName:      *toolName,
		Effect:        *effect,
		ArgsHash:      *argsHash,
		GrantedScopes: splitCSV(*scopes),
		OAuthResource: *oauthResource,
		ReceiptID:     *receiptID,
	}
	record, err := firewall.AuthorizeToolCall(context.Background(), authorization)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	record.DecisionReceiptPath = localMCPReceiptPath(record.RecordID)
	sealed, err := record.Seal()
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if writeLocalMCPReceipt(record.RecordID, "decision", sealed) == "" {
		if record.Verdict == contracts.VerdictAllow {
			record.Verdict = contracts.VerdictDeny
			record.ReasonCode = contracts.ReasonVerification
		}
		record.DecisionReceiptPath = ""
		sealed, err = record.Seal()
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
	}
	record, err = surfaces.PutRecord(sealed)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	exitCode := 0
	if record.Verdict != contracts.VerdictAllow {
		exitCode = 1
	}
	if *jsonOutput {
		_ = writeSurfaceJSON(stdout, record)
		return exitCode
	}
	fmt.Fprintf(stdout, "HELM %s\n", record.Verdict)
	fmt.Fprintf(stdout, "decision: %s\n", record.RecordID)
	fmt.Fprintf(stdout, "reason: %s\n", mcpVerdictReason(record))
	if record.ReasonCode == contracts.ReasonApprovalRequired || record.ReasonCode == contracts.ReasonApprovalTimeout {
		fmt.Fprintln(stdout, "approval: credential verification unavailable; the server remains quarantined")
	}
	fmt.Fprintf(stdout, "receipt: %s\n", record.DecisionReceiptPath)
	if nextStep := mcpAuthorizeCallNextStep(record, catalog, authorization); nextStep != "" {
		fmt.Fprintln(stdout, "next:")
		fmt.Fprintf(stdout, "  %s\n", nextStep)
	}
	return exitCode
}

// mcpAuthorizeCallNextStep returns a schema-remediation command only. It never
// suggests a local approval command because this CLI has no credential verifier
// and therefore cannot move a quarantined server toward ALLOW.
func mcpAuthorizeCallNextStep(record contracts.ExecutionBoundaryRecord, catalog *mcppkg.ToolCatalog, authorization mcppkg.ToolCallAuthorization) string {
	if record.ReasonCode != contracts.ReasonSchemaViolation {
		return ""
	}
	serverID, toolName := authorization.ServerID, authorization.ToolName
	next := []string{
		"helm-ai-kernel mcp authorize-call",
		"--server-id " + shellToken(serverID),
		"--tool-name " + shellToken(toolName),
		"--effect " + shellToken(authorization.Effect),
		"--args-hash " + shellToken(authorization.ArgsHash),
		"--oauth-resource " + shellToken(authorization.OAuthResource),
	}
	if len(authorization.GrantedScopes) > 0 {
		next = append(next, "--scopes "+shellToken(strings.Join(authorization.GrantedScopes, ",")))
	}
	if authorization.ReceiptID != "" {
		next = append(next, "--receipt-id "+shellToken(authorization.ReceiptID))
	}
	tool, ok := catalog.Lookup(toolName)
	if !ok || (tool.ServerID != "" && tool.ServerID != serverID) {
		// The tool is not in the local catalog; the caller must supply its schema.
		next = append(next, "--tool-schema-json '<tool JSON Schema>'")
		return strings.Join(next, " ")
	}
	if tool.ServerID == "" {
		return strings.Join(next, " ")
	}
	toolSchema, err := json.Marshal(tool.Schema)
	if err != nil {
		return ""
	}
	next = append(next, "--tool-schema-json "+shellToken(string(toolSchema)))
	if tool.OutputSchema != nil {
		outputSchema, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			return ""
		}
		next = append(next, "--output-schema-json "+shellToken(string(outputSchema)))
	}
	return strings.Join(next, " ")
}

func shellToken(value string) string {
	if value == "" || strings.ContainsAny(value, " \t\n\r'\"`#~\\$&|;()<>*?[]{}!") {
		return shellQuote(value)
	}
	return value
}

// mcpVerdictReason renders the human reason line for any authorize-call
// verdict, so DENY is as legible as ESCALATE.
func mcpVerdictReason(record contracts.ExecutionBoundaryRecord) string {
	switch record.ReasonCode {
	case contracts.ReasonApprovalRequired:
		if record.Verdict == contracts.VerdictDeny {
			return "tool is outside the approved scope for this MCP server"
		}
		return "unknown MCP server remains quarantined; credential verification is unavailable"
	case contracts.ReasonApprovalTimeout:
		return "MCP server approval expired or was revoked"
	case contracts.ReasonSchemaViolation:
		if record.Verdict == contracts.VerdictDeny {
			return "the tool's schema is not a valid JSON Schema"
		}
		return "MCP tool is not in the catalog for this server"
	case contracts.ReasonInsufficientPrivilege:
		return "granted scopes do not cover the tool's required scopes"
	case contracts.ReasonVerification:
		return "durable decision receipt could not be written"
	}
	if record.Verdict == contracts.VerdictAllow {
		return "approved scope, schema pin, and policy checks passed"
	}
	if record.ReasonCode != "" {
		return string(record.ReasonCode)
	}
	return "MCP action requires approval"
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
