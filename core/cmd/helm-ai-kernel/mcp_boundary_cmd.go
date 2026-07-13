package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/readmodel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
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
	cmd.BoolVar(&requirePinnedSchema, "require-pinned-schema", true, "Deny tool calls unless the caller supplies the pinned schema hash")
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
		"server_id":             serverID,
		"policy_epoch":          policyEpoch,
		"require_pinned_schema": requirePinnedSchema,
		"quarantine_default":    "quarantined",
		"list_time_controls":    []string{"quarantine", "scope_filtering"},
		"call_time_controls":    []string{"quarantine", "scope_check", "schema_pin", "deny_receipt"},
		"receipt_binding":       []string{"policy_epoch", "mcp_server_id", "oauth_resource", "oauth_scopes", "args_hash", "record_hash"},
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

	var (
		serverID   string
		approver   string
		receiptID  string
		risk       string
		tools      string
		effects    string
		ttl        string
		reason     string
		jsonOutput bool
	)
	cmd.StringVar(&serverID, "server-id", "", "Requested MCP server id (approval verification unavailable)")
	cmd.StringVar(&approver, "approver", "local.operator", "Requested approver identity (not executable authority)")
	cmd.StringVar(&receiptID, "receipt-id", "", "Requested approval receipt id (not executable authority)")
	cmd.StringVar(&risk, "risk", "unknown", "Risk label: unknown, low, medium, high, critical")
	cmd.StringVar(&tools, "tools", "", "Requested tools (approval verification unavailable)")
	cmd.StringVar(&effects, "effects", "read", "Requested effects (approval verification unavailable)")
	cmd.StringVar(&ttl, "ttl", "15m", "Requested approval TTL (approval verification unavailable)")
	cmd.StringVar(&reason, "reason", "", "Requested approval reason (approval verification unavailable)")
	cmd.BoolVar(&jsonOutput, "json", false, "Reserved; approval verification is unavailable")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(stderr, "Error: %v\n", mcppkg.ErrApprovalVerificationUnavailable)
	return 2
}

func runMCPQuarantine(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp quarantine", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output threat reviews as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	catalog, err := loadLaunchpadCatalog(stderr)
	if err != nil {
		return 1
	}
	runs, _ := session.NewStore("").List()
	reviews := readmodel.MCPThreatReviews(catalog, runs)
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"threat_reviews": reviews})
		return 0
	}
	fmt.Fprintln(stdout, "MCP Threat Reviews")
	for _, review := range reviews {
		fmt.Fprintf(stdout, "  %s  app=%s state=%s proof=%s\n", review.ServerID, review.AppID, review.State, review.ProofStatus)
		fmt.Fprintf(stdout, "    %s\n", review.Summary)
		fmt.Fprintf(stdout, "    CLI: %s\n", review.CLIEquivalent)
	}
	return 0
}

func splitCommand(command string) []string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}
	return fields
}
