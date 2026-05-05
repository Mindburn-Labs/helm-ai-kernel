package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	mcppkg "github.com/Mindburn-Labs/helm-oss/core/pkg/mcp"
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
		jsonOutput bool
	)
	cmd.StringVar(&serverID, "server-id", "", "MCP server id to approve (REQUIRED)")
	cmd.StringVar(&approver, "approver", "", "Approver identity (REQUIRED)")
	cmd.StringVar(&receiptID, "receipt-id", "", "Approval ceremony receipt id (REQUIRED)")
	cmd.StringVar(&risk, "risk", "unknown", "Risk label: unknown, low, medium, high, critical")
	cmd.BoolVar(&jsonOutput, "json", false, "Output approval record as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if serverID == "" || approver == "" || receiptID == "" {
		fmt.Fprintln(stderr, "Error: --server-id, --approver, and --receipt-id are required")
		return 2
	}

	registry := mcppkg.NewQuarantineRegistry()
	if _, err := registry.Discover(context.Background(), mcppkg.DiscoverServerRequest{
		ServerID: serverID,
		Risk:     mcppkg.ServerRisk(risk),
	}); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	record, err := registry.Approve(context.Background(), mcppkg.ApprovalDecision{
		ServerID:          serverID,
		ApproverID:        approver,
		ApprovalReceiptID: receiptID,
		ApprovedAt:        time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(record)
		return 0
	}
	fmt.Fprintf(stdout, "Approved MCP server %s with receipt %s\n", record.ServerID, record.ApprovalReceiptID)
	return 0
}

func splitCommand(command string) []string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}
	return fields
}
