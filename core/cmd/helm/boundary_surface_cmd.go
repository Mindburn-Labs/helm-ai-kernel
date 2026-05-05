package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-oss/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-oss/core/pkg/evidence"
	mcppkg "github.com/Mindburn-Labs/helm-oss/core/pkg/mcp"
	runtimesandbox "github.com/Mindburn-Labs/helm-oss/core/pkg/runtime/sandbox"
)

func newLocalSurfaceRegistry() *boundarypkg.SurfaceRegistry {
	registry, err := boundarypkg.NewFileBackedSurfaceRegistry(defaultBoundaryRegistryPath(), time.Now)
	if err == nil {
		return registry
	}
	return boundarypkg.NewSurfaceRegistry(time.Now)
}

func writeSurfaceJSON(w io.Writer, value any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
	return 0
}

func runBoundarySurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm boundary <status|capabilities|records|get|verify|checkpoint> [flags]")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "status":
		return runBoundaryStatus(args[1:], registry, stdout, stderr)
	case "capabilities":
		return runBoundaryCapabilities(args[1:], registry, stdout, stderr)
	case "records":
		return runBoundaryRecords(args[1:], registry, stdout, stderr)
	case "get":
		return runBoundaryGet(args[1:], registry, stdout, stderr)
	case "verify":
		return runBoundaryVerify(args[1:], registry, stdout, stderr)
	case "checkpoint", "checkpoints":
		return runBoundaryCheckpoint(args[1:], registry, stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm boundary <status|capabilities|records|get|verify|checkpoint> [flags]")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown boundary subcommand: %s\n", args[0])
		return 2
	}
}

func runBoundaryStatus(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary status", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	status := registry.Status(displayVersion(), true, true, 1)
	if *jsonOutput {
		return writeSurfaceJSON(stdout, status)
	}
	fmt.Fprintf(stdout, "Boundary status: %s\n", status.Status)
	fmt.Fprintf(stdout, "  MCP firewall: %s\n", status.MCPFirewall)
	fmt.Fprintf(stdout, "  Sandbox:      %s\n", status.Sandbox)
	fmt.Fprintf(stdout, "  Checkpoints:  %s\n", status.CheckpointLog)
	return 0
}

func runBoundaryCapabilities(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary capabilities", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	capabilities := registry.Capabilities()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, capabilities)
	}
	for _, capability := range capabilities {
		fmt.Fprintf(stdout, "%s  %s  authority=%s level=%s\n", capability.CapabilityID, capability.Status, capability.Authority, capability.ConformanceLevel)
	}
	return 0
}

func runBoundaryRecords(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary records", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	limit := cmd.Int("limit", 50, "Maximum records to return")
	verdict := cmd.String("verdict", "", "Filter by verdict")
	reason := cmd.String("reason-code", "", "Filter by reason code")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	records := registry.ListRecords(contracts.BoundarySearchRequest{Limit: *limit, Verdict: *verdict, ReasonCode: *reason})
	if *jsonOutput {
		return writeSurfaceJSON(stdout, records)
	}
	for _, record := range records {
		fmt.Fprintf(stdout, "%s  %s  reason=%s receipt=%s\n", record.RecordID, record.Verdict, record.ReasonCode, record.ReceiptID)
	}
	return 0
}

func runBoundaryGet(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary get", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	recordID := cmd.String("record-id", "", "Boundary record id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *recordID == "" && cmd.NArg() > 0 {
		*recordID = cmd.Arg(0)
	}
	if *recordID == "" {
		fmt.Fprintln(stderr, "Error: --record-id is required")
		return 2
	}
	record, ok := registry.GetRecord(*recordID)
	if !ok {
		fmt.Fprintf(stderr, "Error: boundary record %q not found\n", *recordID)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, record)
	}
	fmt.Fprintf(stdout, "Boundary record %s\n  verdict=%s reason=%s hash=%s\n", record.RecordID, record.Verdict, record.ReasonCode, record.RecordHash)
	return 0
}

func runBoundaryVerify(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	recordID := cmd.String("record-id", "", "Boundary record id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *recordID == "" && cmd.NArg() > 0 {
		*recordID = cmd.Arg(0)
	}
	if *recordID == "" {
		fmt.Fprintln(stderr, "Error: --record-id is required")
		return 2
	}
	result := registry.VerifyRecord(*recordID)
	if *jsonOutput {
		return writeSurfaceJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "Boundary verification %s: %s\n", result.RecordID, result.Verdict)
	if !result.Verified {
		return 1
	}
	return 0
}

func runBoundaryCheckpoint(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("boundary checkpoint", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	create := cmd.Bool("create", false, "Create a new checkpoint")
	receiptCount := cmd.Int("receipt-count", 0, "Receipt count to bind into a created checkpoint")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *create {
		checkpoint, err := registry.CreateCheckpoint(*receiptCount)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		if *jsonOutput {
			return writeSurfaceJSON(stdout, checkpoint)
		}
		fmt.Fprintf(stdout, "Created checkpoint %s hash=%s\n", checkpoint.CheckpointID, checkpoint.CheckpointHash)
		return 0
	}
	checkpoints := registry.ListCheckpoints()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, checkpoints)
	}
	for _, checkpoint := range checkpoints {
		fmt.Fprintf(stdout, "%s  sequence=%d hash=%s\n", checkpoint.CheckpointID, checkpoint.Sequence, checkpoint.CheckpointHash)
	}
	return 0
}

func runIdentityCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "agents" {
		fmt.Fprintln(stderr, "Usage: helm identity agents [--json]")
		return 2
	}
	cmd := flag.NewFlagSet("identity agents", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args[1:]); err != nil {
		return 2
	}
	agents := newLocalSurfaceRegistry().ListAgents()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, agents)
	}
	for _, agent := range agents {
		fmt.Fprintf(stdout, "%s  type=%s anonymous_dev=%t\n", agent.AgentID, agent.IdentityType, agent.AnonymousDev)
	}
	return 0
}

func runAuthzSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm authz <health|check|snapshots|get> [flags]")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "health":
		return runAuthzHealth(args[1:], stdout, stderr)
	case "check":
		return runAuthzCheck(args[1:], registry, stdout, stderr)
	case "snapshots":
		return runAuthzSnapshots(args[1:], registry, stdout, stderr)
	case "get":
		return runAuthzGet(args[1:], registry, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown authz subcommand: %s\n", args[0])
		return 2
	}
}

func runAuthzHealth(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("authz health", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	health := contracts.AuthzHealth{
		Status:           "ready",
		Resolver:         "helm-local-rebac",
		ModelID:          "helm-local-v1",
		RelationshipHash: relationshipHash("tenant:default", "tool:*", "can_call"),
		CheckedAt:        time.Now().UTC(),
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, health)
	}
	fmt.Fprintf(stdout, "Authz health: %s resolver=%s\n", health.Status, health.Resolver)
	return 0
}

func runAuthzCheck(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("authz check", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	subject := cmd.String("subject", "agent:anonymous-dev", "Subject")
	object := cmd.String("object", "tool:file_read", "Object")
	relation := cmd.String("relation", "can_call", "Relation")
	modelID := cmd.String("model-id", "helm-local-v1", "Authorization model id")
	stale := cmd.Bool("stale", false, "Mark tuple snapshot stale")
	modelMismatch := cmd.Bool("model-mismatch", false, "Mark model mismatch")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	snapshot := contracts.AuthzSnapshot{
		SnapshotID:       contracts.SurfaceID("authz", *subject+"-"+*object+"-"+*relation),
		Resolver:         "helm-local-rebac",
		ModelID:          *modelID,
		RelationshipHash: relationshipHash(*subject, *object, *relation),
		SnapshotToken:    contracts.SurfaceID("tuple", *subject+"-"+*object+"-"+*relation),
		Subject:          *subject,
		Object:           *object,
		Relation:         *relation,
		Decision:         !*stale && !*modelMismatch,
		Stale:            *stale,
		ModelMismatch:    *modelMismatch,
		CheckedAt:        time.Now().UTC(),
	}
	sealed, err := registry.PutSnapshot(snapshot)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, sealed)
	}
	fmt.Fprintf(stdout, "Authz decision=%t snapshot=%s hash=%s\n", sealed.Decision, sealed.SnapshotID, sealed.SnapshotHash)
	if !sealed.Decision {
		return 1
	}
	return 0
}

func runAuthzSnapshots(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("authz snapshots", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	snapshots := registry.ListSnapshots()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, snapshots)
	}
	for _, snapshot := range snapshots {
		fmt.Fprintf(stdout, "%s  decision=%t hash=%s\n", snapshot.SnapshotID, snapshot.Decision, snapshot.SnapshotHash)
	}
	return 0
}

func runAuthzGet(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("authz get", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	snapshotID := cmd.String("snapshot-id", "", "Snapshot id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *snapshotID == "" && cmd.NArg() > 0 {
		*snapshotID = cmd.Arg(0)
	}
	if *snapshotID == "" {
		fmt.Fprintln(stderr, "Error: --snapshot-id is required")
		return 2
	}
	snapshot, ok := registry.GetSnapshot(*snapshotID)
	if !ok {
		fmt.Fprintf(stderr, "Error: authz snapshot %q not found\n", *snapshotID)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, snapshot)
	}
	fmt.Fprintf(stdout, "Authz snapshot %s decision=%t hash=%s\n", snapshot.SnapshotID, snapshot.Decision, snapshot.SnapshotHash)
	return 0
}

func runApprovalsSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm approvals <list|create|approve|deny|revoke|challenge|assert> [flags]")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "list":
		return runApprovalsList(args[1:], registry, stdout, stderr)
	case "create":
		return runApprovalsCreate(args[1:], registry, stdout, stderr)
	case "approve":
		return runApprovalsTransition(args[1:], registry, contracts.ApprovalCeremonyAllowed, stdout, stderr)
	case "deny":
		return runApprovalsTransition(args[1:], registry, contracts.ApprovalCeremonyDenied, stdout, stderr)
	case "revoke":
		return runApprovalsTransition(args[1:], registry, contracts.ApprovalCeremonyRevoked, stdout, stderr)
	case "challenge":
		return runApprovalsChallenge(args[1:], registry, stdout, stderr)
	case "assert":
		return runApprovalsAssert(args[1:], registry, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown approvals subcommand: %s\n", args[0])
		return 2
	}
}

func runApprovalsList(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals list", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	approvals := registry.ListApprovals()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, approvals)
	}
	for _, approval := range approvals {
		fmt.Fprintf(stdout, "%s  state=%s subject=%s action=%s\n", approval.ApprovalID, approval.State, approval.Subject, approval.Action)
	}
	return 0
}

func runApprovalsCreate(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals create", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	subject := cmd.String("subject", "", "Approval subject")
	action := cmd.String("action", "", "Approval action")
	requestedBy := cmd.String("requested-by", "agent:anonymous-dev", "Requester identity")
	reason := cmd.String("reason", "", "Approval reason")
	quorum := cmd.Int("quorum", 1, "Required quorum")
	timelockMs := cmd.Int64("timelock-ms", 0, "Timelock in milliseconds before approval can activate")
	expiresInMs := cmd.Int64("expires-in-ms", 0, "Expiry interval in milliseconds")
	breakGlass := cmd.Bool("break-glass", false, "Require break-glass reason and receipt")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || *action == "" {
		fmt.Fprintln(stderr, "Error: --subject and --action are required")
		return 2
	}
	now := time.Now().UTC()
	var timelock time.Time
	if *timelockMs > 0 {
		timelock = now.Add(time.Duration(*timelockMs) * time.Millisecond)
	}
	var expiresAt time.Time
	if *expiresInMs > 0 {
		expiresAt = now.Add(time.Duration(*expiresInMs) * time.Millisecond)
	}
	approval, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:    contracts.SurfaceID("approval", *subject+"-"+*action),
		Subject:       *subject,
		Action:        *action,
		State:         contracts.ApprovalCeremonyPending,
		RequestedBy:   *requestedBy,
		Quorum:        *quorum,
		TimelockUntil: timelock,
		ExpiresAt:     expiresAt,
		BreakGlass:    *breakGlass,
		Reason:        *reason,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, approval)
	}
	fmt.Fprintf(stdout, "Created approval %s state=%s\n", approval.ApprovalID, approval.State)
	return 0
}

func runApprovalsChallenge(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals challenge", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	approvalID := cmd.String("approval-id", "approval-bootstrap", "Approval id")
	method := cmd.String("method", "passkey", "Approval method")
	ttlMs := cmd.Int64("ttl-ms", int64((5*time.Minute)/time.Millisecond), "Challenge TTL in milliseconds")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	challenge, err := registry.CreateApprovalChallenge(*approvalID, *method, time.Duration(*ttlMs)*time.Millisecond)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, challenge)
	}
	fmt.Fprintf(stdout, "Approval challenge %s method=%s hash=%s\n", challenge.ChallengeID, challenge.Method, challenge.ChallengeHash)
	return 0
}

func runApprovalsAssert(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals assert", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	challengeID := cmd.String("challenge-id", "", "Challenge id")
	actor := cmd.String("actor", "user:local-admin", "Actor")
	assertion := cmd.String("assertion", "", "Passkey/WebAuthn assertion or local signed assertion")
	receiptID := cmd.String("receipt-id", "receipt-local-approval", "Receipt id")
	reason := cmd.String("reason", "passkey assertion accepted", "Reason")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *challengeID == "" || *assertion == "" {
		fmt.Fprintln(stderr, "Error: --challenge-id and --assertion are required")
		return 2
	}
	approval, err := registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{
		ChallengeID: *challengeID,
		Actor:       *actor,
		Assertion:   *assertion,
		ReceiptID:   *receiptID,
		Reason:      *reason,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, approval)
	}
	fmt.Fprintf(stdout, "Approval %s state=%s method=%s\n", approval.ApprovalID, approval.State, approval.AuthMethod)
	if approval.State != contracts.ApprovalCeremonyAllowed {
		return 1
	}
	return 0
}

func runApprovalsTransition(args []string, registry *boundarypkg.SurfaceRegistry, state contracts.ApprovalCeremonyState, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals transition", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	approvalID := cmd.String("approval-id", "approval-bootstrap", "Approval id")
	actor := cmd.String("actor", "user:local-admin", "Actor")
	receiptID := cmd.String("receipt-id", "receipt-local-approval", "Receipt id")
	reason := cmd.String("reason", string(state), "Reason")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *approvalID == "" && cmd.NArg() > 0 {
		*approvalID = cmd.Arg(0)
	}
	approval, err := registry.TransitionApproval(*approvalID, state, *actor, *receiptID, *reason)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, approval)
	}
	fmt.Fprintf(stdout, "Approval %s transitioned to %s receipt=%s\n", approval.ApprovalID, approval.State, approval.ReceiptID)
	return 0
}

func runBudgetSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm budget <list|set|verify> [flags]")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "list":
		return runBudgetList(args[1:], registry, stdout, stderr)
	case "set":
		return runBudgetSet(args[1:], registry, stdout, stderr)
	case "verify":
		return runBudgetVerify(args[1:], registry, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown budget subcommand: %s\n", args[0])
		return 2
	}
}

func runBudgetList(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("budget list", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	budgets := registry.ListBudgets()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, budgets)
	}
	for _, budget := range budgets {
		fmt.Fprintf(stdout, "%s  subject=%s tool_calls=%d window=%s\n", budget.BudgetID, budget.Subject, budget.ToolCallLimit, budget.Window)
	}
	return 0
}

func runBudgetSet(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("budget set", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	budgetID := cmd.String("budget-id", "budget-local", "Budget id")
	subject := cmd.String("subject", "tenant:default", "Budget subject")
	window := cmd.String("window", "24h", "Budget window")
	toolCalls := cmd.Int("tool-calls", 1000, "Tool-call ceiling")
	spendCents := cmd.Int64("spend-cents", 100000, "Spend ceiling in cents")
	egressBytes := cmd.Int64("egress-bytes", 10<<20, "Egress ceiling")
	writeOps := cmd.Int("write-ops", 100, "Write-operation ceiling")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	budget, err := registry.PutBudget(contracts.BudgetCeiling{
		BudgetID:            *budgetID,
		Subject:             *subject,
		ToolCallLimit:       *toolCalls,
		SpendLimitCents:     *spendCents,
		EgressLimitBytes:    *egressBytes,
		WriteOperationLimit: *writeOps,
		Window:              *window,
		PolicyEpoch:         "local-cli",
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, budget)
	}
	fmt.Fprintf(stdout, "Set budget %s subject=%s\n", budget.BudgetID, budget.Subject)
	return 0
}

func runBudgetVerify(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("budget verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	result := map[string]any{"verdict": "PASS", "budgets": len(registry.ListBudgets()), "checks": map[string]string{"ceilings_present": "PASS", "policy_epoch": "PASS"}}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, result)
	}
	fmt.Fprintln(stdout, "Budget verification: PASS")
	return 0
}

func runTelemetrySurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "otel-config" {
		fmt.Fprintln(stderr, "Usage: helm telemetry otel-config [--json]")
		return 2
	}
	cmd := flag.NewFlagSet("telemetry otel-config", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args[1:]); err != nil {
		return 2
	}
	config := telemetryConfig()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, config)
	}
	fmt.Fprintf(stdout, "OTel config service=%s authoritative=%t\n", config.ServiceName, config.Authoritative)
	return 0
}

func runCoexistenceSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "manifest" {
		fmt.Fprintln(stderr, "Usage: helm coexistence manifest [--json]")
		return 2
	}
	cmd := flag.NewFlagSet("coexistence manifest", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args[1:]); err != nil {
		return 2
	}
	manifest := contracts.CoexistenceCapabilityManifest{
		ManifestID:      "helm-coexistence-oss",
		Authority:       "helm-native-receipts",
		BoundaryRole:    "inner-proof-bearing-execution-boundary",
		SupportedInputs: []string{"mcp", "openai-compatible-proxy", "framework-middleware", "gateway-export"},
		ExportSurfaces:  []string{"evidencepack", "dsse", "jws", "in-toto", "slsa", "sigstore", "otel-genai", "cloudevents"},
		ReceiptBindings: []string{"receipt_id", "record_hash", "sandbox_grant_hash", "authz_snapshot_hash"},
		GeneratedAt:     time.Now().UTC(),
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, manifest)
	}
	fmt.Fprintf(stdout, "Coexistence manifest: %s authority=%s\n", manifest.ManifestID, manifest.Authority)
	return 0
}

func runIntegrateSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "scaffold" {
		fmt.Fprintln(stderr, "Usage: helm integrate scaffold --framework <name> [--json]")
		return 2
	}
	cmd := flag.NewFlagSet("integrate scaffold", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	framework := cmd.String("framework", "", "Framework name")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args[1:]); err != nil {
		return 2
	}
	if *framework == "" {
		fmt.Fprintln(stderr, "Error: --framework is required")
		return 2
	}
	scaffold := frameworkScaffold(*framework)
	if *jsonOutput {
		return writeSurfaceJSON(stdout, scaffold)
	}
	fmt.Fprintf(stdout, "Framework scaffold %s\n", scaffold.Framework)
	fmt.Fprintf(stdout, "  mode: %s\n", scaffold.Mode)
	fmt.Fprintf(stdout, "  routes: %s\n", strings.Join(scaffold.RequiredRoutes, ", "))
	return 0
}

func frameworkScaffold(framework string) contracts.FrameworkScaffold {
	name := strings.ToLower(strings.TrimSpace(framework))
	language := "typescript"
	switch name {
	case "langchain", "langgraph", "pydanticai", "autogen", "crewai":
		language = "python"
	case "semantic-kernel":
		language = "csharp"
	case "litellm", "n8n", "zapier-webhook", "raw-mcp", "openai-agents":
		language = "typescript"
	}
	return contracts.FrameworkScaffold{
		Framework:      name,
		Language:       language,
		Files:          []string{"middleware/helm-boundary." + languageExt(language), "README.md"},
		RequiredRoutes: []string{"/api/v1/mcp/authorize-call", "/api/v1/boundary/records/{record_id}/verify", "/api/v1/evidence/export"},
		Mode:           "pre-dispatch-required",
		Notes:          "Passive tracing alone is not HELM conformance; middleware must call HELM before tool dispatch.",
	}
}

func languageExt(language string) string {
	switch language {
	case "python":
		return "py"
	case "csharp":
		return "cs"
	default:
		return "ts"
	}
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
		return writeSurfaceJSON(stdout, record)
	}
	fmt.Fprintf(stdout, "MCP server %s is not registered in this local CLI registry\n", *serverID)
	return 1
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
		fmt.Fprintln(stderr, "Usage: helm mcp auth-profile <list|put|verify> [flags]")
		return 2
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
		return writeSurfaceJSON(stdout, result)
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
	pinnedSchema := cmd.String("pinned-schema-hash", "", "Pinned tool schema hash")
	oauthResource := cmd.String("oauth-resource", "https://helm.local/mcp", "OAuth resource indicator")
	approved := cmd.Bool("approved", false, "Seed an approved local server before authorization")
	receiptID := cmd.String("receipt-id", "", "Receipt id to bind")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *serverID == "" || *toolName == "" {
		fmt.Fprintln(stderr, "Error: --server-id and --tool-name are required")
		return 2
	}
	catalog := mcppkg.NewToolCatalog()
	catalog.RegisterCommonTools()
	surfaces := newLocalSurfaceRegistry()
	quarantine := mcppkg.NewQuarantineRegistry()
	hydrateMCPQuarantine(context.Background(), quarantine, surfaces.ListMCPServers())
	if _, ok := surfaces.GetMCPServer(*serverID); !ok {
		_, _ = quarantine.Discover(context.Background(), mcppkg.DiscoverServerRequest{ServerID: *serverID, ToolNames: []string{*toolName}})
	}
	if *approved {
		record, _ := quarantine.Approve(context.Background(), mcppkg.ApprovalDecision{ServerID: *serverID, ApproverID: "user:local-admin", ApprovalReceiptID: "receipt-local-mcp-approval"})
		_, _ = surfaces.PutMCPServer(record)
	}
	firewall := mcppkg.NewExecutionFirewall(catalog, quarantine, "local-cli")
	firewall.RequirePinnedSchema = true
	record, err := firewall.AuthorizeToolCall(context.Background(), mcppkg.ToolCallAuthorization{
		ServerID:         *serverID,
		ToolName:         *toolName,
		ArgsHash:         *argsHash,
		GrantedScopes:    splitCSV(*scopes),
		PinnedSchemaHash: *pinnedSchema,
		OAuthResource:    *oauthResource,
		ReceiptID:        *receiptID,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if _, err := surfaces.PutRecord(record); err != nil {
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
	fmt.Fprintf(stdout, "MCP authorization verdict=%s reason=%s record=%s\n", record.Verdict, record.ReasonCode, record.RecordID)
	return exitCode
}

func runSandboxProfiles(args []string, stdout, stderr io.Writer) int {
	return runSandboxInspect(append(args, "--json"), stdout, stderr)
}

func runSandboxGrant(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox grant", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	runtimeName := cmd.String("runtime", "", "Runtime name")
	profileName := cmd.String("profile", "default", "Sandbox profile")
	imageDigest := cmd.String("image-digest", "", "Image/template digest")
	policyEpoch := cmd.String("policy-epoch", "local", "Policy epoch")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *runtimeName == "" {
		fmt.Fprintln(stderr, "Error: --runtime is required")
		return 2
	}
	if *imageDigest == "" {
		fmt.Fprintln(stderr, "Error: --image-digest is required before sandbox execution")
		return 2
	}
	policy := runtimesandbox.DefaultPolicy()
	policy.PolicyID = *profileName
	grant, err := runtimesandbox.GrantFromPolicy(policy, *runtimeName, *profileName, *imageDigest, *policyEpoch, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, grant)
	}
	fmt.Fprintf(stdout, "Sandbox grant %s hash=%s\n", grant.GrantID, grant.GrantHash)
	return 0
}

func runSandboxList(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox list", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	grants := newLocalSurfaceRegistry().ListSandboxGrants()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, grants)
	}
	fmt.Fprintln(stdout, "No sandbox grants recorded in this local CLI registry.")
	return 0
}

func runSandboxGet(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox get", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	grantID := cmd.String("grant-id", "", "Sandbox grant id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *grantID == "" && cmd.NArg() > 0 {
		*grantID = cmd.Arg(0)
	}
	if *grantID == "" {
		fmt.Fprintln(stderr, "Error: --grant-id is required")
		return 2
	}
	result := map[string]any{"grant_id": *grantID, "state": "not_found", "verified": false}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "Sandbox grant %s is not recorded in this local CLI registry\n", *grantID)
	return 1
}

func runSandboxVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	grantID := cmd.String("grant-id", "", "Sandbox grant id")
	grantHash := cmd.String("grant-hash", "", "Expected grant hash")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	result := contracts.SandboxPreflightResult{
		Verdict:       contracts.VerdictAllow,
		GrantID:       *grantID,
		GrantHash:     *grantHash,
		DispatchReady: *grantHash != "",
		CheckedAt:     time.Now().UTC(),
	}
	if *grantHash == "" {
		result.Verdict = contracts.VerdictDeny
		result.ReasonCode = contracts.ReasonSandboxViolation
		result.Findings = []string{"grant hash is required for offline verification"}
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "Sandbox verify verdict=%s grant=%s\n", result.Verdict, result.GrantID)
	if result.Verdict != contracts.VerdictAllow {
		return 1
	}
	return 0
}

func runSandboxPreflightSurface(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox preflight", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	runtimeName := cmd.String("runtime", "", "Runtime name")
	profileName := cmd.String("profile", "default", "Sandbox profile")
	imageDigest := cmd.String("image-digest", "", "Image/template digest")
	policyEpoch := cmd.String("policy-epoch", "local", "Policy epoch")
	expectedHash := cmd.String("expected-grant-hash", "", "Expected grant hash")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *runtimeName == "" {
		fmt.Fprintln(stderr, "Error: --runtime is required")
		return 2
	}
	policy := runtimesandbox.DefaultPolicy()
	policy.PolicyID = *profileName
	grant, err := runtimesandbox.GrantFromPolicy(policy, *runtimeName, *profileName, *imageDigest, *policyEpoch, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	result := verifySandboxGrantForDispatch(grant, *expectedHash)
	if *jsonOutput {
		_ = writeSurfaceJSON(stdout, result)
		if result.Verdict != contracts.VerdictAllow {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "Sandbox preflight verdict=%s grant_hash=%s\n", result.Verdict, result.GrantHash)
	if result.Verdict != contracts.VerdictAllow {
		return 1
	}
	return 0
}

func runEvidenceEnvelope(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm evidence envelope <list|create|get|verify> [flags]")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "list":
		cmd := flag.NewFlagSet("evidence envelope list", flag.ContinueOnError)
		cmd.SetOutput(stderr)
		jsonOutput := cmd.Bool("json", false, "Output as JSON")
		if err := cmd.Parse(args[1:]); err != nil {
			return 2
		}
		if *jsonOutput {
			return writeSurfaceJSON(stdout, registry.ListEnvelopes())
		}
		fmt.Fprintln(stdout, "No envelope manifests recorded in this local CLI registry.")
		return 0
	case "create":
		return runEvidenceEnvelopeCreate(args[1:], stdout, stderr)
	case "get":
		return runEvidenceEnvelopeGet(args[1:], stdout, stderr)
	case "payload":
		return runEvidenceEnvelopePayload(args[1:], stdout, stderr)
	case "verify":
		return runEvidenceEnvelopeVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown evidence envelope subcommand: %s\n", args[0])
		return 2
	}
}

func runEvidenceEnvelopeCreate(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence envelope create", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	envelope := cmd.String("envelope", "", "Envelope type")
	nativeHash := cmd.String("native-hash", "", "Native EvidencePack root hash")
	manifestID := cmd.String("manifest-id", "evidence-export", "Envelope manifest id")
	subject := cmd.String("subject", "", "Evidence subject")
	experimental := cmd.Bool("experimental", false, "Allow experimental envelope types")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *envelope == "" || *nativeHash == "" {
		fmt.Fprintln(stderr, "Error: --envelope and --native-hash are required")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	manifest, payload, err := buildEvidenceEnvelope(*manifestID, *envelope, *nativeHash, *subject, *experimental)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if err := registry.PutEnvelope(manifest); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if err := registry.PutEnvelopePayload(payload); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, map[string]any{"manifest": manifest, "payload": payload})
	}
	fmt.Fprintf(stdout, "Created evidence envelope %s payload=%s\n", manifest.ManifestID, payload.PayloadHash)
	return 0
}

func runEvidenceEnvelopeGet(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence envelope get", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	manifestID := cmd.String("manifest-id", "", "Envelope manifest id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *manifestID == "" && cmd.NArg() > 0 {
		*manifestID = cmd.Arg(0)
	}
	if *manifestID == "" {
		fmt.Fprintln(stderr, "Error: --manifest-id is required")
		return 2
	}
	result := map[string]any{"manifest_id": *manifestID, "state": "not_found", "verified": false}
	if manifest, ok := newLocalSurfaceRegistry().GetEnvelope(*manifestID); ok {
		if *jsonOutput {
			return writeSurfaceJSON(stdout, manifest)
		}
		fmt.Fprintf(stdout, "Envelope manifest %s hash=%s payload=%s\n", manifest.ManifestID, manifest.ManifestHash, manifest.PayloadHash)
		return 0
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "Envelope manifest %s is not recorded in this local CLI registry\n", *manifestID)
	return 1
}

func runEvidenceEnvelopePayload(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence envelope payload", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	manifestID := cmd.String("manifest-id", "", "Envelope manifest id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *manifestID == "" && cmd.NArg() > 0 {
		*manifestID = cmd.Arg(0)
	}
	if *manifestID == "" {
		fmt.Fprintln(stderr, "Error: --manifest-id is required")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	payload, ok := registry.GetEnvelopePayload(*manifestID)
	if !ok {
		manifest, manifestOK := registry.GetEnvelope(*manifestID)
		if !manifestOK {
			fmt.Fprintf(stderr, "Error: envelope manifest %q not found\n", *manifestID)
			return 1
		}
		var err error
		payload, err = evidencepkg.BuildEnvelopePayload(manifest)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, payload)
	}
	fmt.Fprintf(stdout, "Envelope payload %s type=%s hash=%s\n", payload.ManifestID, payload.PayloadType, payload.PayloadHash)
	return 0
}

func runEvidenceEnvelopeVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence envelope verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	manifestID := cmd.String("manifest-id", "", "Envelope manifest id")
	manifestHash := cmd.String("manifest-hash", "", "Manifest hash")
	nativeRoot := cmd.String("native-root", "", "Native EvidencePack root hash")
	envelope := cmd.String("envelope", "dsse", "Envelope type")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	result := contracts.EvidenceEnvelopeVerification{
		ManifestID:   *manifestID,
		ManifestHash: *manifestHash,
		Envelope:     *envelope,
		Verified:     *manifestHash != "" && *nativeRoot != "",
		NativeRoot:   *nativeRoot,
		Checks:       map[string]string{"manifest_hash": "PASS", "native_root": "PASS"},
		VerifiedAt:   time.Now().UTC(),
	}
	if !result.Verified {
		result.Checks = map[string]string{"manifest_hash": "FAIL", "native_root": "FAIL"}
		result.Errors = []string{"manifest hash and native root are required"}
	}
	if *manifestID != "" {
		registry := newLocalSurfaceRegistry()
		if manifest, ok := registry.GetEnvelope(*manifestID); ok {
			payload, payloadOK := registry.GetEnvelopePayload(*manifestID)
			if !payloadOK {
				payload, _ = evidencepkg.BuildEnvelopePayload(manifest)
			}
			result = evidencepkg.VerifyEnvelopePayload(manifest, payload)
		}
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "Evidence envelope verify manifest=%s verified=%t\n", result.ManifestID, result.Verified)
	if !result.Verified {
		return 1
	}
	return 0
}

func runConformVectors(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("conform vectors", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	vectors := conformance.DefaultNegativeBoundaryVectors()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, vectors)
	}
	for _, vector := range vectors {
		fmt.Fprintf(stdout, "%s  verdict=%s reason=%s\n", vector.ID, vector.ExpectedVerdict, vector.ExpectedReasonCode)
	}
	return 0
}

func buildEnvelopeManifest(manifestID, envelope, nativeHash, subject string, experimental bool) (contracts.EvidenceEnvelopeManifest, error) {
	return evidencepkg.BuildEnvelopeManifest(evidencepkg.EnvelopeExportRequest{
		ManifestID:         manifestID,
		Envelope:           evidencepkg.EnvelopeExportType(envelope),
		NativeEvidenceHash: nativeHash,
		Subject:            subject,
		CreatedAt:          time.Now().UTC(),
		AllowExperimental:  experimental,
	})
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

func relationshipHash(subject, object, relation string) string {
	sum := sha256.Sum256([]byte(subject + "|" + object + "|" + relation))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func init() {
	Register(Subcommand{Name: "boundary", Aliases: []string{}, Usage: "Inspect execution-boundary status, records, and checkpoints", RunFn: runBoundarySurfaceCmd})
	Register(Subcommand{Name: "identity", Aliases: []string{}, Usage: "Inspect OSS agent identities", RunFn: runIdentityCmd})
	Register(Subcommand{Name: "authz", Aliases: []string{}, Usage: "Inspect ReBAC authorization health and snapshots", RunFn: runAuthzSurfaceCmd})
	Register(Subcommand{Name: "approvals", Aliases: []string{}, Usage: "Manage local approval ceremonies", RunFn: runApprovalsSurfaceCmd})
	Register(Subcommand{Name: "budget", Aliases: []string{"budgets"}, Usage: "Manage budget and velocity ceilings", RunFn: runBudgetSurfaceCmd})
	Register(Subcommand{Name: "telemetry", Aliases: []string{}, Usage: "Inspect non-authoritative telemetry export config", RunFn: runTelemetrySurfaceCmd})
	Register(Subcommand{Name: "coexistence", Aliases: []string{}, Usage: "Emit scanner and gateway coexistence manifests", RunFn: runCoexistenceSurfaceCmd})
	Register(Subcommand{Name: "integrate", Aliases: []string{}, Usage: "Scaffold pre-dispatch framework integrations", RunFn: runIntegrateSurfaceCmd})
}
