package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// answeredSurfaceHelp answers a help request for a boundary-surface router and
// reports whether it did. Every one of these routers builds the file-backed
// registry before it inspects its arguments, and on a fresh data directory that
// seeds and writes authority state. Asking a governance command what it does
// must not be the same as running it, so help is answered here, upstream of the
// registry. Leaf-specific flag help is a separate improvement (plan 004); this
// only guarantees the question is side-effect free.
func answeredSurfaceHelp(usage string, args []string, stdout io.Writer) bool {
	if len(args) == 0 || !isHelpRequest(args) {
		return false
	}
	fmt.Fprintln(stdout, usage)
	return true
}

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

func writeSurfaceJSONResult(w io.Writer, value any, successful bool) int {
	_ = writeSurfaceJSON(w, value)
	if !successful {
		return 1
	}
	return 0
}

// sanitizeReceiptPart lowercases value and maps every byte outside [a-z0-9]
// to '_', so it is safe as a receipt id and a file name.
func sanitizeReceiptPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown"
	}
	return out
}

// shellQuote single-quotes value for a POSIX shell.
func shellQuote(value string) string {
	if value == "" {
		return `""`
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func runBoundarySurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel boundary <status|capabilities|records|get|verify|checkpoint|profile> [flags]")
		return 2
	}
	if args[0] == "profile" {
		return runBoundaryProfileCmd(args[1:], stdout, stderr)
	}
	if answeredSurfaceHelp("Usage: helm-ai-kernel boundary <status|capabilities|records|get|verify|checkpoint|profile> [flags]", args, stdout) {
		return 0
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
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel boundary <status|capabilities|records|get|verify|checkpoint|profile> [flags]")
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
		return writeSurfaceJSONResult(stdout, result, result.Verified)
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

func init() {
	Register(Subcommand{Name: "boundary", Aliases: []string{}, Usage: "Inspect execution-boundary status, records, and checkpoints; compile/attest Boundary Enforcement Profiles", RunFn: runBoundarySurfaceCmd})
	Register(Subcommand{Name: "identity", Aliases: []string{}, Usage: "Inspect HELM AI Kernel agent identities", RunFn: runIdentityCmd})
	Register(Subcommand{Name: "authz", Aliases: []string{}, Usage: "Inspect ReBAC authorization health and snapshots", RunFn: runAuthzSurfaceCmd})
	Register(Subcommand{Name: "approvals", Aliases: []string{}, Usage: "Manage local approval ceremonies", RunFn: runApprovalsSurfaceCmd})
	Register(Subcommand{Name: "budget", Aliases: []string{"budgets"}, Usage: "Manage budget and velocity ceilings", RunFn: runBudgetSurfaceCmd})
	Register(Subcommand{Name: "telemetry", Aliases: []string{}, Usage: "Inspect non-authoritative telemetry export config", RunFn: runTelemetrySurfaceCmd})
	Register(Subcommand{Name: "coexistence", Aliases: []string{}, Usage: "Emit scanner and gateway coexistence manifests", RunFn: runCoexistenceSurfaceCmd})
	Register(Subcommand{Name: "integrate", Aliases: []string{}, Usage: "Scaffold pre-dispatch framework integrations", RunFn: runIntegrateSurfaceCmd})
}
