package main

import (
	"flag"
	"fmt"
	"io"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func runBudgetSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel budget <list|set> [flags]")
		return 2
	}
	if answeredSurfaceHelp("Usage: helm-ai-kernel budget <list|set> [flags]", args, stdout) {
		return 0
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "list":
		return runBudgetList(args[1:], registry, stdout, stderr)
	case "set":
		return runBudgetSet(args[1:], registry, stdout, stderr)
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
