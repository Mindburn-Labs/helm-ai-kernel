package main

import (
	"fmt"
	"io"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

func init() {
	Register(Subcommand{
		Name:    "plan",
		Aliases: []string{},
		Usage:   "Inspect local PlanTransaction evidence (plan transactions)",
		RunFn:   runPlanCmd,
	})
}

// runPlanCmd dispatches `helm-ai-kernel plan <subcommand>`.
//
// The only subcommand is `transactions`, which inspects PlanTransaction
// records in the local boundary surface registry. `plan compile` and
// `plan evaluate` were removed (helm-tracker#328): compiling task descriptions
// into a plan decides what to attempt, which is orchestration, and the
// evaluate path signed its decisions with a key it discarded on exit and
// persisted no receipt. Evaluate each proposed action through the evaluate
// API instead, so every step gets a persisted, verifiable receipt.
func runPlanCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel plan transactions [flags]")
		return 2
	}

	switch args[0] {
	case "transactions":
		return runPlanTransactions(args[1:], stdout, stderr)
	default:
		_ = cliui.WriteError(stderr, cliui.UsageErrorf("plan", "unknown subcommand: %s", args[0]))
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel plan transactions [flags]")
		return 2
	}
}
