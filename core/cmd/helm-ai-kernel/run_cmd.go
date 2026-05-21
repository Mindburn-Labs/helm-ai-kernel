package main

import (
	"fmt"
	"io"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/readmodel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func init() {
	Register(Subcommand{Name: "run", Usage: "Inspect Launchpad runs (open, logs, receipts)", RunFn: runRunCmd})
}

func runRunCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel run <open|logs|receipts|maintenance> <run_id>")
		return 2
	}
	switch args[0] {
	case "maintenance":
		return runMaintenanceCmd(args[1:], stdout, stderr)
	case "open":
		return runRunOpen(args[1:], stdout, stderr)
	case "logs":
		return runLaunchLogs(args[1:], stdout, stderr)
	case "receipts":
		return runRunReceipts(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel run <open|logs|receipts|maintenance> <run_id>")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown run subcommand: %s\n", args[0])
		return 2
	}
}

func runRunOpen(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel run open <run_id>")
		return 2
	}
	run, err := session.NewStore("").Get(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "run open error: %v\n", err)
		return 1
	}
	printRunSummary(stdout, run)
	return 0
}

func runRunReceipts(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel run receipts <run_id>")
		return 2
	}
	run, err := session.NewStore("").Get(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "run receipts error: %v\n", err)
		return 1
	}
	refs := readmodel.ReceiptRefs(run)
	if len(refs) == 0 {
		fmt.Fprintln(stdout, "unproven")
		return 0
	}
	for _, ref := range refs {
		fmt.Fprintln(stdout, ref)
	}
	return 0
}
