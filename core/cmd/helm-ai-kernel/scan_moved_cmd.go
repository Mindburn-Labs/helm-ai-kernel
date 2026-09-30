package main

import (
	"fmt"
	"io"
)

// The local agent risk scan moved to its own binary, helm-risk-scan, in
// HELM-756: it observes configuration and enforces nothing, so it sits outside
// the kernel. These stubs keep `scan` and `verify-scan` for one release so a
// documented command says where it went instead of "unknown command".

const scanMovedRelease = "HELM-756"

func runScanMovedCmd(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stderr, "helm-ai-kernel scan moved to the helm-risk-scan binary (%s).\n", scanMovedRelease)
	fmt.Fprintln(stderr, "Run: helm-risk-scan scan [same options]; --upload was removed.")
	return 2
}

func runVerifyScanMovedCmd(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stderr, "helm-ai-kernel verify-scan moved to the helm-risk-scan binary (%s).\n", scanMovedRelease)
	fmt.Fprintln(stderr, "Run: helm-risk-scan verify --bundle <pack>")
	return 2
}

func printScanMovedUsage(stdout io.Writer) {
	fmt.Fprintln(stdout, "Usage: helm-ai-kernel scan (deprecated: moved to helm-risk-scan)")
	fmt.Fprintln(stdout, "The local agent risk scan is now its own binary:")
	fmt.Fprintln(stdout, "  helm-risk-scan scan --path DIR [--risk-envelope FILE] [--preview FILE] [--evidence-pack FILE]")
	fmt.Fprintln(stdout, "  helm-risk-scan verify --bundle FILE")
}

func init() {
	Register(Subcommand{
		Name:   "scan",
		Usage:  "Deprecated: moved to helm-risk-scan",
		RunFn:  runScanMovedCmd,
		HelpFn: printScanMovedUsage,
	})
	Register(Subcommand{
		Name:  "verify-scan",
		Usage: "Deprecated: moved to helm-risk-scan verify",
		RunFn: runVerifyScanMovedCmd,
	})
}
