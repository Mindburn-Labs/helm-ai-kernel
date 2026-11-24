package main

import (
	"fmt"
	"io"
)

// ── Commands ────────────────────────────────────────────────────────────────

// runPackCmd implements `helm-ai-kernel pack` — governed self-extension lifecycle.
//
// Exit codes:
//
//	0 = success
//	1 = operational error
//	2 = config/usage error
func runPackCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printPackUsage(stderr)
		return 2
	}

	switch args[0] {
	case "propose":
		return runPackPropose(args[1:], stdout, stderr)
	case "build":
		return runPackBuild(args[1:], stdout, stderr)
	case "test":
		return runPackTest(args[1:], stdout, stderr)
	case "promote":
		return runPackPromote(args[1:], stdout, stderr)
	case "install":
		return runPackInstall(args[1:], stdout, stderr)
	case "list":
		return runPackList(args[1:], stdout, stderr)
	case "create":
		// Built-in evidence pack creation
		return handlePackCreate(args[1:])
	case "verify":
		// Built-in evidence pack verification
		return handlePackVerify(args[1:])
	case "--help", "-h":
		printPackUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown pack subcommand: %s\n", args[0])
		printPackUsage(stderr)
		return 2
	}
}

func init() {
	Register(Subcommand{
		Name:    "pack",
		Aliases: []string{},
		Usage:   "Governed self-extension lifecycle and evidence pack management",
		RunFn:   runPackCmd,
	})
	Register(Subcommand{
		Name:    "coverage",
		Aliases: []string{},
		Usage:   "Show coverage statistics",
		RunFn: func(args []string, stdout, stderr io.Writer) int {
			// Moved from main.go
			fmt.Fprintln(stdout, "[helm] coverage factory: ready")
			return 0
		},
	})
}

func printPackUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel pack <propose|build|test|promote|install|list> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Governed Skill Lifecycle — self-extension with receipts and conformance.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  propose     Create a SkillCandidate artifact")
	fmt.Fprintln(w, "  build       Build a Pack from a SkillCandidate")
	fmt.Fprintln(w, "  test        Run conformance tests on a Pack")
	fmt.Fprintln(w, "  promote     Promote a Pack (requires approval)")
	fmt.Fprintln(w, "  install     Install a promoted Pack")
	fmt.Fprintln(w, "  list        List candidates, packs, and installed skills")
}
