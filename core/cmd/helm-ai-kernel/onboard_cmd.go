package main

import (
	"flag"
	"fmt"
	"io"
)

// onboard is retained as a compatibility shim for scripts that used the
// former first-run command. New operators should use setup so profile choice,
// preview, confirmation, and recovery all live in one journey.
var runOnboardSetup = runSetupFrontDoorFlags

func runOnboardCmd(args []string, stdout, stderr io.Writer) int {
	if isHelpRequest(args) {
		printOnboardUsage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("onboard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "mcp", "Compatibility first-run profile")
	yes := fs.Bool("yes", false, "Confirm first-run changes")
	dryRun := fs.Bool("dry-run", false, "Preview without changing local state")
	jsonOut := fs.Bool("json", false, "Print machine-readable Quickstart output")
	dataDir := fs.String("data-dir", "data", "Directory for HELM first-run state")
	console := fs.Bool("console", false, "Start the packaged local Console")
	consolePort := fs.Int("console-port", 3400, "Local Console port (0 chooses an ephemeral port)")
	noOpen := fs.Bool("no-open", false, "Do not open the local Console in a browser")
	offline := fs.Bool("offline", false, "Refuse optional network checks during first run")
	reset := fs.Bool("reset", false, "Replace HELM-owned first-run state")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "onboard: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if !*jsonOut {
		fmt.Fprintln(stderr, "onboard is deprecated; forwarding to `helm-ai-kernel setup --quickstart`. Existing --yes scripts remain supported.")
	}
	forwarded := []string{
		"--quickstart",
		"--profile", *profile,
		"--data-dir", *dataDir,
	}
	if *yes {
		forwarded = append(forwarded, "--yes")
	}
	if *dryRun {
		forwarded = append(forwarded, "--dry-run")
	}
	if *jsonOut {
		forwarded = append(forwarded, "--json")
	}
	if *console {
		forwarded = append(forwarded, "--console", "--console-port", fmt.Sprint(*consolePort))
	}
	if *noOpen {
		forwarded = append(forwarded, "--no-open")
	}
	if *offline {
		forwarded = append(forwarded, "--offline")
	}
	if *reset {
		forwarded = append(forwarded, "--reset")
	}
	return runOnboardSetup(forwarded, stdout, stderr)
}

func printOnboardUsage(w io.Writer) {
	fmt.Fprintln(w, "Deprecated: `onboard` forwards to the guided first-run path.")
	fmt.Fprintln(w, "Use: helm-ai-kernel setup --quickstart --profile <claude|codex|mcp|openai-compatible> --yes")
	fmt.Fprintln(w, "Existing scripts can keep: helm-ai-kernel onboard --yes [--data-dir DIR]")
}

func init() {
	Register(Subcommand{
		Name:   "onboard",
		Usage:  "Deprecated compatibility alias for setup --quickstart",
		RunFn:  runOnboardCmd,
		HelpFn: printOnboardUsage,
	})
}
