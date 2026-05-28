package main

import (
	"flag"
	"fmt"
	"io"

	lpcmd "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/cmd"
)

func init() {
	Register(Subcommand{
		Name:    "console",
		Aliases: []string{},
		Usage:   "Console pairing commands (pair, status)",
		RunFn:   runConsoleCmd,
	})
}

func runConsoleCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel console <pair|status> [flags]")
		return 2
	}

	switch args[0] {
	case "pair":
		return runConsolePairCmd(args[1:], stdout, stderr)
	case "status":
		return runConsoleStatusCmd(stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown console subcommand: %s\n", args[0])
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel console <pair|status> [flags]")
		return 2
	}
}

func runConsolePairCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("console pair", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var workspaceID, apiURL string
	fs.StringVar(&workspaceID, "workspace", "", "Workspace ID to pair with (auto-discovers if not set)")
	fs.StringVar(&apiURL, "api-url", "", "Console API base URL (default: https://console.helm.mindburn.org)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	opts := lpcmd.PairOptions{
		WorkspaceID: workspaceID,
		APIURL:      apiURL,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	if err := lpcmd.RunPair(opts); err != nil {
		fmt.Fprintf(stderr, "console pair: %v\n", err)
		return 1
	}
	return 0
}

func runConsoleStatusCmd(stdout, stderr io.Writer) int {
	pairing, err := lpcmd.LoadPairing()
	if err != nil {
		fmt.Fprintf(stderr, "console status: %v\n", err)
		return 1
	}

	session, sessionErr := lpcmd.LoadSession()
	tokenStatus := "expired"
	if sessionErr == nil && !lpcmd.IsTokenExpired(session) {
		tokenStatus = "valid"
	}

	fmt.Fprintf(stdout, "Workspace:  %s\n", pairing.WorkspaceID)
	fmt.Fprintf(stdout, "API URL:    %s\n", pairing.APIURL)
	fmt.Fprintf(stdout, "Paired at:  %s\n", pairing.PairedAt)
	fmt.Fprintf(stdout, "Session:    %s\n", tokenStatus)
	return 0
}
