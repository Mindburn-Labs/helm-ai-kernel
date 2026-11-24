package main

// quantum_posture: CLI dispatch/front-door wiring only; cryptographic controls
// live in core/pkg/crypto and related verifier packages.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	_ "github.com/lib/pq" // Postgres Driver
)

// Dispatcher
func main() {
	os.Exit(Run(os.Args, os.Stdout, os.Stderr))
}

// startServer is a variable to allow mocking in tests
var startServer = runServer

// RunWithContext dispatches argv. A cancelled ctx prevents Dispatch from
// starting. After start, Kernel Run/Dispatch do not observe ctx — callers
// must discard late results. The operator TUI never starts listeners, so
// Esc abort cannot leak a bind the TUI started.
func RunWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return 2
		default:
		}
	}
	return Run(args, stdout, stderr)
}

// Run is the entrypoint for testing
func Run(args []string, stdout, stderr io.Writer) int {
	if shouldLaunchTUI(args, stdout) {
		return runKernelTUI(stdout, stderr)
	}
	if len(args) < 2 {
		printFrontDoor(stdout)
		return 0
	}
	if args[1] == "help" {
		rest, code, ok := applyOperatorFormat("help", args[2:], stderr)
		if !ok {
			return code
		}
		return runHelpCommand(rest, stdout, stderr)
	}
	if len(args) == 3 && isHelpRequest(args[2:]) {
		if code, ok := Dispatch(args[1], []string{"--help"}, stdout, stderr); ok {
			return code
		}
		printGlobalCommandHelp(args[1], stdout)
		return 0
	}

	// Attempt to dispatch from registry
	if code, ok := Dispatch(args[1], args[2:], stdout, stderr); ok {
		return code
	}

	// Handle specific global commands that don't fit the registry pattern
	switch args[1] {
	case "completion":
		rest, code, ok := applyOperatorFormat("completion", args[2:], stderr)
		if !ok {
			return code
		}
		return runCompletionCommand(rest, stdout, stderr)
	case "server", "serve":
		rest, code, ok := applyOperatorFormat(args[1], args[2:], stderr)
		if !ok {
			return code
		}
		return runServerCommand(args[1], rest, stdout, stderr)

	case "trust":
		if len(args) < 3 {
			_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel trust <add-key|revoke-key|list-keys>")
			return 2
		}
		return runTrustCmd(args[2:], stdout, stderr)
	case "threat":
		rest, code, ok := applyOperatorFormat("threat", args[2:], stderr)
		if !ok {
			return code
		}
		if len(rest) < 1 {
			_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel threat <scan|test> [flags]")
			return 2
		}
		return runThreatCmd(rest, stdout, stderr)
	case "version":
		rest, code, ok := applyOperatorFormat("version", args[2:], stderr)
		if !ok {
			return code
		}
		return runVersionCommand(rest, stdout, stderr)
	case "--version", "-v":
		rest, code, ok := applyOperatorFormat("version", args[2:], stderr)
		if !ok {
			return code
		}
		return runVersionFlag(rest, stdout, stderr)
	case "--help", "-h":
		printFrontDoor(stdout)
		return 0
	default:
		if args[1][0] == '-' {
			// An unrecognized flag used to start the server, as a convenience for
			// `helm-ai-kernel --port …` without the subcommand. Nothing in the
			// estate invokes it that way — every image, chart and unit names
			// `serve`, `server` or a subcommand explicitly — and the convenience
			// meant a mistyped flag silently launched a listener and minted a
			// trust root in the working directory. A boundary that starts by
			// accident is not a boundary.
			_, _ = fmt.Fprintf(stderr, "Unknown flag: %s\n", args[1])
			_, _ = fmt.Fprintf(stderr, "To start the server, name it: helm-ai-kernel serve %s\n", args[1])
			printUsage(stderr)
			return 2
		}
		printUnknownCommand(stderr, args[1])
		return 2
	}
}

func runHelpCommand(args []string, stdout, stderr io.Writer) int {
	if operatorJSONRequested(args) {
		return writeCommandCatalogJSON(stdout)
	}
	if len(args) > 0 && args[0] == "--all" {
		printUsageAll(stdout)
		return 0
	}
	if len(args) > 0 {
		path := append([]string(nil), args[1:]...)
		if !isHelpRequest(path) {
			path = append(path, "--help")
		}
		if code, ok := Dispatch(args[0], path, stdout, stderr); ok {
			return code
		}
		printGlobalCommandHelp(args[0], stdout)
		return 0
	}
	printFrontDoor(stdout)
	return 0
}

func printGlobalCommandHelp(name string, stdout io.Writer) {
	switch name {
	case "console":
		fmt.Fprintln(stdout, "The local browser Console is launched by Quickstart, not as a standalone server.")
		printLocalConsoleJourney(stdout)
		return
	case "completion":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel completion <bash|zsh|fish|powershell>")
	case "help":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel help [--all|--json|<command>]")
	case "server":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel server [--policy PATH] [--addr ADDR] [--port PORT] [--data-dir DIR] [--json]")
		fmt.Fprintln(stdout, "Logs default to JSON; set HELM_LOG_FORMAT=text for local human-readable output.")
	case "serve":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel serve --policy PATH [--addr ADDR] [--port PORT] [--data-dir DIR] [--json]")
		fmt.Fprintln(stdout, "Logs default to JSON; set HELM_LOG_FORMAT=text for local human-readable output.")
	case "threat":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel threat <scan|test> [flags]")
	case "version":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel version [--json]")
	default:
		fmt.Fprintf(stdout, "Usage: helm-ai-kernel %s [options]\n", name)
	}
	fmt.Fprintln(stdout, "Run `helm-ai-kernel help --all` to list commands.")
}

// ANSI Colors
const (
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[37m"
)

func init() {
	Register(Subcommand{
		Name:    "health",
		Aliases: []string{},
		Usage:   "Check local HELM server health",
		RunFn:   func(args []string, stdout, stderr io.Writer) int { return runHealthCmd(args, stdout, stderr) },
	})
}

func runHealthCmd(args []string, out, errOut io.Writer) int {
	jsonOut := operatorJSONRequested(args)
	healthPort := 8081
	if envHP := os.Getenv("HELM_HEALTH_PORT"); envHP != "" {
		if p, parseErr := strconv.Atoi(envHP); parseErr == nil {
			healthPort = p
		}
	}

	type healthDoc struct {
		Status string `json:"status"`
		Port   int    `json:"port"`
		Error  string `json:"error,omitempty"`
	}

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/healthz", healthPort))
	if err != nil {
		if jsonOut {
			_ = json.NewEncoder(out).Encode(healthDoc{Status: "FAIL", Port: healthPort, Error: err.Error()})
			return 1
		}
		fmt.Fprintf(errOut, "Health check failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if jsonOut {
			_ = json.NewEncoder(out).Encode(healthDoc{Status: "FAIL", Port: healthPort, Error: fmt.Sprintf("status %d", resp.StatusCode)})
			return 1
		}
		fmt.Fprintf(errOut, "Health check failed: status %d\n", resp.StatusCode)
		return 1
	}

	if jsonOut {
		_ = json.NewEncoder(out).Encode(healthDoc{Status: "OK", Port: healthPort})
		return 0
	}
	fmt.Fprintln(out, "OK")
	return 0
}
