package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Subcommand represents a registered CLI command.
type Subcommand struct {
	Name    string
	Aliases []string
	Usage   string
	RunFn   func(args []string, stdout, stderr io.Writer) int
}

var subcommands = make(map[string]Subcommand)

// Register adds a subcommand to the CLI registry.
// This should be called from init() functions in cmd/ files.
func Register(cmd Subcommand) {
	subcommands[cmd.Name] = cmd
	for _, alias := range cmd.Aliases {
		subcommands[alias] = cmd
	}
}

// Dispatch executes the requested subcommand. Returns (exitCode, handled).
func Dispatch(name string, args []string, stdout, stderr io.Writer) (int, bool) {
	cmd, ok := subcommands[name]
	if !ok {
		return 0, false
	}
	return cmd.RunFn(args, stdout, stderr), true
}

func printUsage(out io.Writer) {
	fmt.Fprintf(out, "%sHELM%s: Canonical Execution Verifier (Version %s, Commit %s)\n\n", ColorBold, ColorReset, displayVersion(), displayCommit())
	fmt.Fprintln(out, "Usage: helm <command> [options]")
	fmt.Fprintln(out, "\nCommands:")

	// Sort commands for consistent output, excluding aliases
	var names []string
	for name, cmd := range subcommands {
		if name == cmd.Name {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		cmd := subcommands[name]
		aliasStr := ""
		if len(cmd.Aliases) > 0 {
			aliasStr = fmt.Sprintf(" (aliases: %s)", strings.Join(cmd.Aliases, ", "))
		}
		fmt.Fprintf(out, "  %-20s %s%s\n", name, cmd.Usage, aliasStr)
	}

	fmt.Fprintln(out, "\nGlobal Commands:")
	fmt.Fprintln(out, "  server              Start the HELM Guardian API and proxy services")
	fmt.Fprintln(out, "  health              Check local HELM server health")
	fmt.Fprintln(out, "  version             Print version and schema information")
	fmt.Fprintln(out, "  help                Show this help message")
}
