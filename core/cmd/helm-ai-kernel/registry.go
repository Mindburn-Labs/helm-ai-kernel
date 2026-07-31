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
	HelpFn  func(stdout io.Writer)
}

var subcommands = make(map[string]Subcommand)

// Register adds a subcommand to the CLI registry.
// This should be called from init() functions in cmd/ files.
func Register(cmd Subcommand) {
	names := append([]string{cmd.Name}, cmd.Aliases...)
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			panic("helm-ai-kernel: subcommand names must not be empty")
		}
		if _, ok := seen[name]; ok {
			panic(fmt.Sprintf("helm-ai-kernel: duplicate subcommand name or alias %q", name))
		}
		seen[name] = struct{}{}
		if _, ok := subcommands[name]; ok {
			panic(fmt.Sprintf("helm-ai-kernel: duplicate subcommand name or alias %q", name))
		}
	}
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
	if isHelpRequest(args) {
		printSubcommandHelp(cmd, stdout)
		return 0, true
	}
	return cmd.RunFn(args, stdout, stderr), true
}

func isHelpRequest(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" || arg == "help" {
			return true
		}
	}
	return false
}

func printSubcommandHelp(cmd Subcommand, stdout io.Writer) {
	if cmd.HelpFn != nil {
		cmd.HelpFn(stdout)
		return
	}
	fmt.Fprintf(stdout, "Usage: helm-ai-kernel %s [options]\n", cmd.Name)
	if cmd.Usage != "" {
		fmt.Fprintln(stdout, cmd.Usage)
	}
	fmt.Fprintln(stdout, "Run `helm-ai-kernel help --all` to list commands.")
}

func printUsage(out io.Writer) {
	printFrontDoor(out)
}

func printUsageAll(out io.Writer) {
	fmt.Fprintf(out, "%sHELM AI Kernel%s: Canonical Execution Verifier (Version %s, Commit %s)\n\n", ColorBold, ColorReset, displayVersion(), displayCommit())
	fmt.Fprintln(out, "Usage: helm-ai-kernel <command> [options]")
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
	fmt.Fprintln(out, "  serve               Start a local HELM boundary from --policy")
	fmt.Fprintln(out, "  health              Check local HELM server health")
	fmt.Fprintln(out, "  version             Print version and schema information")
	fmt.Fprintln(out, "  help                Show this help message")
}
