package main

import (
	"encoding/json"
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

const commandCatalogSchemaVersion = "helm-ai-kernel.command-catalog.v1"

// commandCatalogDocument is the stable, side-effect-free command discovery contract.
type commandCatalogDocument struct {
	SchemaVersion string                `json:"schema_version"`
	Commands      []commandCatalogEntry `json:"commands"`
}

type commandCatalogEntry struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
	Usage   string   `json:"usage"`
}

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
	// Only depth-1 help is answered here. Deeper help belongs to the leaf, which
	// owns the flag set being described — see TestNestedHelpReachesLeafFlagSets.
	// A leaf is responsible for answering it before it touches any state.
	if len(args) == 1 && isHelpRequest(args) {
		printSubcommandHelp(cmd, stdout)
		return 0, true
	}
	return cmd.RunFn(args, stdout, stderr), true
}

func isHelpRequest(args []string) bool {
	for index, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
		if index == 0 && arg == "help" {
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
	fmt.Fprintf(out, "%s: Canonical Execution Verifier (Version %s, Commit %s)\n\n", terminalTitle(out, "HELM AI Kernel"), displayVersion(), displayCommit())
	fmt.Fprintln(out, "Usage: helm-ai-kernel <command> [options]")
	fmt.Fprintln(out, "\nCommands:")

	for _, cmd := range canonicalRegisteredCommands() {
		aliasStr := ""
		if len(cmd.Aliases) > 0 {
			aliasStr = fmt.Sprintf(" (aliases: %s)", strings.Join(cmd.Aliases, ", "))
		}
		fmt.Fprintf(out, "  %-20s %s%s\n", cmd.Name, cmd.Usage, aliasStr)
	}

	fmt.Fprintln(out, "\nGlobal Commands:")
	for _, cmd := range explicitGlobalCommands() {
		aliasStr := ""
		if len(cmd.Aliases) > 0 {
			aliasStr = fmt.Sprintf(" (aliases: %s)", strings.Join(cmd.Aliases, ", "))
		}
		fmt.Fprintf(out, "  %-20s %s%s\n", cmd.Name, cmd.Usage, aliasStr)
	}
}

func commandCatalog() commandCatalogDocument {
	commands := append(canonicalRegisteredCommands(), explicitGlobalCommands()...)
	sort.Slice(commands, func(i, j int) bool { return commands[i].Name < commands[j].Name })
	return commandCatalogDocument{
		SchemaVersion: commandCatalogSchemaVersion,
		Commands:      commands,
	}
}

func canonicalRegisteredCommands() []commandCatalogEntry {
	commands := make([]commandCatalogEntry, 0, len(subcommands))
	for name, cmd := range subcommands {
		if name != cmd.Name {
			continue
		}
		aliases := append([]string{}, cmd.Aliases...)
		sort.Strings(aliases)
		commands = append(commands, commandCatalogEntry{
			Name:    cmd.Name,
			Aliases: aliases,
			Usage:   cmd.Usage,
		})
	}
	sort.Slice(commands, func(i, j int) bool { return commands[i].Name < commands[j].Name })
	return commands
}

func explicitGlobalCommands() []commandCatalogEntry {
	return []commandCatalogEntry{
		{Name: "completion", Aliases: []string{}, Usage: "Generate static shell completion"},
		{Name: "help", Aliases: []string{"--help", "-h"}, Usage: "Show command help"},
		{Name: "server", Aliases: []string{}, Usage: "Start the HELM Guardian API and proxy services"},
		{Name: "serve", Aliases: []string{}, Usage: "Start a local HELM boundary from --policy"},
		{Name: "threat", Aliases: []string{}, Usage: "Run a threat scan or test"},
		{Name: "version", Aliases: []string{"--version", "-v"}, Usage: "Print version and schema information"},
	}
}

func completionWords() []string {
	seen := make(map[string]struct{})
	for _, cmd := range commandCatalog().Commands {
		seen[cmd.Name] = struct{}{}
		for _, alias := range cmd.Aliases {
			seen[alias] = struct{}{}
		}
	}
	words := make([]string, 0, len(seen))
	for word := range seen {
		words = append(words, word)
	}
	sort.Strings(words)
	return words
}

func writeCommandCatalogJSON(out io.Writer) int {
	if err := json.NewEncoder(out).Encode(commandCatalog()); err != nil {
		return 1
	}
	return 0
}
