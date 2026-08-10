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

// suggestCommands returns registered command names within edit distance 2 of
// the typed token, nearest first. A typo used to print the whole front-door
// banner and no route; the nearest real command is what the user actually
// needs.
func suggestCommands(typed string) []string {
	typed = strings.ToLower(strings.TrimSpace(typed))
	if typed == "" {
		return nil
	}
	type scored struct {
		name string
		dist int
	}
	var out []scored
	seen := map[string]struct{}{}
	consider := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		d := levenshtein(typed, strings.ToLower(name))
		// Allow a slightly looser bound for longer words, capped at 2.
		bound := 2
		if len(typed) <= 3 {
			bound = 1
		}
		if d <= bound {
			out = append(out, scored{name, d})
		}
	}
	for _, c := range canonicalRegisteredCommands() {
		consider(c.Name)
		for _, a := range c.Aliases {
			consider(a)
		}
	}
	// The top-level verbs handled directly by the dispatcher, not the registry.
	for _, n := range []string{"server", "serve", "trust", "threat", "run", "version", "completion", "help"} {
		consider(n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].dist != out[j].dist {
			return out[i].dist < out[j].dist
		}
		return out[i].name < out[j].name
	})
	names := make([]string, 0, len(out))
	for _, s := range out {
		names = append(names, s.name)
		if len(names) == 3 {
			break
		}
	}
	return names
}

// levenshtein is the standard edit distance, ASCII-folded by the caller.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}

// printUnknownCommand reports an unrecognized command with the nearest real
// commands, not the full front-door banner.
func printUnknownCommand(out io.Writer, typed string) {
	fmt.Fprintf(out, "Unknown command: %s\n", typed)
	if suggestions := suggestCommands(typed); len(suggestions) > 0 {
		if len(suggestions) == 1 {
			fmt.Fprintf(out, "Did you mean: %s?\n", suggestions[0])
		} else {
			fmt.Fprintf(out, "Did you mean one of: %s?\n", strings.Join(suggestions, ", "))
		}
	}
	fmt.Fprintln(out, "Run `helm-ai-kernel help --all` to list commands.")
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
