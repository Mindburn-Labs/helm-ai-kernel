package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
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
	SchemaVersion string                  `json:"schema_version"`
	Commands      []commandCatalogEntry   `json:"commands"`
	Sections      []commandCatalogSection `json:"sections,omitempty"`
}

type commandCatalogEntry struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases"`
	Usage   string   `json:"usage"`
	Group   string   `json:"group,omitempty"`
	Format  string   `json:"format,omitempty"`
}

type commandCatalogSection struct {
	ID       string                `json:"id"`
	Title    string                `json:"title"`
	Commands []commandCatalogEntry `json:"commands"`
}

type commandSectionSpec struct {
	ID       string
	Title    string
	Commands []string
}

type completionContext struct {
	Path       []string
	Candidates []string
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
	if len(args) == 1 && isHelpRequest(args) {
		printSubcommandHelp(cmd, stdout)
		return 0, true
	}
	// Deeper help belongs to the leaf flag set. Route its help chrome to stdout
	// and normalize flag.ErrHelp-style exit codes; leaf parsers return before work.
	if helpArgs, ok := normalizeHelpRequest(args); ok {
		_ = cmd.RunFn(helpArgs, stdout, stdout)
		return 0, true
	}
	rest, code, ok := applyOperatorFormat(cmd.Name, args, stderr)
	if !ok {
		return code, true
	}
	return cmd.RunFn(rest, stdout, stderr), true
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
	if len(args) > 1 && args[len(args)-1] == "help" {
		for _, arg := range args[:len(args)-1] {
			if strings.HasPrefix(arg, "-") {
				return false
			}
		}
		return true
	}
	return false
}

func normalizeHelpRequest(args []string) ([]string, bool) {
	if !isHelpRequest(args) {
		return nil, false
	}
	normalized := append([]string(nil), args...)
	if normalized[len(normalized)-1] == "help" {
		normalized[len(normalized)-1] = "--help"
	}
	return normalized, true
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
	catalog := commandCatalog()
	p := ui.NewPrinter(out)
	p.Brand(ui.BrandHeader{
		Name:    "HELM",
		Tagline: "Fail-closed execution firewall for AI agents.",
		Version: displayVersion(),
		Commit:  displayCommit(),
		Hint:    "Canonical Execution Verifier. Usage: helm-ai-kernel <command> [options]",
	})
	p.Blank()
	p.Muted("Common outcomes first; `help --json` keeps the stable machine catalog.")
	p.Muted("Operator-data commands accept --format text|json (legacy --json stays). Unknown formats exit 2.")
	fmt.Fprintln(out, "\nCommands:")
	for _, section := range catalog.Sections {
		fmt.Fprintf(out, "\n%s:\n", section.Title)
		rows := make([]ui.CommandRow, 0, len(section.Commands))
		for _, cmd := range section.Commands {
			rows = append(rows, ui.CommandRow{Name: cmd.Name, Usage: cmd.Usage, Aliases: cmd.Aliases})
		}
		p.Table(rows)
	}
}

func commandCatalog() commandCatalogDocument {
	commands := append(canonicalRegisteredCommands(), explicitGlobalCommands()...)
	sort.Slice(commands, func(i, j int) bool { return commands[i].Name < commands[j].Name })
	return commandCatalogDocument{
		SchemaVersion: commandCatalogSchemaVersion,
		Commands:      commands,
		Sections:      groupedCommandCatalogSections(commands),
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
			Group:   commandGroupTitle(cmd.Name),
			Format:  catalogFormatContract(cmd.Name),
		})
	}
	sort.Slice(commands, func(i, j int) bool { return commands[i].Name < commands[j].Name })
	return commands
}

func explicitGlobalCommands() []commandCatalogEntry {
	return []commandCatalogEntry{
		{Name: "completion", Aliases: []string{}, Usage: "Generate static shell completion", Group: commandGroupTitle("completion"), Format: catalogFormatContract("completion")},
		{Name: "help", Aliases: []string{"--help", "-h"}, Usage: "Show command help", Group: commandGroupTitle("help"), Format: catalogFormatContract("help")},
		{Name: "server", Aliases: []string{}, Usage: "Start the HELM Guardian API and proxy services", Group: commandGroupTitle("server"), Format: catalogFormatContract("server")},
		{Name: "serve", Aliases: []string{}, Usage: "Start a local HELM boundary from --policy", Group: commandGroupTitle("serve"), Format: catalogFormatContract("serve")},
		{Name: "threat", Aliases: []string{}, Usage: "Run a threat scan or test", Group: commandGroupTitle("threat"), Format: catalogFormatContract("threat")},
		{Name: "version", Aliases: []string{"--version", "-v"}, Usage: "Print version and schema information", Group: commandGroupTitle("version"), Format: catalogFormatContract("version")},
	}
}

func completionCommandNames(name string) []string {
	canonical := name
	for _, command := range commandCatalog().Commands {
		if command.Name == name {
			return append([]string{command.Name}, command.Aliases...)
		}
		for _, alias := range command.Aliases {
			if alias != name {
				continue
			}
			return append([]string{command.Name}, command.Aliases...)
		}
	}
	return []string{canonical}
}

func completionCanonicalPath(path []string) []string {
	if len(path) == 0 {
		return nil
	}
	normalized := append([]string(nil), path...)
	normalized[0] = completionCommandNames(normalized[0])[0]
	if len(normalized) > 1 && normalized[0] == "help" {
		normalized[1] = completionCommandNames(normalized[1])[0]
	}
	return normalized
}

func expandCompletionContexts(contexts []completionContext) []completionContext {
	expanded := make([]completionContext, 0, len(contexts))
	seen := make(map[string]struct{}, len(contexts))
	for _, context := range contexts {
		var paths [][]string
		paths = append(paths, []string{})
		for index, segment := range context.Path {
			names := []string{segment}
			if index == 0 {
				names = completionCommandNames(segment)
			}
			if index == 1 && len(context.Path) > 1 && completionCanonicalPath(context.Path)[0] == "help" {
				names = completionCommandNames(segment)
			}
			next := make([][]string, 0, len(paths)*len(names))
			for _, path := range paths {
				for _, name := range names {
					candidate := append(append([]string(nil), path...), name)
					next = append(next, candidate)
				}
			}
			paths = next
		}
		for _, path := range paths {
			key := strings.Join(path, "\x00")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			expanded = append(expanded, completionContext{
				Path:       path,
				Candidates: uniqueStrings(context.Candidates),
			})
		}
	}
	return expanded
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

func groupedCommandCatalogSections(commands []commandCatalogEntry) []commandCatalogSection {
	index := make(map[string]commandCatalogEntry, len(commands))
	for _, command := range commands {
		index[command.Name] = command
	}
	seen := make(map[string]struct{}, len(commands))
	sections := make([]commandCatalogSection, 0, len(commandSectionSpecs()))
	for _, spec := range commandSectionSpecs() {
		grouped := make([]commandCatalogEntry, 0, len(spec.Commands))
		for _, name := range spec.Commands {
			command, ok := index[name]
			if !ok {
				continue
			}
			grouped = append(grouped, command)
			seen[name] = struct{}{}
		}
		if spec.ID == "operate" {
			var leftovers []commandCatalogEntry
			for _, command := range commands {
				if _, ok := seen[command.Name]; ok {
					continue
				}
				leftovers = append(leftovers, command)
			}
			sort.Slice(leftovers, func(i, j int) bool { return leftovers[i].Name < leftovers[j].Name })
			grouped = append(grouped, leftovers...)
		}
		sections = append(sections, commandCatalogSection{
			ID:       spec.ID,
			Title:    spec.Title,
			Commands: grouped,
		})
	}
	return sections
}

func commandGroupTitle(name string) string {
	for _, spec := range commandSectionSpecs() {
		for _, command := range spec.Commands {
			if command == name {
				return spec.Title
			}
		}
	}
	return "Operate"
}

func commandSectionSpecs() []commandSectionSpec {
	return []commandSectionSpec{
		{
			ID:    "get-started",
			Title: "Get started",
			Commands: []string{
				"tui", "setup", "quickstart", "scan", "doctor", "help", "completion", "version", "onboard", "init", "connect", "login", "demo",
			},
		},
		{
			ID:    "use-helm",
			Title: "Use HELM",
			Commands: []string{
				"watch", "receipts", "mcp", "launch", "app", "up", "run", "proxy", "spend-proxy", "local", "sandbox", "hook", "serve", "server", "dev", "scaffold", "shadow", "skills", "control-plane", "integrate", "health", "threat",
			},
		},
		{
			ID:    "evidence",
			Title: "Evidence",
			Commands: []string{
				"verify", "verify-scan", "evidence", "export", "audit", "report", "replay", "rollup", "log", "traces", "gui", "plan", "risk-summary", "conform", "certify", "coverage", "brief",
			},
		},
		{
			ID:    "operate",
			Title: "Operate",
			Commands: []string{
				"approvals", "authz", "boundary", "budget", "bundle", "coexistence", "counterfactual", "did", "freeze", "identity", "import", "incident", "policy", "secret", "tee", "telemetry", "trust", "unfreeze", "workstation",
			},
		},
	}
}

func completionContexts() []completionContext {
	return expandCompletionContexts([]completionContext{
		{Path: []string{"completion"}, Candidates: []string{"bash", "zsh", "fish", "powershell"}},
		{Path: []string{"help"}, Candidates: append([]string{"--all", "--json"}, completionWords()...)},
		{Path: []string{"launch"}, Candidates: []string{"matrix", "apps", "substrates", "plan", "status", "logs", "repair", "delete", "evidence", "promote", "secrets", "imports"}},
		{Path: []string{"launch", "delete"}, Candidates: []string{"--cascade"}},
		{Path: []string{"launch", "evidence"}, Candidates: []string{"--export", "--json", "--output"}},
		{Path: []string{"launch", "plan"}, Candidates: []string{"--json"}},
		{Path: []string{"quickstart"}, Candidates: []string{"--addr", "--port", "--data-dir", "--reset", "--offline", "--profile", "claude", "codex", "mcp", "openai-compatible", "--json", "--dry-run", "--yes", "--console", "--console-port", "--no-open"}},
		{Path: []string{"receipts"}, Candidates: []string{"status", "list", "show", "tail", "verify", "export"}},
		{Path: []string{"receipts", "tail"}, Candidates: []string{"--agent", "--server", "--since", "--json", "--format", "text", "json", "--limit"}},
		{Path: []string{"receipts", "list"}, Candidates: []string{"--server", "--limit", "--json", "--format", "text", "json"}},
		{Path: []string{"receipts", "show"}, Candidates: []string{"--id", "--file", "--server", "--json", "--format", "text", "json"}},
		{Path: []string{"receipts", "status"}, Candidates: []string{"--json", "--format", "text", "json"}},
		{Path: []string{"scan"}, Candidates: []string{"--path", "--from-receipts", "--cohort", "unknown", "1-10repos", "11-50repos", "51-200repos", "201plusrepos", "--salt-file", "--risk-envelope", "--preview", "--evidence-pack", "--no-user-config", "--upload", "--upload-url", "--yes"}},
		{Path: []string{"setup"}, Candidates: []string{"claude-code", "codex", "hermes", "deepseek", "status", "repair", "remove", "--client", "--print-config", "--json", "--quickstart", "--profile", "claude", "codex", "mcp", "openai-compatible", "--yes", "--dry-run", "--data-dir", "--console", "--console-port", "--no-open", "--offline", "--reset"}},
		{Path: []string{"setup", "claude-code"}, Candidates: []string{"--scope", "user", "project", "--workspace", "--data-dir", "--dry-run", "--json", "--yes", "--no-quickstart", "--quickstart", "--console", "--console-port", "--no-open", "--signing-seed-file", "--policy-profile", "--policy-profile-sha256"}},
		{Path: []string{"setup", "codex"}, Candidates: []string{"--scope", "user", "project", "--workspace", "--data-dir", "--dry-run", "--json", "--yes", "--no-quickstart", "--quickstart", "--console", "--console-port", "--no-open", "--signing-seed-file", "--policy-profile", "--policy-profile-sha256"}},
		{Path: []string{"setup", "hermes"}, Candidates: []string{"--scope", "user", "project", "--workspace", "--data-dir", "--dry-run", "--json", "--yes", "--no-quickstart", "--quickstart", "--console", "--console-port", "--no-open", "--signing-seed-file", "--policy-profile", "--policy-profile-sha256"}},
		{Path: []string{"setup", "deepseek"}, Candidates: []string{"--scope", "user", "project", "--workspace", "--data-dir", "--dry-run", "--json", "--yes", "--no-quickstart", "--quickstart", "--console", "--console-port", "--no-open", "--signing-seed-file", "--policy-profile", "--policy-profile-sha256"}},
		{Path: []string{"setup", "remove"}, Candidates: []string{"claude-code", "codex", "hermes", "deepseek", "--scope", "user", "project", "--workspace", "--yes", "--dry-run", "--json", "--data-dir"}},
		{Path: []string{"setup", "repair"}, Candidates: []string{"claude-code", "codex", "hermes", "deepseek", "--scope", "user", "project", "--workspace", "--yes", "--dry-run", "--json", "--data-dir"}},
		{Path: []string{"setup", "status"}, Candidates: []string{"claude-code", "codex", "hermes", "deepseek", "cursor", "vscode", "windsurf", "--all", "--scope", "user", "project", "--workspace", "--json", "--format", "text", "json", "--data-dir"}},
		{Path: []string{"version"}, Candidates: []string{"--json"}},
		{Path: []string{"watch"}, Candidates: []string{"--url", "--api-key-file", "--once", "--json"}},
	})
}

func completionCandidates(path []string) []string {
	root := completionWords()
	if len(path) == 0 {
		return root
	}
	path = completionCanonicalPath(path)
	key := strings.Join(path, " ")
	byKey := make(map[string][]string, len(completionContexts()))
	for _, context := range completionContexts() {
		byKey[strings.Join(context.Path, " ")] = uniqueStrings(context.Candidates)
	}
	if candidates, ok := byKey[key]; ok {
		return candidates
	}
	if len(path) > 1 {
		if candidates, ok := byKey[path[0]]; ok {
			return candidates
		}
	}
	return root
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func writeCommandCatalogJSON(out io.Writer) int {
	if err := json.NewEncoder(out).Encode(commandCatalog()); err != nil {
		return 1
	}
	return 0
}
