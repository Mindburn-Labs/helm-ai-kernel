// quantum_posture: this file installs configuration only; decision receipts are
// signed by the classical Ed25519 workstation seed resolved in the hook path.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Grok Build discovers hooks as `*.json` files in dedicated directories —
// `~/.grok/hooks/` and `<git-worktree-root>/.grok/hooks/` — rather than from a
// key inside the main config (xai-grok-hooks/src/lib.rs, discovery.rs). A
// dedicated file is the durable seam: it is not reachable by the
// `compat.claude` remote-settings flag that governs whether Grok also scans
// Claude Code's settings, so it survives a vendor-side default flip.
const (
	grokHooksDirName = "hooks"
	// grokHookFilename is HELM-owned. Writing our own file rather than editing a
	// shared one means setup never has to parse or rewrite an operator's hooks.
	grokHookFilename = "helm-ai-kernel.json"
	grokHookEvent    = "PreToolUse"
	// grokHookMatcher covers Grok's shell and edit tools plus MCP. Grok compiles
	// `matcher` as a regex against the tool name.
	grokHookMatcher = "^(Bash|run_terminal_command|terminal|shell|Edit|Write|MultiEdit|search_replace|edit_file|mcp__.*)$"
)

type setupGrokOptions struct {
	DataDir             string
	GrokHome            string
	SigningSeedFile     string
	PolicyProfile       string
	PolicyProfileSHA256 string
	DryRun              bool
}

// grokHomeDir mirrors Grok's user_grok_home(): $GROK_HOME when set, else
// ~/.grok.
func grokHomeDir(override string) string {
	if trimmed := strings.TrimSpace(override); trimmed != "" {
		return trimmed
	}
	if env := strings.TrimSpace(os.Getenv("GROK_HOME")); env != "" {
		return env
	}
	return setupUserPath(".grok")
}

// grokHookFile is the shape Grok's discovery expects: an event map whose entries
// pair a matcher with a list of command handlers.
type grokHookFile struct {
	Hooks map[string][]grokHookMatcherEntry `json:"hooks"`
}

type grokHookMatcherEntry struct {
	Matcher string            `json:"matcher,omitempty"`
	Hooks   []grokHookHandler `json:"hooks"`
}

type grokHookHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

func runSetupGrokCmd(args []string, stdout, stderr io.Writer) int {
	opts := setupGrokOptions{DataDir: defaultSetupDataDir()}
	fs := flag.NewFlagSet("setup grok", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.DataDir, "data-dir", opts.DataDir, "Directory for HELM local state")
	fs.StringVar(&opts.GrokHome, "grok-home", "", "Grok home directory (default: $GROK_HOME or ~/.grok)")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	fs.StringVar(&opts.PolicyProfile, "policy-profile", "", "Policy profile JSON path")
	fs.StringVar(&opts.PolicyProfileSHA256, "policy-profile-sha256", "", "Approved SHA-256 digest for the policy profile")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print the planned changes without writing them")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	home := grokHomeDir(opts.GrokHome)
	if strings.TrimSpace(home) == "" {
		fmt.Fprintln(stderr, "setup grok: cannot resolve a home directory; pass --grok-home")
		return 2
	}
	if abs, err := filepath.Abs(opts.DataDir); err == nil {
		opts.DataDir = abs
	}

	bin, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "setup grok: locate executable: %v\n", err)
		return 1
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	command := grokHookCommand(opts, bin)

	hooksDir := filepath.Join(home, grokHooksDirName)
	hookPath := filepath.Join(hooksDir, grokHookFilename)

	if opts.DryRun {
		fmt.Fprintln(stdout, "setup grok (dry run)")
		fmt.Fprintf(stdout, "  hook file: %s\n", hookPath)
		fmt.Fprintf(stdout, "  event:     %s\n", grokHookEvent)
		fmt.Fprintf(stdout, "  matcher:   %s\n", grokHookMatcher)
		fmt.Fprintf(stdout, "  command:   %s\n", command)
		return 0
	}

	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "setup grok: create %s: %v\n", hooksDir, err)
		return 1
	}
	payload := grokHookFile{Hooks: map[string][]grokHookMatcherEntry{
		grokHookEvent: {{
			Matcher: grokHookMatcher,
			Hooks:   []grokHookHandler{{Type: "command", Command: command}},
		}},
	}}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "setup grok: encode hook: %v\n", err)
		return 1
	}
	if err := writeFileAtomic0600(hookPath, append(encoded, '\n')); err != nil {
		fmt.Fprintf(stderr, "setup grok: write %s: %v\n", hookPath, err)
		return 1
	}

	fmt.Fprintf(stdout, "HELM is installed as a Grok Build %s hook.\n", grokHookEvent)
	fmt.Fprintf(stdout, "  hook file: %s\n", hookPath)
	fmt.Fprintln(stdout, "\nTwo limits worth knowing:")
	fmt.Fprintln(stdout, "  - Grok's hook rail is fail-open by design: if this hook cannot run,")
	fmt.Fprintln(stdout, "    the tool call proceeds. HELM decides what it sees; it is not a sandbox.")
	fmt.Fprintln(stdout, "  - A fleet-wide pin that a user config cannot override lives in the")
	fmt.Fprintln(stdout, "    system requirements.toml. It needs root, so this command does not")
	fmt.Fprintln(stdout, "    write it; deploy it through your MDM.")
	return 0
}

func grokHookCommand(opts setupGrokOptions, bin string) string {
	command := shellQuote(bin) + " hook pre-tool --client grok --data-dir " + shellQuote(opts.DataDir)
	if strings.TrimSpace(opts.SigningSeedFile) != "" {
		command += " --signing-seed-file " + shellQuote(opts.SigningSeedFile)
	}
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		command += " --policy-profile " + shellQuote(opts.PolicyProfile)
		if strings.TrimSpace(opts.PolicyProfileSHA256) != "" {
			command += " --policy-profile-sha256 " + shellQuote(opts.PolicyProfileSHA256)
		}
	}
	return command
}
