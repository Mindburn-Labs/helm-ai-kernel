// quantum_posture: this file installs configuration only; decision receipts are
// signed by the classical Ed25519 workstation seed resolved in the hook path.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// Hermes reads shell hooks from a `hooks:` block in config.yaml under its home
// directory, and gates every hook behind a per-user allowlist that records the
// operator's consent. Both are documented in the Hermes source:
// agent/shell_hooks.py (_parse_single_entry, allowlist_path, _record_approval)
// and hermes_constants.py (_get_platform_default_hermes_home).
const (
	hermesConfigFilename    = "config.yaml"
	hermesAllowlistFilename = "shell-hooks-allowlist.json"
	// hermesHookEvent is the only pre-dispatch event Hermes lets a hook block.
	hermesHookEvent = "pre_tool_call"
	// hermesHookTimeout stays inside Hermes's clamp and leaves room for a cold
	// process spawn plus an AST parse and an Ed25519 signature.
	hermesHookTimeout = 20
)

type setupHermesOptions struct {
	DataDir             string
	HermesHome          string
	SigningSeedFile     string
	PolicyProfile       string
	PolicyProfileSHA256 string
	DryRun              bool
}

// hermesHomeDir resolves Hermes's home the same way Hermes does, so setup and
// the agent cannot disagree about which file is live.
func hermesHomeDir(override string) string {
	if trimmed := strings.TrimSpace(override); trimmed != "" {
		return trimmed
	}
	if env := strings.TrimSpace(os.Getenv("HERMES_HOME")); env != "" {
		return env
	}
	if runtime.GOOS == "windows" {
		if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" {
			return filepath.Join(local, "hermes")
		}
		return setupUserPath("AppData", "Local", "hermes")
	}
	return setupUserPath(".hermes")
}

func runSetupHermesCmd(args []string, stdout, stderr io.Writer) int {
	opts := setupHermesOptions{DataDir: defaultSetupDataDir()}
	fs := flag.NewFlagSet("setup hermes", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.DataDir, "data-dir", opts.DataDir, "Directory for HELM local state")
	fs.StringVar(&opts.HermesHome, "hermes-home", "", "Hermes home directory (default: $HERMES_HOME or ~/.hermes)")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	fs.StringVar(&opts.PolicyProfile, "policy-profile", "", "Policy profile JSON path")
	fs.StringVar(&opts.PolicyProfileSHA256, "policy-profile-sha256", "", "Approved SHA-256 digest for the policy profile")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print the planned changes without writing them")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	home := hermesHomeDir(opts.HermesHome)
	if strings.TrimSpace(home) == "" {
		fmt.Fprintln(stderr, "setup hermes: cannot resolve a home directory; pass --hermes-home")
		return 2
	}
	if abs, err := filepath.Abs(opts.DataDir); err == nil {
		opts.DataDir = abs
	}

	bin, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "setup hermes: locate executable: %v\n", err)
		return 1
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	command := hermesHookCommand(opts, bin)

	configPath := filepath.Join(home, hermesConfigFilename)
	allowlistPath := filepath.Join(home, hermesAllowlistFilename)

	if opts.DryRun {
		fmt.Fprintf(stdout, "setup hermes (dry run)\n")
		fmt.Fprintf(stdout, "  config:     %s\n", configPath)
		fmt.Fprintf(stdout, "  allowlist:  %s\n", allowlistPath)
		fmt.Fprintf(stdout, "  event:      %s (fail_closed: true)\n", hermesHookEvent)
		fmt.Fprintf(stdout, "  command:    %s\n", command)
		return 0
	}

	if err := os.MkdirAll(home, 0o700); err != nil {
		fmt.Fprintf(stderr, "setup hermes: create %s: %v\n", home, err)
		return 1
	}
	if err := upsertHermesHookConfig(configPath, command); err != nil {
		fmt.Fprintf(stderr, "setup hermes: update %s: %v\n", configPath, err)
		return 1
	}
	if err := upsertHermesApproval(allowlistPath, hermesHookEvent, command); err != nil {
		fmt.Fprintf(stderr, "setup hermes: update %s: %v\n", allowlistPath, err)
		return 1
	}

	fmt.Fprintf(stdout, "HELM is installed as a Hermes %s hook.\n", hermesHookEvent)
	fmt.Fprintf(stdout, "  config:    %s\n", configPath)
	fmt.Fprintf(stdout, "  allowlist: %s (approval recorded by this command)\n", allowlistPath)
	fmt.Fprintf(stdout, "  fail_closed: true — if HELM cannot answer, Hermes blocks the tool call\n")
	fmt.Fprintln(stdout, "\nHermes must be restarted for the hook to load.")
	return 0
}

func hermesHookCommand(opts setupHermesOptions, bin string) string {
	command := shellQuote(bin) + " hook pre-tool --client hermes --data-dir " + shellQuote(opts.DataDir)
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

// upsertHermesHookConfig inserts or updates HELM's entry in the user's
// config.yaml. It edits a yaml.Node tree rather than round-tripping through a
// map so the operator's comments, key order and formatting survive: this file
// belongs to the user, and setup is not entitled to reformat it.
func upsertHermesHookConfig(path, command string) error {
	var doc yaml.Node
	existing, err := os.ReadFile(path)
	switch {
	case err == nil && len(strings.TrimSpace(string(existing))) > 0:
		if err := yaml.Unmarshal(existing, &doc); err != nil {
			return fmt.Errorf("parse existing config (left unchanged): %w", err)
		}
	case err != nil && !os.IsNotExist(err):
		return err
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("config root is not a mapping; leaving it unchanged")
	}
	root := doc.Content[0]

	hooks, err := yamlMappingChild(root, "hooks", yaml.MappingNode)
	if err != nil {
		return err
	}
	events, err := yamlMappingChild(hooks, hermesHookEvent, yaml.SequenceNode)
	if err != nil {
		return err
	}

	entry := hermesHookEntryNode(command)
	replaced := false
	for i, item := range events.Content {
		if yamlScalarChild(item, "command") == command {
			events.Content[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		events.Content = append(events.Content, entry)
	}

	// yaml.Marshal defaults to a 4-space indent and would silently reformat the
	// operator's whole file; 2 spaces is the prevailing convention and matches
	// what Hermes ships.
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return writeFileAtomic0600(path, buf.Bytes())
}

func hermesHookEntryNode(command string) *yaml.Node {
	scalar := func(v string) *yaml.Node {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
	}
	key := func(v string) *yaml.Node {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
	}
	return &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		key("command"), scalar(command),
		// Hermes only honours `matcher` for pre_tool_call / post_tool_call.
		key("matcher"), scalar("^(terminal|run_terminal_command|bash|shell|write_file|search_replace|edit_file|mcp__.*)$"),
		key("timeout"), {Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(hermesHookTimeout)},
		// The property Claude Code does not offer: a hook that fails to answer
		// blocks the call instead of waving it through.
		key("fail_closed"), {Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"},
	}}
}

// yamlMappingChild returns the value node stored under key in a mapping,
// creating it with the requested kind when absent.
//
// A kind mismatch is refused, never coerced. Coercing would blank the existing
// node — and the node under `hooks.pre_tool_call` may be another operator's
// security hook. Deleting a competing control in order to install ourselves is
// the one thing this command must never do, so it stops and says what it found.
func yamlMappingChild(parent *yaml.Node, key string, kind yaml.Kind) (*yaml.Node, error) {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			child := parent.Content[i+1]
			if child.Kind != kind {
				return nil, fmt.Errorf(
					"%q is %s in this config but HELM needs %s; refusing to overwrite it — resolve it by hand, then re-run",
					key, yamlKindName(child.Kind), yamlKindName(kind))
			}
			return child, nil
		}
	}
	child := &yaml.Node{Kind: kind}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, child)
	return child, nil
}

func yamlKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		return "a scalar"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "an unexpected node"
	}
}

func yamlScalarChild(mapping *yaml.Node, key string) string {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1].Value
		}
	}
	return ""
}

// hermesApproval mirrors agent/shell_hooks.py _record_approval. Hermes refuses to
// run a hook the operator has not approved; running `setup hermes` is that act.
type hermesApproval struct {
	Event                 string  `json:"event"`
	Command               string  `json:"command"`
	ApprovedAt            string  `json:"approved_at"`
	ScriptMtimeAtApproval *string `json:"script_mtime_at_approval"`
}

// withHermesAllowlistLock holds the same exclusive lock Hermes takes before it
// rewrites the allowlist: an flock on a sibling `<file>.lock`
// (agent/shell_hooks.py _locked_update_approvals). Without it, a concurrent
// `hermes hooks revoke` and this read-modify-write can interleave so that HELM
// writes back a stale snapshot and restores an approval the operator had just
// withdrawn — HELM granting authority for a hook that is not its own.
func withHermesAllowlistLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open allowlist lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock allowlist: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func upsertHermesApproval(path, event, command string) error {
	return withHermesAllowlistLock(path, func() error {
		return upsertHermesApprovalLocked(path, event, command)
	})
}

func upsertHermesApprovalLocked(path, event, command string) error {
	payload := map[string]any{}
	if raw, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return fmt.Errorf("parse existing allowlist (left unchanged): %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	kept := []any{}
	if existing, ok := payload["approvals"].([]any); ok {
		for _, item := range existing {
			entry, ok := item.(map[string]any)
			if ok && entry["event"] == event && entry["command"] == command {
				continue // replaced below
			}
			kept = append(kept, item)
		}
	}

	approval := hermesApproval{
		Event:      event,
		Command:    command,
		ApprovedAt: hookNow().Format(time.RFC3339),
	}
	if mtime := hermesScriptMtime(command); mtime != "" {
		approval.ScriptMtimeAtApproval = &mtime
	}
	encoded, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	var asMap map[string]any
	if err := json.Unmarshal(encoded, &asMap); err != nil {
		return err
	}
	payload["approvals"] = append(kept, asMap)

	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic0600(path, append(out, '\n'))
}

// hermesScriptMtime resolves the first token of the hook command to a file and
// returns its mtime, matching Hermes's script_mtime_iso. Hermes uses it to notice
// that an approved hook binary changed after approval.
func hermesScriptMtime(command string) string {
	token := strings.TrimSpace(command)
	if token == "" {
		return ""
	}
	if strings.HasPrefix(token, "'") {
		if end := strings.Index(token[1:], "'"); end >= 0 {
			token = token[1 : end+1]
		}
	} else if idx := strings.IndexByte(token, ' '); idx > 0 {
		token = token[:idx]
	}
	info, err := os.Stat(token)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339)
}

func writeFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
