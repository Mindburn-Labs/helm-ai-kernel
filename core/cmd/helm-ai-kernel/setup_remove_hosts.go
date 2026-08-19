// quantum_posture: this file removes configuration only; no signing material is
// read or written here.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Removal exists because the install writes into two third-party consent stores:
// Hermes's shell-hook allowlist and Grok's hook directory. A grant that HELM can
// write and only the operator can withdraw by hand is, in effect, a self-grant —
// the asymmetry matters more than the intent. Every write `setup hermes` and
// `setup grok` make is reversible by these commands, and only HELM's own entries
// are touched.

func runSetupRemoveHermesCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup remove hermes", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var home string
	var dryRun bool
	fs.StringVar(&home, "hermes-home", "", "Hermes home directory (default: $HERMES_HOME or ~/.hermes)")
	fs.BoolVar(&dryRun, "dry-run", false, "Print what would be removed without writing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	resolved := hermesHomeDir(home)
	if strings.TrimSpace(resolved) == "" {
		fmt.Fprintln(stderr, "setup remove hermes: cannot resolve a home directory; pass --hermes-home")
		return 2
	}
	configPath := filepath.Join(resolved, hermesConfigFilename)
	allowlistPath := filepath.Join(resolved, hermesAllowlistFilename)

	if dryRun {
		fmt.Fprintln(stdout, "setup remove hermes (dry run)")
		fmt.Fprintf(stdout, "  would drop HELM hook entries from %s\n", configPath)
		fmt.Fprintf(stdout, "  would drop HELM approvals from    %s\n", allowlistPath)
		return 0
	}

	hooksRemoved, err := removeHermesHookEntries(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "setup remove hermes: update %s: %v\n", configPath, err)
		return 1
	}
	approvalsRemoved, err := removeHermesApprovals(allowlistPath)
	if err != nil {
		fmt.Fprintf(stderr, "setup remove hermes: update %s: %v\n", allowlistPath, err)
		return 1
	}
	fmt.Fprintf(stdout, "Removed %d HELM hook entr%s and %d approval%s.\n",
		hooksRemoved, plural(hooksRemoved, "y", "ies"), approvalsRemoved, plural(approvalsRemoved, "", "s"))
	if hooksRemoved == 0 && approvalsRemoved == 0 {
		fmt.Fprintln(stdout, "Nothing to remove — HELM was not installed in this Hermes home.")
	} else {
		fmt.Fprintln(stdout, "Hermes must be restarted for the change to take effect.")
	}
	return 0
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// isHelmHermesHookCommand recognises only entries this tool wrote, so an
// operator's own hooks are never removed.
func isHelmHermesHookCommand(command string) bool {
	return strings.Contains(command, "hook pre-tool") && strings.Contains(command, "--client hermes")
}

func removeHermesHookEntries(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("parse config (left unchanged): %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return 0, nil
	}
	hooks := yamlExistingChild(doc.Content[0], "hooks")
	if hooks == nil || hooks.Kind != yaml.MappingNode {
		return 0, nil
	}
	events := yamlExistingChild(hooks, hermesHookEvent)
	if events == nil || events.Kind != yaml.SequenceNode {
		return 0, nil
	}
	kept := make([]*yaml.Node, 0, len(events.Content))
	removed := 0
	for _, item := range events.Content {
		if isHelmHermesHookCommand(yamlScalarChild(item, "command")) {
			removed++
			continue
		}
		kept = append(kept, item)
	}
	if removed == 0 {
		return 0, nil
	}
	events.Content = kept

	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return 0, err
	}
	if err := enc.Close(); err != nil {
		return 0, err
	}
	return removed, writeFileAtomic0600(path, []byte(buf.String()))
}

func yamlExistingChild(parent *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			return parent.Content[i+1]
		}
	}
	return nil
}

func removeHermesApprovals(path string) (int, error) {
	removed := 0
	err := withHermesAllowlistLock(path, func() error {
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		payload := map[string]any{}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return fmt.Errorf("parse allowlist (left unchanged): %w", err)
		}
		existing, _ := payload["approvals"].([]any)
		kept := make([]any, 0, len(existing))
		for _, item := range existing {
			entry, ok := item.(map[string]any)
			if ok {
				if command, _ := entry["command"].(string); isHelmHermesHookCommand(command) {
					removed++
					continue
				}
			}
			kept = append(kept, item)
		}
		if removed == 0 {
			return nil
		}
		payload["approvals"] = kept
		out, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		return writeFileAtomic0600(path, append(out, '\n'))
	})
	return removed, err
}

func runSetupRemoveGrokCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup remove grok", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var home string
	var dryRun bool
	fs.StringVar(&home, "grok-home", "", "Grok home directory (default: $GROK_HOME or ~/.grok)")
	fs.BoolVar(&dryRun, "dry-run", false, "Print what would be removed without writing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	resolved := grokHomeDir(home)
	if strings.TrimSpace(resolved) == "" {
		fmt.Fprintln(stderr, "setup remove grok: cannot resolve a home directory; pass --grok-home")
		return 2
	}
	hookPath := filepath.Join(resolved, grokHooksDirName, grokHookFilename)

	if dryRun {
		fmt.Fprintln(stdout, "setup remove grok (dry run)")
		fmt.Fprintf(stdout, "  would delete %s\n", hookPath)
		return 0
	}
	// The file is HELM-owned by construction (setup grok writes only this name),
	// so removing it cannot take an operator hook with it.
	if err := os.Remove(hookPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(stdout, "Nothing to remove — HELM was not installed in this Grok home.")
			return 0
		}
		fmt.Fprintf(stderr, "setup remove grok: remove %s: %v\n", hookPath, err)
		return 1
	}
	fmt.Fprintf(stdout, "Removed %s\n", hookPath)
	return 0
}
