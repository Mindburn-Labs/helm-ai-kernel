package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSetupGrokWritesDiscoverableHook pins the file to the shape Grok's own
// discovery expects (xai-grok-hooks discovery.rs): an event map whose entries
// pair a matcher with a list of {type, command} handlers. A shape drift here is
// silent — Grok simply finds no hook and every call proceeds ungoverned.
func TestSetupGrokWritesDiscoverableHook(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runSetupGrokCmd([]string{"--grok-home", home, "--data-dir", t.TempDir()}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup grok = %d, stderr=%s", code, stderr.String())
	}

	path := filepath.Join(home, grokHooksDirName, grokHookFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("hook file not written: %v", err)
	}
	var got grokHookFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("hook file is not valid JSON: %v\n%s", err, raw)
	}
	entries := got.Hooks[grokHookEvent]
	if len(entries) != 1 {
		t.Fatalf("hooks.%s = %d entries, want 1", grokHookEvent, len(entries))
	}
	if len(entries[0].Hooks) != 1 {
		t.Fatalf("handlers = %d, want 1", len(entries[0].Hooks))
	}
	handler := entries[0].Hooks[0]
	if handler.Type != "command" {
		t.Errorf("handler type = %q, want \"command\" — Grok ignores unknown handler types", handler.Type)
	}
	if !strings.Contains(handler.Command, "hook pre-tool --client grok") {
		t.Errorf("command = %q, want --client grok so the denial carries the top-level `decision` Grok reads", handler.Command)
	}
	if _, err := regexp.Compile(entries[0].Matcher); err != nil {
		t.Errorf("matcher is not a valid regex (%v); Grok compiles it and would drop the hook: %q", err, entries[0].Matcher)
	}
	for _, tool := range []string{"Bash", "run_terminal_command", "Edit", "Write", "mcp__github__create_issue"} {
		if ok, _ := regexp.MatchString(entries[0].Matcher, tool); !ok {
			t.Errorf("matcher does not cover tool %q", tool)
		}
	}
}

func TestSetupGrokIsIdempotentAndDryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	data := t.TempDir()

	var out, errb bytes.Buffer
	if code := runSetupGrokCmd([]string{"--grok-home", home, "--data-dir", data, "--dry-run"}, &out, &errb); code != 0 {
		t.Fatalf("dry run = %d", code)
	}
	if _, err := os.Stat(filepath.Join(home, grokHooksDirName)); !os.IsNotExist(err) {
		t.Error("--dry-run created the hooks directory")
	}

	var first, second []byte
	for i := 0; i < 2; i++ {
		out.Reset()
		errb.Reset()
		if code := runSetupGrokCmd([]string{"--grok-home", home, "--data-dir", data}, &out, &errb); code != 0 {
			t.Fatalf("install %d = %d, stderr=%s", i, code, errb.String())
		}
		raw, err := os.ReadFile(filepath.Join(home, grokHooksDirName, grokHookFilename))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = raw
		} else {
			second = raw
		}
	}
	if string(first) != string(second) {
		t.Errorf("re-running setup changed the hook file:\n%s\n---\n%s", first, second)
	}
}

// TestSetupGrokStatesTheFailOpenLimit guards a claim boundary, not a behaviour:
// Grok's hook rail proceeds when a hook cannot run, and the operator must be told
// that rather than inferring HELM is a sandbox on that host.
func TestSetupGrokStatesTheFailOpenLimit(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runSetupGrokCmd([]string{"--grok-home", home, "--data-dir", t.TempDir()}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup grok = %d", code)
	}
	if !strings.Contains(stdout.String(), "fail-open") {
		t.Errorf("setup grok did not disclose the host's fail-open hook rail:\n%s", stdout.String())
	}
}
