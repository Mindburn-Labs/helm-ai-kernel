package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSetupHermesPreservesOperatorConfig is the load-bearing guarantee: the file
// belongs to the operator. Setup adds one entry and must not reformat, reorder,
// or strip comments from anything it did not write.
func TestSetupHermesPreservesOperatorConfig(t *testing.T) {
	home := t.TempDir()
	original := "# keep this comment\nmodel:\n  provider: anthropic # and this one\nagent:\n  name: worker\n"
	configPath := filepath.Join(home, hermesConfigFilename)
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := runSetupHermesCmd([]string{"--hermes-home", home, "--data-dir", t.TempDir()}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup hermes = %d, stderr=%s", code, stderr.String())
	}

	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"# keep this comment", "# and this one", "provider: anthropic", "name: worker"} {
		if !strings.Contains(text, want) {
			t.Errorf("config lost %q after setup:\n%s", want, text)
		}
	}
	if strings.Contains(text, "    provider:") {
		t.Errorf("setup reindented the operator's config from 2 spaces to 4:\n%s", text)
	}
}

func TestSetupHermesInstallsFailClosedHookAndApproval(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runSetupHermesCmd([]string{"--hermes-home", home, "--data-dir", t.TempDir()}, &stdout, &stderr); code != 0 {
		t.Fatalf("setup hermes = %d, stderr=%s", code, stderr.String())
	}

	raw, err := os.ReadFile(filepath.Join(home, hermesConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Hooks map[string][]struct {
			Command    string `yaml:"command"`
			Matcher    string `yaml:"matcher"`
			Timeout    int    `yaml:"timeout"`
			FailClosed bool   `yaml:"fail_closed"`
		} `yaml:"hooks"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("emitted config is not parseable by a Hermes-shaped reader: %v\n%s", err, raw)
	}
	entries := cfg.Hooks[hermesHookEvent]
	if len(entries) != 1 {
		t.Fatalf("hooks.%s = %d entries, want 1", hermesHookEvent, len(entries))
	}
	entry := entries[0]
	if !entry.FailClosed {
		t.Error("fail_closed is false — a hook that cannot answer would wave the call through, which is the whole reason to prefer this seam over Claude Code's")
	}
	if entry.Timeout < 1 || entry.Timeout > 300 {
		t.Errorf("timeout = %d, outside the range Hermes accepts", entry.Timeout)
	}
	if !strings.Contains(entry.Command, "hook pre-tool --client hermes") {
		t.Errorf("command = %q, want the hermes client so the denial carries Hermes's dialect", entry.Command)
	}

	// Hermes refuses a hook the operator has not approved; the approval must
	// match the command byte for byte or the hook silently never runs.
	allowRaw, err := os.ReadFile(filepath.Join(home, hermesAllowlistFilename))
	if err != nil {
		t.Fatalf("no allowlist written: %v", err)
	}
	var allow struct {
		Approvals []struct {
			Event   string `json:"event"`
			Command string `json:"command"`
		} `json:"approvals"`
	}
	if err := json.Unmarshal(allowRaw, &allow); err != nil {
		t.Fatal(err)
	}
	if len(allow.Approvals) != 1 {
		t.Fatalf("approvals = %d, want 1", len(allow.Approvals))
	}
	if allow.Approvals[0].Command != entry.Command {
		t.Errorf("approval command %q != configured command %q; Hermes would refuse to run the hook",
			allow.Approvals[0].Command, entry.Command)
	}
	if allow.Approvals[0].Event != hermesHookEvent {
		t.Errorf("approval event = %q, want %q", allow.Approvals[0].Event, hermesHookEvent)
	}
}

func TestSetupHermesIsIdempotent(t *testing.T) {
	home := t.TempDir()
	data := t.TempDir()
	for i := 0; i < 3; i++ {
		var stdout, stderr bytes.Buffer
		if code := runSetupHermesCmd([]string{"--hermes-home", home, "--data-dir", data}, &stdout, &stderr); code != 0 {
			t.Fatalf("install %d = %d, stderr=%s", i, code, stderr.String())
		}
	}
	raw, _ := os.ReadFile(filepath.Join(home, hermesConfigFilename))
	if n := strings.Count(string(raw), "command:"); n != 1 {
		t.Errorf("re-running setup duplicated the hook: %d entries\n%s", n, raw)
	}
	allowRaw, _ := os.ReadFile(filepath.Join(home, hermesAllowlistFilename))
	var allow struct {
		Approvals []json.RawMessage `json:"approvals"`
	}
	_ = json.Unmarshal(allowRaw, &allow)
	if len(allow.Approvals) != 1 {
		t.Errorf("re-running setup duplicated the approval: %d", len(allow.Approvals))
	}
}

func TestSetupHermesDryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runSetupHermesCmd([]string{"--hermes-home", home, "--data-dir", t.TempDir(), "--dry-run"}, &stdout, &stderr); code != 0 {
		t.Fatalf("dry run = %d, stderr=%s", code, stderr.String())
	}
	for _, name := range []string{hermesConfigFilename, hermesAllowlistFilename} {
		if _, err := os.Stat(filepath.Join(home, name)); !os.IsNotExist(err) {
			t.Errorf("--dry-run created %s", name)
		}
	}
	if !strings.Contains(stdout.String(), "dry run") {
		t.Errorf("dry run did not say so: %s", stdout.String())
	}
}

func TestSetupHermesRefusesToRewriteUnparseableConfig(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, hermesConfigFilename)
	broken := "model:\n  provider: [unclosed\n"
	if err := os.WriteFile(configPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runSetupHermesCmd([]string{"--hermes-home", home, "--data-dir", t.TempDir()}, &stdout, &stderr); code == 0 {
		t.Error("setup succeeded on an unparseable config; it must refuse rather than overwrite")
	}
	got, _ := os.ReadFile(configPath)
	if string(got) != broken {
		t.Errorf("setup modified a config it could not parse:\n%s", got)
	}
}
