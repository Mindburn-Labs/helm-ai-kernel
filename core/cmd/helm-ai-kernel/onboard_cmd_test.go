package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOnboardLegacyYesPreservesStoreTrustRootAndConfig(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	dataDir := filepath.Join(cwd, "custom-data")
	original := runOnboardSetup
	t.Cleanup(func() { runOnboardSetup = original })
	called := false
	runOnboardSetup = func([]string, io.Writer, io.Writer) int {
		called = true
		return 1
	}

	var stdout, stderr bytes.Buffer
	if code := runOnboardCmd([]string{"--data-dir", dataDir, "--yes"}, &stdout, &stderr); code != 0 {
		t.Fatalf("onboard code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if called {
		t.Fatal("legacy --yes script unexpectedly entered Quickstart")
	}
	pubKey, err := os.ReadFile(filepath.Join(dataDir, "root.pub"))
	if err != nil {
		t.Fatalf("custom data dir root.pub missing: %v", err)
	}
	config, err := os.ReadFile(filepath.Join(cwd, "helm.yaml"))
	if err != nil {
		t.Fatalf("helm.yaml missing: %v", err)
	}
	if !strings.Contains(string(config), `data_dir: "`+dataDir+`"`) {
		t.Fatalf("helm.yaml did not reference custom data dir: %s", string(config))
	}
	if !strings.Contains(string(config), `root_public_key: "`+strings.TrimSpace(string(pubKey))+`"`) {
		t.Fatal("helm.yaml trust root did not match custom data dir public key")
	}
	if _, err := os.Stat(filepath.Join(cwd, "data", "root.key")); !os.IsNotExist(err) {
		t.Fatalf("onboard wrote root.key outside custom data dir: %v", err)
	}
}

func TestOnboardForwardsGuidedFlagsToSetupQuickstart(t *testing.T) {
	original := runOnboardSetup
	t.Cleanup(func() { runOnboardSetup = original })
	var got []string
	runOnboardSetup = func(args []string, _, _ io.Writer) int {
		got = append([]string(nil), args...)
		return 0
	}

	var stdout, stderr bytes.Buffer
	code := runOnboardCmd([]string{
		"--yes", "--data-dir", "/tmp/helm-state", "--profile", "codex",
		"--console", "--console-port", "0", "--no-open", "--offline", "--reset", "--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("onboard exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	want := []string{
		"--quickstart", "--profile", "codex", "--data-dir", "/tmp/helm-state", "--yes", "--json",
		"--console", "--console-port", "0", "--no-open", "--offline", "--reset",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("forwarded args = %#v, want %#v", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("JSON compatibility path wrote terminal narration: %q", stderr.String())
	}
}

func TestOnboardDeprecationKeepsUngatedFirstRunReadOnly(t *testing.T) {
	original := runOnboardSetup
	t.Cleanup(func() { runOnboardSetup = original })
	var got []string
	runOnboardSetup = func(args []string, _, _ io.Writer) int {
		got = append([]string(nil), args...)
		return 2
	}

	var stdout, stderr bytes.Buffer
	code := runOnboardCmd([]string{"--data-dir", "/tmp/helm-state"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("onboard exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "\x1b") || !strings.Contains(stderr.String(), "deprecated") {
		t.Fatalf("onboard deprecation = %q", stderr.String())
	}
	if strings.Contains(strings.Join(got, " "), "--yes") {
		t.Fatalf("ungated onboard forwarded a mutation confirmation: %#v", got)
	}
}

func TestOnboardHelpIsSideEffectFree(t *testing.T) {
	original := runOnboardSetup
	t.Cleanup(func() { runOnboardSetup = original })
	called := false
	runOnboardSetup = func([]string, io.Writer, io.Writer) int {
		called = true
		return 1
	}

	var stdout, stderr bytes.Buffer
	if code := runOnboardCmd([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("onboard help exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if called || stderr.Len() != 0 || strings.Contains(stdout.String(), "\x1b") || !strings.Contains(stdout.String(), "Deprecated") {
		t.Fatalf("onboard help was not side-effect-free: called=%v stdout=%q stderr=%q", called, stdout.String(), stderr.String())
	}
}
