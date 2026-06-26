package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestUpCommandAcceptsProductSyntaxWithFlagsAfterApp(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm", "up", "openclaw", "--demo", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("up command exit = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode up json: %v\n%s", err, stdout.String())
	}
	if payload["mode"] != "demo" {
		t.Fatalf("mode = %v", payload["mode"])
	}
	if strings.Contains(stdout.String(), "console_url") {
		t.Fatalf("headless launch output should not include console_url: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "offline_verify_command") {
		t.Fatalf("headless launch output missing offline verifier command: %s", stdout.String())
	}
}

func TestUpCommandVerifyOnlyDoesNotRequireRuntime(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "test-key")
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm", "up", "openclaw", "--verify-only", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify-only exit = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	// Match the top-level "run" JSON field, not bare "run" substrings that
	// can legitimately appear inside runtime_command arrays (openclaw's
	// `[openclaw, gateway, run, --port, ...]`) or strings like
	// "helm run open <id>". The contract is "verify-only must not create
	// a runtime run", which corresponds to the absence of the field, not
	// the absence of the four characters anywhere in the document.
	if strings.Contains(stdout.String(), `"run":`) {
		t.Fatalf("verify-only should not emit a runtime run: %s", stdout.String())
	}
}
