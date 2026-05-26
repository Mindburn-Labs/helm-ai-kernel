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
	code := Run([]string{"helm", "up", "openclaw", "--demo", "--no-open", "--json"}, &stdout, &stderr)
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
	if !strings.Contains(stdout.String(), "/runs/") {
		t.Fatalf("console run deep link missing: %s", stdout.String())
	}
}

func TestUpCommandVerifyOnlyDoesNotRequireRuntime(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "test-key")
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm", "up", "openclaw", "--verify-only", "--no-open", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify-only exit = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), `"started_runtime": true`) {
		t.Fatalf("verify-only should not start runtime: %s", stdout.String())
	}
}
