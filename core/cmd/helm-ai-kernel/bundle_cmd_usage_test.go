package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestBundleBuildUsageStatesWhatItCompiles pins the `bundle` help text to what
// `bundle build` does: it compiles a Rego or Cedar source and prints the
// compiled bundle's identity. It signs nothing, writes no file and rejects CEL.
func TestBundleBuildUsageStatesWhatItCompiles(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runBundleCmd(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("bundle with no subcommand: exit = %d, want 2", code)
	}
	usage := stderr.String()
	const wantBuild = "  build     Compile a Rego or Cedar policy source and print the compiled bundle's identity (no signature, no file)\n"
	if !strings.Contains(usage, wantBuild) {
		t.Fatalf("bundle usage does not describe build as %q:\n%s", wantBuild, usage)
	}
	if strings.Contains(usage, "signed bundle") || strings.Contains(usage, "CEL") {
		t.Fatalf("bundle usage still claims a signed bundle or a CEL build:\n%s", usage)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runBundleCmd([]string{"build"}, &stdout, &stderr); code != 2 {
		t.Fatalf("bundle build with no source: exit = %d, want 2", code)
	}
	const wantUsage = "Usage: helm-ai-kernel bundle build [--language=rego|cedar] [--entities=path] <source>\n"
	if !strings.Contains(stderr.String(), wantUsage) {
		t.Fatalf("bundle build usage = %q, want it to contain %q", stderr.String(), wantUsage)
	}
}

// TestBundleBuildPrintsIdentityOnlyAndRejectsCEL keeps the help text above
// true: the Rego example compiles to an unsigned identity document on stdout,
// and the CEL example is refused.
func TestBundleBuildPrintsIdentityOnlyAndRejectsCEL(t *testing.T) {
	examples := filepath.Join(kernelRepoRoot(t), "examples", "policies")

	var stdout, stderr bytes.Buffer
	if code := runBundleCmd([]string{"build", "--language", "rego", filepath.Join(examples, "rego", "example.rego")}, &stdout, &stderr); code != 0 {
		t.Fatalf("rego build: exit = %d stderr=%s", code, stderr.String())
	}
	var identity map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &identity); err != nil {
		t.Fatalf("rego build output is not one JSON document: %v\n%s", err, stdout.String())
	}
	for _, key := range []string{"bundle_id", "hash", "language", "name", "version"} {
		if _, ok := identity[key]; !ok {
			t.Fatalf("rego build output lacks %q: %v", key, identity)
		}
	}
	if len(identity) != 5 {
		t.Fatalf("rego build output carries more than the bundle identity (a signature would be a new claim): %v", identity)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runBundleCmd([]string{"build", "--language", "cel", filepath.Join(examples, "cel", "example.cel")}, &stdout, &stderr); code != 1 {
		t.Fatalf("cel build: exit = %d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "language=cel is not yet routed through the registry") {
		t.Fatalf("cel build refusal changed: %s", stderr.String())
	}
}
