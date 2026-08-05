// quantum_posture: doctor tests exercise classical Ed25519 root-key fixtures
// and SHA-256 redaction checks only; no post-quantum cryptographic control is
// implemented or claimed.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

func TestDoctorDoesNotLeakRootKeySeed(t *testing.T) {
	dir := t.TempDir()
	seed := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.pub"), []byte("public-key-fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_DATA_DIR", dir)

	for _, args := range [][]string{{"--json"}, {"--verbose"}} {
		var stdout, stderr bytes.Buffer
		_ = runDoctorCmd(args, &stdout, &stderr)
		out := stdout.String()
		if strings.Contains(out, seed) || strings.Contains(out, seed[:12]) {
			t.Fatalf("doctor output leaked root key seed for args %v: %s", args, out)
		}
		if !strings.Contains(out, "public_key_hash") {
			t.Fatalf("doctor output should use public key hash detail for args %v: %s", args, out)
		}
	}
}

func TestDoctorRenderTextHonorsSharedNoColorCapability(t *testing.T) {
	results := []CheckResult{{
		Name:       "crypto_keys",
		Status:     statusFail,
		Message:    "No keypair found",
		Suggestion: "Run: helm-ai-kernel init",
	}}
	summary := doctorSummary{Fail: 1}
	caps := ui.CapabilitiesFor(true, true, ui.TerminalOptions{
		NoColor: true,
		Term:    "xterm-256color",
		Width:   80,
	})
	var out bytes.Buffer
	if code := renderTextWithCaps(&out, results, summary, false, caps); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("doctor output should not contain ANSI under NO_COLOR: %q", out.String())
	}
}

func TestDoctorRenderTextUsesSemanticStatusLabels(t *testing.T) {
	results := []CheckResult{
		{Name: "crypto_keys", Status: statusPass, Message: "Ed25519 keypair loaded"},
		{Name: "evidence_store", Status: statusWarn, Message: "Evidence directory missing", Suggestion: "Run setup"},
		{Name: "policy_bundles", Status: statusFail, Message: "No policy bundle found", Suggestion: "Run setup"},
		{Name: "go_version", Status: statusInfo, Message: "go1.test"},
	}
	summary := doctorSummary{Pass: 2, Warn: 1, Fail: 1}

	cases := []struct {
		name      string
		caps      ui.Capabilities
		wantANSI  bool
		wantASCII bool
	}{
		{
			name:     "color terminal",
			caps:     ui.CapabilitiesFor(true, true, ui.TerminalOptions{Term: "xterm-256color", Width: 80}),
			wantANSI: true,
		},
		{
			name: "NO_COLOR",
			caps: ui.CapabilitiesFor(true, true, ui.TerminalOptions{
				NoColor: true,
				Term:    "xterm-256color",
				Width:   80,
			}),
		},
		{
			name: "dumb terminal",
			caps: ui.CapabilitiesFor(true, true, ui.TerminalOptions{
				Term:  "dumb",
				Width: 80,
			}),
			wantASCII: true,
		},
		{
			name:      "noninteractive pipe",
			caps:      ui.CapabilitiesFor(false, false, ui.TerminalOptions{Width: 80}),
			wantASCII: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := renderTextWithCaps(&out, results, summary, false, tc.caps); code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			got := out.String()
			for _, label := range []string{"[PASS]", "[WARN]", "[FAIL]", "[INFO]", "Next action: Run setup"} {
				if !strings.Contains(got, label) {
					t.Fatalf("doctor output = %q, missing %q", got, label)
				}
			}
			for _, legacy := range []string{"✅", "⚠️", "❌", "ℹ️", "crypto_keys            "} {
				if strings.Contains(got, legacy) {
					t.Fatalf("doctor output retained command-local presentation %q: %q", legacy, got)
				}
			}
			if tc.wantANSI != strings.Contains(got, "\x1b[") {
				t.Fatalf("ANSI presence = %t, want %t: %q", strings.Contains(got, "\x1b["), tc.wantANSI, got)
			}
			if tc.wantASCII && strings.ContainsAny(got, "✓×↑…│") {
				t.Fatalf("ASCII fallback contains Unicode decoration: %q", got)
			}
		})
	}
}

func TestDoctorRenderJSONRemainsDataOnly(t *testing.T) {
	results := []CheckResult{{Name: "policy_bundles", Status: statusFail, Message: "No policy bundle found", Suggestion: "Run setup"}}
	summary := doctorSummary{Fail: 1}
	var out bytes.Buffer
	if code := renderJSON(&out, results, summary, false); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("JSON output contains terminal chrome: %q", out.String())
	}

	var report doctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("doctor JSON is not parseable: %v\n%s", err, out.String())
	}
	if len(report.Checks) != 1 || report.Checks[0] != results[0] || report.Summary != summary || report.Healthy {
		t.Fatalf("doctor JSON report = %#v, want checks=%#v summary=%#v healthy=false", report, results, summary)
	}
}
