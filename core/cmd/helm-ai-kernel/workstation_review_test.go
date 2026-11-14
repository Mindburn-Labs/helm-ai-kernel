// quantum_posture: these tests exercise workstation receipts signed with the
// classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// enforceEnvironmentVariables are the variables that change where a network
// client connects or what a shell runs first. enforceShim clears them so the
// environment of whoever runs the tests does not decide them.
var enforceEnvironmentVariables = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "RSYNC_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "rsync_proxy",
	"CURL_HOME", "WGETRC", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND",
	"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT",
	"GIT_CONFIG_PARAMETERS", "GIT_EXEC_PATH", "RSYNC_RSH", "RSYNC_CONNECT_PROG",
	"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV",
}

func clearEnforceEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range enforceEnvironmentVariables {
		if _, ok := os.LookupEnv(name); ok {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// The child runs with the wrapper's environment, so a proxy or a connection
// override set there is part of what the decision covers.
func TestWorkstationEnforceDecidesOnTheEnvironmentItPasses(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	network := []string{"--class", "network", "--target", "https://api.github.com/zen", "--", "curl", "https://api.github.com/zen"}
	cases := []struct {
		name         string
		env          map[string]string
		args         []string
		wantRun      bool
		reason       string
		deniedTarget string
	}{
		{name: "proxy", env: map[string]string{"HTTPS_PROXY": "http://other.example:8080"}, args: network, reason: "EGRESS_DESTINATION_NOT_ALLOWED", deniedTarget: "http://other.example:8080"},
		{name: "lower-case proxy", env: map[string]string{"https_proxy": "http://other.example:8080"}, args: network, reason: "EGRESS_DESTINATION_NOT_ALLOWED", deniedTarget: "http://other.example:8080"},
		{name: "proxy for every scheme", env: map[string]string{"ALL_PROXY": "socks5://other.example:1080"}, args: network, reason: "EGRESS_DESTINATION_NOT_ALLOWED", deniedTarget: "socks5://other.example:1080"},
		{name: "client configuration directory", env: map[string]string{"CURL_HOME": "/tmp/elsewhere"}, args: network, reason: "EGRESS_DESTINATION_UNDETERMINED"},
		{name: "preloaded library", env: map[string]string{"LD_PRELOAD": "/tmp/hook.so"}, args: network, reason: "EGRESS_DESTINATION_UNDETERMINED"},
		{name: "inserted library", env: map[string]string{"DYLD_INSERT_LIBRARIES": "/tmp/hook.dylib"}, args: network, reason: "EGRESS_DESTINATION_UNDETERMINED"},
		{name: "ssh command for git", env: map[string]string{"GIT_SSH_COMMAND": "ssh -o ProxyCommand=nc other.example 22"}, args: network, reason: "EGRESS_DESTINATION_UNDETERMINED"},
		{name: "bash startup file", env: map[string]string{"BASH_ENV": "/tmp/startup.sh"}, args: network, reason: "EGRESS_DESTINATION_UNDETERMINED"},
		{name: "sh startup file", env: map[string]string{"ENV": "/tmp/startup.sh"}, args: network, reason: "EGRESS_DESTINATION_UNDETERMINED"},

		{name: "no variable set", args: network, wantRun: true},
		{name: "empty proxy", env: map[string]string{"HTTPS_PROXY": ""}, args: network, wantRun: true},
		{name: "proxy with a command that does not connect", env: map[string]string{"HTTPS_PROXY": "http://other.example:8080"}, args: []string{"--class", "shell-operate", "--", "python3", "build.py"}, wantRun: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := enforceShim(t, "curl", "python3")
			clearEnforceEnvironment(t)
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			dataDir := filepath.Join(t.TempDir(), "helm")
			var stdout, stderr bytes.Buffer
			code := Run(enforceArgs(dataDir, allow, tc.args...), &stdout, &stderr)
			_, statErr := os.Stat(marker)
			if ran := statErr == nil; ran != tc.wantRun {
				t.Fatalf("command executed = %v, want %v (exit %d stdout=%s stderr=%s)", ran, tc.wantRun, code, stdout.String(), stderr.String())
			}
			receipts := enforceReceipts(t, dataDir)
			if tc.wantRun {
				if code != 0 {
					t.Fatalf("exit = %d, want 0 (stderr=%s)", code, stderr.String())
				}
				for _, receipt := range receipts {
					if receipt.Verdict != contracts.WorkstationVerdictAllow {
						t.Fatalf("command ran beside a %s receipt: %+v", receipt.Verdict, receipt)
					}
				}
				return
			}
			if code != 126 {
				t.Fatalf("exit = %d, want 126 (stdout=%s stderr=%s)", code, stdout.String(), stderr.String())
			}
			found := false
			for _, receipt := range receipts {
				if receipt.Verdict == contracts.WorkstationVerdictDeny && receipt.ReasonCode == tc.reason && (tc.deniedTarget == "" || receipt.Request.Target == tc.deniedTarget) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no DENY/%s receipt for %q among %+v", tc.reason, tc.deniedTarget, receipts)
			}
		})
	}
}

// A wrapper hands its caller the wrapped command's own exit status.
func TestWorkstationEnforceReturnsTheCommandsExitCode(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "build-tool"), []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	clearEnforceEnvironment(t)
	dataDir := filepath.Join(t.TempDir(), "helm")
	var stdout, stderr bytes.Buffer
	if code := Run(enforceArgs(dataDir, allow, "--class", "shell-operate", "--", "build-tool"), &stdout, &stderr); code != 3 {
		t.Fatalf("exit = %d, want the command's 3 (stderr=%s)", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(enforceArgs(dataDir, allow, "--class", "shell-operate", "--", "no-such-program-helm-test"), &stdout, &stderr); code != 127 {
		t.Fatalf("exit for a program that cannot be started = %d, want 127 (stderr=%s)", code, stderr.String())
	}
}

// A command whose receipt cannot be written does not run, and the wrapper
// says so with the code it documents for a command it did not run.
func TestWorkstationEnforceExitsDeniedWhenAReceiptCannotBeWritten(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"denied effect", []string{"--class", "network", "--", "curl", "https://other.example/x"}},
		{"allowed effect", []string{"--class", "network", "--", "curl", "https://api.github.com/zen"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := enforceShim(t, "curl")
			clearEnforceEnvironment(t)
			dataDir := filepath.Join(t.TempDir(), "helm")
			blocked := filepath.Join(t.TempDir(), "not-a-directory")
			if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"helm-ai-kernel", "workstation", "enforce", "--data-dir", dataDir, "--receipt-dir", filepath.Join(blocked, "receipts"), "--policy-profile", allow}
			var stdout, stderr bytes.Buffer
			code := Run(append(args, tc.args...), &stdout, &stderr)
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("command ran although its receipt could not be written (exit %d)", code)
			}
			if code != 126 {
				t.Fatalf("exit = %d, want 126 (stderr=%s)", code, stderr.String())
			}
		})
	}
}

// One operator section printed as JSON carries the same signature checks as
// the whole view: which checks ran, and the status of every item.
func TestWorkstationSectionJSONCarriesTheSignatureChecks(t *testing.T) {
	dir, dataDir := receiptInputs(t)
	importOut := filepath.Join(dir, "denied-memory-import.json")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "workstation", "import", "--artifacts", filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "denied-memory"), "--out", importOut, "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("import exit = %d stderr = %s", code, stderr.String())
	}
	for _, tc := range []struct {
		section, key string
	}{
		{"list", "runs"},
		{"denied", "denied_timeline"},
		{"memory", "memory_review_queue"},
	} {
		t.Run(tc.section, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			if code := Run([]string{"helm-ai-kernel", "workstation", tc.section, "--input", dir, "--data-dir", dataDir, "--json"}, &stdout, &stderr); code != 0 {
				t.Fatalf("%s exit = %d stderr = %s", tc.section, code, stderr.String())
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatalf("%s --json is not an object with the checks: %v\n%s", tc.section, err, stdout.String())
			}
			var verification struct {
				Statuses   map[string]int    `json:"signature_statuses"`
				NotCounted []json.RawMessage `json:"not_counted"`
			}
			if err := json.Unmarshal(envelope["verification"], &verification); err != nil || verification.Statuses[signedByTrustedKey] == 0 || len(verification.NotCounted) != 2 {
				t.Fatalf("%s --json verification = %s (err %v), want the statuses and the two inputs left out", tc.section, envelope["verification"], err)
			}
			var items []map[string]any
			if err := json.Unmarshal(envelope[tc.key], &items); err != nil || len(items) == 0 {
				t.Fatalf("%s --json %s = %s (err %v), want items", tc.section, tc.key, envelope[tc.key], err)
			}
			for _, item := range items {
				if status, _ := item["signature_status"].(string); status == "" {
					t.Fatalf("%s item carries no signature_status: %v", tc.section, item)
				}
			}
		})
	}
}

const signedByTrustedKey = "signed_by_trusted_key"

// An evidence pack is written into a directory of its own: one that holds
// files already, or a link to a file elsewhere, is refused, not written over.
func TestWorkstationEvidenceRefusesADirectoryThatIsNotEmpty(t *testing.T) {
	dir, dataDir := receiptInputs(t)
	importOut := filepath.Join(dir, "denied-memory-import.json")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "workstation", "import", "--artifacts", filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "denied-memory"), "--out", importOut, "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("import exit = %d stderr = %s", code, stderr.String())
	}
	pack := filepath.Join(t.TempDir(), "pack")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "workstation", "evidence", "--receipt", importOut, "--out", pack}, &stdout, &stderr); code != 0 {
		t.Fatalf("first export exit = %d stderr = %s", code, stderr.String())
	}
	stale := filepath.Join(pack, "02_PROOFGRAPH", "receipts", "arr_stale.json")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(pack, "01_SCORE.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(pack, "01_SCORE.json")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code := Run([]string{"helm-ai-kernel", "workstation", "evidence", "--receipt", importOut, "--out", pack}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "not empty") {
		t.Fatalf("export into a used directory: exit = %d stderr = %s, want a refusal that says the directory is not empty", code, stderr.String())
	}
	if data, _ := os.ReadFile(outside); string(data) != "keep" {
		t.Fatalf("a hard-linked file outside the pack was written through: %q", data)
	}
	if data, _ := os.ReadFile(stale); string(data) != "stale" {
		t.Fatalf("a file already in the directory was changed: %q", data)
	}
}

// The retired built-in seed is public, so a receipt it signed is never
// trusted, even when the caller names its key as the trusted one.
func TestWorkstationVerifyDecisionNeverTrustsTheRetiredKey(t *testing.T) {
	receipt := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "reference", "receipts", "decision-network-deny.json")
	legacySeed := sha256.Sum256([]byte("helm-workstation-observe-only-agent-run-receipt-v1"))
	legacyKey := ed25519.NewKeyFromSeed(legacySeed[:]).Public().(ed25519.PublicKey)
	keyFile := filepath.Join(t.TempDir(), "retired.pub")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(legacyKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "workstation", "verify-decision", "--receipt", receipt, "--trusted-public-key-file", keyFile, "--json"}, &stdout, &stderr)
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("verify-decision JSON: %v\n%s\n%s", err, stdout.String(), stderr.String())
	}
	if code != 1 || result["integrity_valid"] != true || result["signer_trusted"] != false {
		t.Fatalf("verify-decision of a retired-key receipt against the retired key: exit=%d result=%v, want integrity true, trust false, exit 1", code, result)
	}
}
