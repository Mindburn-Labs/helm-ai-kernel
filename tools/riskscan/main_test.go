package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// fakeAPIKey is a key-shaped test fixture, built at runtime so secret scanners
// do not flag the source.
var fakeAPIKey = "sk-" + strings.Repeat("1234567890", 3) + "12"

func TestScanCommandWritesLocalArtifacts(t *testing.T) {
	root := scanFixtureRoot(t)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--risk-envelope", filepath.Join(out, "risk.json"),
		"--preview", filepath.Join(out, "risk.md"),
		"--preview", filepath.Join(out, "risk.html"),
		"--evidence-pack", filepath.Join(out, "pack.tar"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("scan code = %d stderr=%s", code, stderr.String())
	}
	for _, name := range []string{"risk.json", "risk.md", "risk.html", "pack.tar"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	riskJSON, _ := os.ReadFile(filepath.Join(out, "risk.json"))
	if bytes.Contains(riskJSON, []byte("customer/private-game")) || bytes.Contains(riskJSON, []byte("deploy-production")) {
		t.Fatalf("risk envelope leaked raw local data: %s", riskJSON)
	}
	if !strings.Contains(stdout.String(), "Content hash: sha256:") {
		t.Fatalf("stdout missing content hash: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Boundary grade: F — ") {
		t.Fatalf("stdout missing boundary grade: %s", stdout.String())
	}
	riskMD, _ := os.ReadFile(filepath.Join(out, "risk.md"))
	if !bytes.Contains(riskMD, []byte("Boundary grade: F")) {
		t.Fatalf("markdown preview missing boundary grade: %s", riskMD)
	}
}

func TestScanCommandPrintsCleanBoundaryGrade(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan",
		"--path", t.TempDir(),
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--no-user-config",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("scan code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	want := "Boundary grade: A — no agent execution surface detected"
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestScanCommandFromReceiptsWritesEnvelope(t *testing.T) {
	receipts := scanReceiptFixtureRoot(t)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan",
		"--from-receipts", receipts,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--risk-envelope", filepath.Join(out, "risk.json"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("scan receipts code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	riskJSON, err := os.ReadFile(filepath.Join(out, "risk.json"))
	if err != nil {
		t.Fatalf("read risk envelope: %v", err)
	}
	if !bytes.Contains(riskJSON, []byte(`"DIRECT_DISPATCH_SEEN"`)) {
		t.Fatalf("receipt-derived risk missing from envelope: %s", riskJSON)
	}
	if bytes.Contains(riskJSON, []byte("customer/private-game")) || bytes.Contains(riskJSON, []byte("curl https://private.example")) {
		t.Fatalf("risk envelope leaked raw receipt data: %s", riskJSON)
	}
}

func TestScanCommandDoesNotExportOnIncompleteCoverage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	output := filepath.Join(out, "risk.json")
	pack := filepath.Join(out, "risk.tar")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--risk-envelope", output,
		"--evidence-pack", pack,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("scan code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "coverage could not be completed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), root) {
		t.Fatalf("stderr leaked local root: %s", stderr.String())
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("risk envelope should not be written, stat error = %v", err)
	}
	if _, err := os.Stat(pack); !os.IsNotExist(err) {
		t.Fatalf("evidence pack should not be written, stat error = %v", err)
	}
}

func TestScanCommandCanExcludeUserConfig(t *testing.T) {
	root := scanFixtureRoot(t)
	home := os.Getenv("HOME")
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "coverage could not be completed") {
		t.Fatalf("default user-config scan code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--no-user-config",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("no-user-config scan code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func scanFixtureRoot(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte("import anthropic\nOPENAI_API_KEY='"+fakeAPIKey+"'\n"), 0o644); err != nil {
		t.Fatalf("write agent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"private-game-prod":{"command":"deploy-production"}}}`), 0o644); err != nil {
		t.Fatalf("write mcp: %v", err)
	}
	claudeDir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"permissionMode":"acceptEdits","project":"customer/private-game"}`), 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	return root
}

func scanReceiptFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	receipt := contracts.WorkstationPolicyDecisionReceipt{
		ReceiptVersion: "workstation_policy_decision.v1",
		DecisionID:     "decision-network",
		Request: contracts.WorkstationDecisionRequest{
			RequestID:    "network-1",
			RunID:        "run-private-game",
			AgentSurface: "codex",
			ToolID:       "curl",
			Action:       "curl https://private.example/customer/private-game",
			EffectType:   contracts.EffectTypeWorkstationNetworkEgress,
			EffectMode:   contracts.WorkstationEffectModeObserve,
			Target:       "customer/private-game",
			OccurredAt:   time.Unix(0, 0).UTC(),
		},
		Verdict:      contracts.WorkstationVerdictAllow,
		ObservedOnly: true,
		CreatedAt:    time.Unix(0, 0).UTC(),
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "decision.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	return root
}

func TestVerifyVerifiesArchiveAndFailsClosedOnTampering(t *testing.T) {
	root := scanFixtureRoot(t)
	out := t.TempDir()
	pack := filepath.Join(out, "scan.tar")
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--evidence-pack", pack,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("scan code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify", "--bundle", pack, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"verified": true`) {
		t.Fatalf("verify output=%s", stdout.String())
	}

	dir := t.TempDir()
	if err := extractArchive(pack, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "risk-envelope.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify", dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("tampered verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "FAILED") {
		t.Fatalf("tampered verify output=%s", stdout.String())
	}
}

// HELM-756: nothing leaves the machine; the upload flags are gone.
func TestScanRejectsRemovedUploadFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--path", t.TempDir(), "--upload"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("--upload code=%d, want %d; stderr=%s", code, exitUsage, stderr.String())
	}
}
