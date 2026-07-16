package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
)

func TestScanCommandWritesLocalArtifacts(t *testing.T) {
	root := scanFixtureRoot(t)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "scan",
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
}

func TestScanCommandUploadRequiresURLAndConfirmation(t *testing.T) {
	root := scanFixtureRoot(t)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--upload",
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--upload-url is required") {
		t.Fatalf("missing upload url code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{
		"helm-ai-kernel", "scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--upload",
		"--upload-url", server.URL,
	}, &stdout, &stderr)
	if code != 2 || calls != 0 || !strings.Contains(stderr.String(), "Upload not sent") {
		t.Fatalf("unconfirmed upload code=%d calls=%d stdout=%s stderr=%s", code, calls, stdout.String(), stderr.String())
	}
}

func TestScanCommandUploadSendsPrintedBody(t *testing.T) {
	root := scanFixtureRoot(t)
	out := t.TempDir()
	var got []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--upload",
		"--upload-url", server.URL,
		"--yes",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("upload code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	wantHash := riskenvelope.SHA256Ref(got)
	if !strings.Contains(stdout.String(), "Upload body hash: "+wantHash) {
		t.Fatalf("stdout hash mismatch, want %s in %s", wantHash, stdout.String())
	}
}

func TestScanCommandFromReceiptsWritesEnvelope(t *testing.T) {
	receipts := scanReceiptFixtureRoot(t)
	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "scan",
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
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "scan",
		"--path", root,
		"--salt-file", filepath.Join(out, "salt.hex"),
		"--risk-envelope", output,
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
}

func scanFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte("import anthropic\nOPENAI_API_KEY='sk-12345678901234567890123456789012'\n"), 0o644); err != nil {
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
