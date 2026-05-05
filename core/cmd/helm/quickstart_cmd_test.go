package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadServePolicyTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release.high_risk.v3.toml")
	if err := os.WriteFile(path, []byte(`
name = "release.high_risk.v3"
profile = "high_risk"
reference_pack = "./reference_packs/eu_ai_act_high_risk.v1.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`), 0600); err != nil {
		t.Fatal(err)
	}

	policy, err := loadServePolicy(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if policy.Server.Port != 7714 || policy.Receipts.Store != "sqlite" {
		t.Fatalf("unexpected policy: %+v", policy)
	}
}

func TestLoadServePolicyRuntimeCompilesReferencePackActions(t *testing.T) {
	dir := t.TempDir()
	refDir := filepath.Join(dir, "reference_packs")
	if err := os.MkdirAll(refDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(refDir, "runtime.json"), []byte(`{
  "pack_id": "runtime-pack",
  "version": 1,
  "runtime_actions": [
    {"action": "EXECUTE_TOOL", "expression": "true", "description": "allow test tool execution"}
  ]
}`), 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(`
name = "runtime"
profile = "test"
reference_pack = "./reference_packs/runtime.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`), 0600); err != nil {
		t.Fatal(err)
	}

	runtime, err := loadServePolicyRuntime(policyPath)
	if err != nil {
		t.Fatalf("load runtime: %v", err)
	}
	if runtime.ReferencePack.PackID != "runtime-pack" {
		t.Fatalf("pack id = %q", runtime.ReferencePack.PackID)
	}
	rule, ok := runtime.Graph.Rules["EXECUTE_TOOL"]
	if !ok {
		t.Fatalf("expected EXECUTE_TOOL rule")
	}
	if len(rule.Requirements) != 1 || rule.Requirements[0].Expression != "true" {
		t.Fatalf("unexpected rule: %+v", rule)
	}
}

func TestLoadServePolicyRuntimeRequiresValidReferencePack(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte(`
name = "runtime"
profile = "test"
reference_pack = "./missing.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadServePolicyRuntime(policyPath); err == nil {
		t.Fatal("expected missing reference pack error")
	}
}

func TestRunServerCommandServeRequiresPolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runServerCommand("serve", nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "requires --policy") {
		t.Fatalf("stderr missing policy error: %s", stderr.String())
	}
}

func TestVerifyCmdAcceptsPositionalBundle(t *testing.T) {
	bundle := createMinimalVerifiableBundle(t)
	var stdout, stderr bytes.Buffer

	code := runVerifyCmd([]string{bundle}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatalf("stdout missing compact verification: %s", stdout.String())
	}
}

func TestVerifyCmdOnlineUsesLedgerURL(t *testing.T) {
	bundle := createMinimalVerifiableBundle(t)
	ledger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verified":true,"envelope_id":"ep_test","anchor_index":8412094,"sealed_at":"2024-11-08T10:24:18.402Z","signature_valid_count":1,"signature_total_count":1,"merkle_root":"root"}`))
	}))
	defer ledger.Close()

	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{bundle, "--online", "--ledger-url", ledger.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "anchor #8412094") {
		t.Fatalf("stdout missing online anchor: %s", stdout.String())
	}
}

func TestReceiptsTailRequiresAgent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runReceiptsCmd([]string{"tail"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--agent is required") {
		t.Fatalf("stderr missing agent error: %s", stderr.String())
	}
}

func TestBuildReceiptsTailURL(t *testing.T) {
	got, err := buildReceiptsTailURL("http://127.0.0.1:7714", "agent.titan.exec", "12", 5)
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:7714/api/v1/receipts/tail?agent=agent.titan.exec&limit=5&since=12" {
		t.Fatalf("url = %s", got)
	}
}

func createMinimalVerifiableBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	receiptsDir := filepath.Join(dir, "receipts")
	if err := os.MkdirAll(receiptsDir, 0750); err != nil {
		t.Fatal(err)
	}
	receipt := []byte(`{"decision_hash":"sha256:decision","signature":"sig","lamport_clock":1}`)
	receiptHash := sha256.Sum256(receipt)
	manifest := fmt.Sprintf(`{"session_id":"ep_test","sealed_at":"2024-11-08T10:24:18.402Z","file_hashes":{"receipts/r1.json":"%s"}}`, hex.EncodeToString(receiptHash[:]))
	files := map[string][]byte{
		"manifest.json":    []byte(manifest),
		"proofgraph.json":  []byte(`{"nodes":[]}`),
		"receipts/r1.json": receipt,
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
