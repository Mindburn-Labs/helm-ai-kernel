package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
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

func TestVerifyCmdRejectsBundledConformancePublicKey(t *testing.T) {
	bundle := createMinimalVerifiableBundle(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conform.SignReport(bundle, "policy-hash", "schema-hash", "attacker", func(data []byte) (string, error) {
		return hex.EncodeToString(ed25519.Sign(priv, data)), nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "public_key.hex"), []byte(hex.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{bundle, "--json"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("verify accepted bundled public_key.hex as a trust root: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "no trusted verification key") {
		t.Fatalf("verify did not report missing external trust root: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if err := os.Remove(filepath.Join(bundle, "public_key.hex")); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = runVerifyCmd([]string{bundle, "--json", "--trusted-public-key", hex.EncodeToString(pub)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify with explicit trusted key failed: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
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
	for _, subdir := range []string{"02_PROOFGRAPH/receipts", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS", "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "12_REPORTS"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(subdir)), 0750); err != nil {
			t.Fatal(err)
		}
	}
	score := []byte(`{"pass":true}`)
	receipt := []byte(`{"decision_hash":"sha256:decision","lamport_clock":1}`)
	proofgraph := []byte(`{"nodes":[]}`)
	files := map[string][]byte{
		"01_SCORE.json":                  score,
		"02_PROOFGRAPH/proofgraph.json":  proofgraph,
		"02_PROOFGRAPH/receipts/r1.json": receipt,
		"03_TELEMETRY/.keep":             []byte("reserved\n"),
		"04_EXPORTS/.keep":               []byte("reserved\n"),
		"05_DIFFS/.keep":                 []byte("reserved\n"),
		"06_LOGS/.keep":                  []byte("reserved\n"),
		"08_TAPES/.keep":                 []byte("reserved\n"),
		"09_SCHEMAS/.keep":               []byte("reserved\n"),
		"12_REPORTS/.keep":               []byte("reserved\n"),
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
	entries := make([]map[string]string, 0, len(files))
	for name, data := range files {
		sum := sha256.Sum256(data)
		entries = append(entries, map[string]string{"path": name, "sha256": hex.EncodeToString(sum[:])})
	}
	indexData, err := json.MarshalIndent(map[string]any{"version": "1.0.0", "entries": entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), append(indexData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), dir, evidencepkg.SealEvidencePackOptions{
		PackID:  "ep_test",
		DataDir: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}
