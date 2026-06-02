package receipts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func TestWriteEvidencePackMaterializesRequiredDirectories(t *testing.T) {
	packDir, err := WriteEvidencePack(t.TempDir(), "launch-test", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, keep := range []string{
		"03_TELEMETRY/.keep",
		"05_DIFFS/.keep",
		"06_LOGS/.keep",
		"07_ATTESTATIONS/.keep",
		"08_TAPES/.keep",
		"09_SCHEMAS/.keep",
		"11_HOST_EVIDENCE/.keep",
		"12_REPORTS/.keep",
	} {
		if _, err := os.Stat(filepath.Join(packDir, keep)); err != nil {
			t.Fatalf("required EvidencePack placeholder %s missing: %v", keep, err)
		}
	}
	report, err := verifier.VerifyBundle(packDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("EvidencePack did not verify: %s", report.Summary)
	}
}

func TestWriteEvidencePackBuildsEvidenceGraph(t *testing.T) {
	packDir, err := WriteEvidencePack(t.TempDir(), "launch-graph", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","type":"launchpad.kernel_verdict","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
		"receipts/launch.json":         []byte(`{"receipt_id":"r2","type":"launchpad.launch","decision_id":"d2","decision_hash":"sha256:test2","status":"ALLOW","verdict":"ALLOW","lamport_clock":2}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(packDir, "04_EXPORTS", "launchpad_evidence_graph.json"))
	if err != nil {
		t.Fatal(err)
	}
	var graph EvidenceGraph
	if err := json.Unmarshal(data, &graph); err != nil {
		t.Fatal(err)
	}
	if graph.LaunchID != "launch-graph" || graph.RootHash == "" || len(graph.Nodes) != 2 {
		t.Fatalf("unexpected evidence graph: %+v", graph)
	}
	if graph.Nodes[1].PreviousHash != graph.Nodes[0].ChainHash {
		t.Fatalf("receipt graph is not hash chained: %+v", graph.Nodes)
	}
}

func TestWriteEvidencePackRewriteKeepsEvidenceGraphHashCurrent(t *testing.T) {
	root := t.TempDir()
	if _, err := WriteEvidencePack(root, "launch-rewrite", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","type":"launchpad.kernel_verdict","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
	}); err != nil {
		t.Fatal(err)
	}
	packDir, err := WriteEvidencePack(root, "launch-rewrite", map[string][]byte{
		"receipts/teardown.json": []byte(`{"receipt_id":"r2","type":"launchpad.teardown","decision_id":"d2","decision_hash":"sha256:test2","status":"ALLOW","verdict":"ALLOW","lamport_clock":2}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := verifier.VerifyBundle(packDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("rewritten EvidencePack did not verify: %s", report.Summary)
	}
}

func TestWriteEvidencePackRedactsSecretLikePayloads(t *testing.T) {
	secret := strings.Join([]string{"sk", "or", "v1"}, "-") + "-" + strings.Repeat("a", 24)
	deepseekSecret := "deepseek-token-" + strings.Repeat("b", 24)
	packDir, err := WriteEvidencePack(t.TempDir(), "launch-redact", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","type":"launchpad.kernel_verdict","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
		"runtime_environment.json":     []byte(`{"OPENROUTER_API_KEY":"` + secret + `","DEEPSEEK_API_KEY":"` + deepseekSecret + `"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(packDir, "04_EXPORTS", "runtime_environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), deepseekSecret) {
		t.Fatalf("secret-like payload was not redacted: %s", data)
	}
	var payload map[string]string
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("redaction must preserve JSON validity: %v: %s", err, data)
	}
	if payload["OPENROUTER_API_KEY"] != "[REDACTED_SECRET]" {
		t.Fatalf("unexpected redacted payload: %#v", payload)
	}
	if payload["DEEPSEEK_API_KEY"] != "[REDACTED_SECRET]" {
		t.Fatalf("catalog provider secret assignment was not redacted: %#v", payload)
	}
}
