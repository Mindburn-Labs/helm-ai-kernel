package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	lpreceipts "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
)

func TestEvidenceInspectReportsLaunchpadGraph(t *testing.T) {
	packDir, err := lpreceipts.WriteEvidencePack(t.TempDir(), "launch-inspect", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","type":"launchpad.kernel_verdict","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runEvidenceInspect([]string{"--json", packDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runEvidenceInspect code=%d stderr=%s", code, stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("parse inspect json: %v\n%s", err, stdout.String())
	}
	if report["verified"] != true {
		t.Fatalf("inspect report did not verify: %s", stdout.String())
	}
	if report["evidence_graph_root"] == "" {
		t.Fatalf("inspect report missing graph root: %s", stdout.String())
	}
	if report["evidence_graph_nodes"].(float64) < 1 {
		t.Fatalf("inspect report missing graph nodes: %s", stdout.String())
	}
}

func TestEvidenceDiffComparesIndexedFiles(t *testing.T) {
	root := t.TempDir()
	packA, err := lpreceipts.WriteEvidencePack(root, "launch-diff-a", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","type":"launchpad.kernel_verdict","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	packB, err := lpreceipts.WriteEvidencePack(root, "launch-diff-b", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","type":"launchpad.kernel_verdict","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
		"extra.json":                   []byte(`{"evidence":"new"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runEvidenceDiff([]string{"--json", packA, packB}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runEvidenceDiff code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"identical": false`) || !strings.Contains(stdout.String(), "04_EXPORTS/extra.json") {
		t.Fatalf("diff output missing changed evidence: %s", stdout.String())
	}
}
