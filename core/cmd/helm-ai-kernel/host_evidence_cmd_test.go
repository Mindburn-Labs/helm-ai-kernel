package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
	lpreceipts "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func TestVerifyExternalReceiptCmdJSON(t *testing.T) {
	dir := t.TempDir()
	chainPath, pubHex := writeCLIHostChain(t, dir, "workload-1", "203.0.113.10")
	var stdout, stderr bytes.Buffer

	code := runVerifyExternalReceiptCmd([]string{"--chain", chainPath, "--public-key", pubHex, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), `"verified": true`) {
		t.Fatalf("expected verified JSON, got %s", stdout.String())
	}
}

func TestEvidenceAttachHostChainAndCorrelateCLI(t *testing.T) {
	root := t.TempDir()
	chainPath, _ := writeCLIHostChain(t, root, "workload-1", "203.0.113.10")
	packDir, err := lpreceipts.WriteEvidencePack(root, "launch-host-evidence", map[string][]byte{
		"receipts/network.json": []byte(`{"receipt_id":"r-network","decision_id":"d-network","decision_hash":"sha256:test","type":"NETWORK_EGRESS_ALLOWED","effect_type":"WORKSTATION_NETWORK_EGRESS","status":"ALLOW","verdict":"ALLOW","lamport_clock":1,"timestamp":"2026-05-21T12:00:00Z","metadata":{"workload_id":"workload-1","destination_ip":"203.0.113.10","destination_port":"443","protocol":"tcp","max_egress_bytes":"1024"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "attached-pack")
	var stdout, stderr bytes.Buffer
	code := runEvidenceAttachHostChain([]string{"--bundle", packDir, "--chain", chainPath, "--out", outDir, "--source", "test", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("attach exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if _, err := os.Stat(filepath.Join(outDir, "11_HOST_EVIDENCE", "test", filepath.Base(chainPath))); err != nil {
		t.Fatalf("attached chain missing: %v", err)
	}
	verifyReport, err := verifier.VerifyBundle(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyReport.Verified {
		t.Fatalf("attached pack should verify: %+v", verifyReport.Checks)
	}

	stdout.Reset()
	stderr.Reset()
	code = runEvidenceCorrelateHost([]string{"--bundle", outDir, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("correlate exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var report hostCorrelationCLIReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode correlate JSON: %v\n%s", err, stdout.String())
	}
	if report.DriftCount != 0 || report.ResultCount == 0 {
		t.Fatalf("unexpected correlation report: %+v", report)
	}
	if report.Results[0].Status != contracts.HostCorrelationCorrelated {
		t.Fatalf("status=%s, want correlated", report.Results[0].Status)
	}
}

func writeCLIHostChain(t *testing.T, dir, workload, ip string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receipt := contracts.ExternalHostReceipt{
		SchemaVersion: contracts.ExternalHostReceiptVersion,
		ReceiptID:     "host-r1",
		HostID:        "host-a",
		WorkloadID:    workload,
		SigningKeyID:  "host-key",
		Event: contracts.NetworkEgressEvent{
			DestinationIP:   ip,
			DestinationPort: 443,
			Protocol:        "tcp",
			Timestamp:       time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC),
			BytesSent:       32,
			Verdict:         "OBSERVED",
		},
	}
	signed, err := externalhost.SignReceipt(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	chain := contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		ChainID:       "chain-cli",
		PublicKeys: []contracts.ExternalVerifierKey{{
			KeyID:        "host-key",
			Algorithm:    "Ed25519",
			PublicKeyHex: hex.EncodeToString(pub),
		}},
		Receipts: []contracts.ExternalHostReceipt{signed},
	}
	data, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "host-chain.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, hex.EncodeToString(pub)
}
