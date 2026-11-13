package main

// quantum_posture: classical Ed25519/SHA-256 only; no post-quantum assurance
// is claimed or provided by this file.

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
	chainPath, pubHex := writeCLIHostChain(t, root, "workload-1", "203.0.113.10")
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
	verifyReport, err := verifier.VerifyBundleWithOptions(outDir, verifier.VerifyOptions{ExternalHostKeyHex: pubHex,
		// Pack sealed by this test; self-attested seal is expected (F-02).
		AllowSelfAttested: true})
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

// TestCorrelateHostReadsAReceiptFileAsItsReaderDoes is helm-tracker#305
// round 3 finding NF6. evidence correlate-host decoded each receipt file of
// the pack into contracts.Receipt with encoding/json, which binds "Verdict" to
// verdict. A network receipt that says DENY to jq and to every exact-name
// reader, with "Status" and "Verdict" of ALLOW appended, was correlated as
// allowed host egress and reported no Boundary Drift. A receipt file the
// member-name rules of receiptverify.ValidateReceiptMemberNames refuse now
// stops the command.
func TestCorrelateHostReadsAReceiptFileAsItsReaderDoes(t *testing.T) {
	const deny = `{"receipt_id":"r-network","decision_id":"d-network","decision_hash":"sha256:test","type":"NETWORK_EGRESS_DENIED","effect_type":"WORKSTATION_NETWORK_EGRESS","status":"DENY","verdict":"DENY","lamport_clock":1,"timestamp":"2026-05-21T12:00:00Z","metadata":{"workload_id":"workload-1","destination_ip":"203.0.113.10","destination_port":"443","protocol":"tcp","max_egress_bytes":"1024"}}`
	correlate := func(receipt string) (int, string, string) {
		t.Helper()
		root := t.TempDir()
		chainPath, _ := writeCLIHostChain(t, root, "workload-1", "203.0.113.10")
		packDir, err := lpreceipts.WriteEvidencePack(root, "launch-host-evidence", map[string][]byte{"receipts/network.json": []byte(receipt)})
		if err != nil {
			t.Fatal(err)
		}
		outDir := filepath.Join(root, "attached-pack")
		var stdout, stderr bytes.Buffer
		if code := runEvidenceAttachHostChain([]string{"--bundle", packDir, "--chain", chainPath, "--out", outDir, "--source", "test"}, &stdout, &stderr); code != 0 {
			t.Fatalf("attach exit=%d stderr=%s", code, stderr.String())
		}
		stdout.Reset()
		stderr.Reset()
		code := runEvidenceCorrelateHost([]string{"--bundle", outDir}, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	if code, stdout, stderr := correlate(deny); code != 1 || !strings.Contains(stdout, string(contracts.HostCorrelationPolicyDeniedHostEgress)) {
		t.Fatalf("host egress after the genuine DENY must be Boundary Drift; the case proves nothing: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	shadowed := strings.TrimSuffix(deny, "}") + `,"Status":"ALLOW","Verdict":"ALLOW"}`
	var exact map[string]any
	if err := json.Unmarshal([]byte(shadowed), &exact); err != nil || exact["verdict"] != "DENY" || exact["status"] != "DENY" {
		t.Fatalf("the planted receipt does not read DENY by exact name; the case proves nothing (%v)", err)
	}
	code, stdout, stderr := correlate(shadowed)
	if code != 2 || !strings.Contains(stderr, "network.json") || !strings.Contains(stderr, "letter case") {
		t.Fatalf("a receipt file with a letter-case Verdict must stop correlate-host and be named: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, tc := range []struct {
		name, receipt, reason string
	}{
		{"duplicate verdict", strings.TrimSuffix(deny, "}") + `,"verdict":"ALLOW"}`, "duplicate object member"},
		{"invalid JSON", `{"receipt_id":`, "invalid receipt JSON"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := correlate(tc.receipt)
			if code != 2 || !strings.Contains(stderr, "network.json") || !strings.Contains(stderr, tc.reason) {
				t.Fatalf("a refused receipt must stop correlate-host and be named: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
		})
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
