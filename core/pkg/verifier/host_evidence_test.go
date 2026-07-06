package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

// quantum_posture: host-evidence verifier tests cover classical Ed25519
// receipt signatures only; post-quantum host attestation is out of scope here.
func TestVerifyBundle_VerifiesHostEvidenceWhenPresent(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := verifierTestChain(t, priv, hex.EncodeToString(pub))
	data, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	hostDir := filepath.Join(dir, "11_HOST_EVIDENCE", "test")
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "chain.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sealVerifierFixture(t, dir, "canonical-test")

	report, err := VerifyBundleWithOptions(dir, VerifyOptions{ExternalHostKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("expected bundle to verify with signed host evidence: %+v", report.Checks)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "11_HOST_EVIDENCE/test/chain.json:external_host:signature" && check.Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("host evidence signature check missing from report: %+v", report.Checks)
	}
}

func TestVerifyBundle_RejectsSelfSuppliedHostEvidenceKey(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := verifierTestChain(t, priv, hex.EncodeToString(pub))
	data, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	hostDir := filepath.Join(dir, "11_HOST_EVIDENCE", "test")
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "chain.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sealVerifierFixture(t, dir, "canonical-test")

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatalf("self-supplied host evidence key should fail: %+v", report.Checks)
	}
	found := false
	for _, check := range report.Checks {
		if check.Name == "11_HOST_EVIDENCE/test/chain.json:external_host:public_key" && !check.Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing failed public key check: %+v", report.Checks)
	}
}

func verifierTestChain(t *testing.T, priv ed25519.PrivateKey, pubHex string) contracts.ExternalReceiptChain {
	t.Helper()
	receipt := contracts.ExternalHostReceipt{
		SchemaVersion: contracts.ExternalHostReceiptVersion,
		ReceiptID:     "host-r1",
		HostID:        "host-a",
		SigningKeyID:  "host-key",
		Event: contracts.NetworkEgressEvent{
			DestinationIP:   "203.0.113.10",
			DestinationPort: 443,
			Protocol:        "tcp",
			Timestamp:       time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC),
			BytesSent:       1,
		},
	}
	signed, err := externalhost.SignReceipt(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		ChainID:       "chain-1",
		PublicKeys: []contracts.ExternalVerifierKey{{
			KeyID:        "host-key",
			Algorithm:    "Ed25519",
			PublicKeyHex: pubHex,
		}},
		Receipts: []contracts.ExternalHostReceipt{signed},
	}
}
