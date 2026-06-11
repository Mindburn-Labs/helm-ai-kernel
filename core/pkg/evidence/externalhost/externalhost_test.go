package externalhost

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestVerifyChain_ValidSignedChain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := signedTestChain(t, priv)
	chain.PublicKeys = []contracts.ExternalVerifierKey{{
		KeyID:        "host-key-1",
		Algorithm:    "Ed25519",
		PublicKeyHex: hex.EncodeToString(pub),
	}}
	chain.ReceiptChainHash = ComputeChainHash([]string{chain.Receipts[0].ReceiptHash, chain.Receipts[1].ReceiptHash})

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("expected valid chain, got checks: %+v", report.Checks)
	}
	if report.ChainHash != chain.ReceiptChainHash {
		t.Fatalf("chain hash mismatch: %s != %s", report.ChainHash, chain.ReceiptChainHash)
	}
}

func TestVerifyChain_RequireKeyIgnoresEmbeddedPublicKeys(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := signedTestChain(t, priv)
	chain.PublicKeys = []contracts.ExternalVerifierKey{{
		KeyID:        "attacker-key",
		Algorithm:    "Ed25519",
		PublicKeyHex: hex.EncodeToString(pub),
	}}

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("embedded chain public key must not satisfy RequireKey")
	}
	if report.PublicKeyUsed != "" {
		t.Fatalf("embedded key was treated as trusted: %s", report.PublicKeyUsed)
	}
	assertFailedCheck(t, report, "external_host:public_key")
}

func TestVerifyChain_TamperedEventFailsHashAndSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := signedTestChain(t, priv)
	chain.PublicKeys = []contracts.ExternalVerifierKey{{
		KeyID:        "host-key-1",
		Algorithm:    "Ed25519",
		PublicKeyHex: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}}
	chain.Receipts[0].Event.BytesSent = 999

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("tampered chain should fail")
	}
	assertFailedCheck(t, report, "external_host:receipt_hash")
	assertFailedCheck(t, report, "external_host:signature")
}

func TestVerifyChain_PrevHashMismatchFails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := signedTestChain(t, priv)
	chain.PublicKeys = []contracts.ExternalVerifierKey{{
		KeyID:        "host-key-1",
		Algorithm:    "Ed25519",
		PublicKeyHex: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}}
	chain.Receipts[1].PrevReceiptHash = "sha256:wrong"

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("prev hash mismatch should fail")
	}
	assertFailedCheck(t, report, "external_host:prev_hash")
}

func TestVerifyChain_MissingPublicKeyFails(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := signedTestChain(t, priv)

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("missing public key should fail")
	}
	assertFailedCheck(t, report, "external_host:public_key")
}

func TestVerifyChain_HardwareRootIsNotImplicitlyTrusted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := signedTestChain(t, priv)
	chain.PublicKeys = []contracts.ExternalVerifierKey{{
		KeyID:        "host-key-1",
		Algorithm:    "Ed25519",
		PublicKeyHex: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}}
	chain.Receipts[0].HardwareRoot = &contracts.HardwareRootClaim{
		HardwareRootType: "TPM2",
		QuoteBlobB64:     "dHBtLXF1b3Rl",
	}
	chain.Receipts[0], err = SignReceipt(chain.Receipts[0], priv)
	if err != nil {
		t.Fatal(err)
	}
	chain.Receipts[1].PrevReceiptHash = chain.Receipts[0].ReceiptHash
	chain.Receipts[1], err = SignReceipt(chain.Receipts[1], priv)
	if err != nil {
		t.Fatal(err)
	}

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("TPM2 structural claim should not verify cryptographically in MVP")
	}
	assertFailedCheck(t, report, "external_host:hardware_root")
}

func signedTestChain(t *testing.T, priv ed25519.PrivateKey) *contracts.ExternalReceiptChain {
	t.Helper()
	ts := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	r1 := testReceipt("host-1", "", ts)
	var err error
	r1, err = SignReceipt(r1, priv)
	if err != nil {
		t.Fatal(err)
	}
	r2 := testReceipt("host-2", r1.ReceiptHash, ts.Add(time.Second))
	r2, err = SignReceipt(r2, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		ChainID:       "chain-1",
		Receipts:      []contracts.ExternalHostReceipt{r1, r2},
	}
}

func testReceipt(id, prev string, ts time.Time) contracts.ExternalHostReceipt {
	return contracts.ExternalHostReceipt{
		SchemaVersion:      contracts.ExternalHostReceiptVersion,
		ReceiptID:          id,
		SourceVendor:       "test-recorder",
		HostID:             "host-a",
		ProcessIdentity:    "pid:123",
		ProcessAncestry:    []string{"agent"},
		AgentID:            "agent-1",
		WorkloadID:         "workload-1",
		PrevReceiptHash:    prev,
		SigningKeyID:       "host-key-1",
		SignatureAlgorithm: "Ed25519",
		Event: contracts.NetworkEgressEvent{
			EventID:         id + "-event",
			DestinationIP:   "203.0.113.10",
			DestinationPort: 443,
			Protocol:        "tcp",
			Timestamp:       ts,
			BytesSent:       128,
			BytesReceived:   64,
			Verdict:         "OBSERVED",
		},
	}
}

func assertFailedCheck(t *testing.T, report *VerificationReport, name string) {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name && !check.Pass {
			return
		}
	}
	t.Fatalf("missing failed check %s in %+v", name, report.Checks)
}
