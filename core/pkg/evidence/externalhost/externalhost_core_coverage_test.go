package externalhost

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestParseVariantsAndVerifyFile(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := signedTestChain(t, priv)
	chain.PublicKeys = []contracts.ExternalVerifierKey{{
		Algorithm:    "Ed25519",
		PublicKeyHex: hex.EncodeToString(pub),
	}}
	chain.ReceiptChainHash = ComputeChainHash([]string{chain.Receipts[0].ReceiptHash, chain.Receipts[1].ReceiptHash})

	chainBytes, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	parsed, err := Parse(chainBytes)
	if err != nil {
		t.Fatalf("Parse chain: %v", err)
	}
	if parsed.SchemaVersion != contracts.ExternalReceiptChainVersion || len(parsed.Receipts) != 2 {
		t.Fatalf("parsed chain = %#v", parsed)
	}

	path := filepath.Join(t.TempDir(), "chain.json")
	if err := os.WriteFile(path, chainBytes, 0o600); err != nil {
		t.Fatalf("write chain file: %v", err)
	}
	report, err := VerifyFile(path, VerifyOptions{RequireKey: true})
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if !report.Verified {
		t.Fatalf("VerifyFile report failed: %+v", report.Checks)
	}
	if _, err := ParseFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("ParseFile missing error = nil")
	}

	arrayBytes, err := json.Marshal(chain.Receipts)
	if err != nil {
		t.Fatalf("marshal receipts array: %v", err)
	}
	parsed, err = Parse(arrayBytes)
	if err != nil || len(parsed.Receipts) != 2 {
		t.Fatalf("Parse receipts array = %#v, %v", parsed, err)
	}

	singleBytes, err := json.Marshal(chain.Receipts[0])
	if err != nil {
		t.Fatalf("marshal single receipt: %v", err)
	}
	parsed, err = Parse(singleBytes)
	if err != nil || len(parsed.Receipts) != 1 {
		t.Fatalf("Parse single receipt = %#v, %v", parsed, err)
	}

	line1, _ := json.Marshal(chain.Receipts[0])
	line2, _ := json.Marshal(chain.Receipts[1])
	parsed, err = Parse(append(append(line1, '\n', '\n'), line2...))
	if err != nil || len(parsed.Receipts) != 2 {
		t.Fatalf("Parse JSONL = %#v, %v", parsed, err)
	}
	if _, err := Parse([]byte(" \n\t ")); err == nil {
		t.Fatal("Parse empty error = nil")
	}
	if _, err := Parse([]byte("{")); err == nil {
		t.Fatal("Parse malformed JSONL fallback error = nil")
	}
	if _, err := parseJSONL([]byte("{")); err == nil {
		t.Fatal("parseJSONL malformed line error = nil")
	}
	if _, err := parseJSONL([]byte("\n\n")); err == nil {
		t.Fatal("parseJSONL no receipts error = nil")
	}
	if _, err := VerifyFile(filepath.Join(t.TempDir(), "missing.json"), VerifyOptions{}); err == nil {
		t.Fatal("VerifyFile missing path error = nil")
	}

	needsDefaults := &contracts.ExternalReceiptChain{
		SourceVendor:  "chain-vendor",
		SourceProfile: "chain-profile",
		Receipts: []contracts.ExternalHostReceipt{{
			ReceiptID: "needs-defaults",
			HostID:    "host",
			Event: contracts.NetworkEgressEvent{
				DestinationHost: "example.test",
				DestinationPort: 443,
				Protocol:        "tcp",
				Timestamp:       time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC),
			},
			ReceiptHash: "sha256:placeholder",
		}},
	}
	normalizeChain(needsDefaults)
	if needsDefaults.Receipts[0].SchemaVersion == "" ||
		needsDefaults.Receipts[0].SourceVendor != "chain-vendor" ||
		needsDefaults.Receipts[0].SourceProfile != "chain-profile" {
		t.Fatalf("normalizeChain did not fill defaults: %#v", needsDefaults.Receipts[0])
	}
}

func TestVerifyChainSchemaSignatureAndHardwareBranches(t *testing.T) {
	report, err := VerifyChain(nil, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain nil: %v", err)
	}
	if report.Verified {
		t.Fatal("nil chain should not verify")
	}

	report, err = VerifyChain(&contracts.ExternalReceiptChain{}, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain empty: %v", err)
	}
	if report.Verified {
		t.Fatal("empty chain should not verify")
	}

	base := hashedReceipt(testReceipt("schema", "", time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)))
	tests := []struct {
		name   string
		mutate func(*contracts.ExternalHostReceipt)
	}{
		{"missing receipt id", func(r *contracts.ExternalHostReceipt) { r.ReceiptID = "" }},
		{"missing host id", func(r *contracts.ExternalHostReceipt) { r.HostID = "" }},
		{"missing destination", func(r *contracts.ExternalHostReceipt) {
			r.Event.DestinationIP = ""
			r.Event.DestinationHost = ""
		}},
		{"bad port", func(r *contracts.ExternalHostReceipt) { r.Event.DestinationPort = 0 }},
		{"missing protocol", func(r *contracts.ExternalHostReceipt) { r.Event.Protocol = "" }},
		{"missing timestamp", func(r *contracts.ExternalHostReceipt) { r.Event.Timestamp = time.Time{} }},
		{"missing hash", func(r *contracts.ExternalHostReceipt) { r.ReceiptHash = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipt := base
			tt.mutate(&receipt)
			if err := validateReceipt(&receipt); err == nil {
				t.Fatal("validateReceipt error = nil")
			}
			report, err := VerifyChain(&contracts.ExternalReceiptChain{Receipts: []contracts.ExternalHostReceipt{receipt}}, VerifyOptions{})
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			if report.Verified {
				t.Fatal("invalid schema receipt should not verify")
			}
		})
	}

	unsigned := base
	unsigned.Signature = ""
	report, err = VerifyChain(&contracts.ExternalReceiptChain{Receipts: []contracts.ExternalHostReceipt{unsigned}}, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain unsigned: %v", err)
	}
	if !report.Verified {
		t.Fatalf("unsigned optional-signature receipt should verify: %+v", report.Checks)
	}
	report, err = VerifyChain(&contracts.ExternalReceiptChain{Receipts: []contracts.ExternalHostReceipt{unsigned}}, VerifyOptions{RequireKey: true})
	if err != nil {
		t.Fatalf("VerifyChain unsigned require key: %v", err)
	}
	if report.Verified {
		t.Fatal("unsigned required-signature receipt should not verify")
	}

	unsupportedAlg := base
	unsupportedAlg.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	unsupportedAlg.SignatureAlgorithm = "RSA"
	check := verifySignatureCheck(unsupportedAlg, hex.EncodeToString(make([]byte, ed25519.PublicKeySize)), true)
	if check.Pass {
		t.Fatal("unsupported signature algorithm check passed")
	}
	badPub := verifySignatureCheck(unsupportedAlg, "not-hex", true)
	if badPub.Pass {
		t.Fatal("bad public key check passed")
	}
	badSig := base
	badSig.Signature = "%%%not-base64%%%"
	if check := verifySignatureCheck(badSig, hex.EncodeToString(make([]byte, ed25519.PublicKeySize)), true); check.Pass {
		t.Fatal("bad signature encoding check passed")
	}
	signedWithoutKey := base
	signedWithoutKey.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if check := verifySignatureCheck(signedWithoutKey, "", false); check.Pass {
		t.Fatal("signature without public key check passed")
	}

	hardware := base
	hardware.HardwareRoot = &contracts.HardwareRootClaim{HardwareRootType: "bogus"}
	if check := verifyHardwareRootCheck(hardware); check.Pass {
		t.Fatal("unsupported hardware root check passed")
	}
	hardware.HardwareRoot = &contracts.HardwareRootClaim{HardwareRootType: "TPM2", QuoteBlobB64: "not-base64"}
	if check := verifyHardwareRootCheck(hardware); check.Pass {
		t.Fatal("invalid quote hardware root check passed")
	}

	mismatch := &contracts.ExternalReceiptChain{
		Receipts:         []contracts.ExternalHostReceipt{base},
		ReceiptChainHash: "sha256:wrong",
	}
	report, err = VerifyChain(mismatch, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain chain hash mismatch: %v", err)
	}
	if report.Verified {
		t.Fatal("chain hash mismatch should not verify")
	}

	second := base
	second.ReceiptID = "second"
	second.PrevReceiptHash = "sha256:any"
	report, err = VerifyChain(&contracts.ExternalReceiptChain{Receipts: []contracts.ExternalHostReceipt{
		{ReceiptID: "invalid-first"},
		second,
	}}, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain prev hash unavailable: %v", err)
	}
	if report.Verified {
		t.Fatal("prev hash unavailable chain should not verify")
	}
}

func TestSignReceiptDefaultsSignatureAlgorithm(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receipt := testReceipt("default-alg", "", time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC))
	receipt.SignatureAlgorithm = ""
	signed, err := SignReceipt(receipt, priv)
	if err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}
	if signed.SignatureAlgorithm != "Ed25519" || signed.Signature == "" || signed.ReceiptHash == "" {
		t.Fatalf("signed receipt missing defaults: %#v", signed)
	}
}

func hashedReceipt(receipt contracts.ExternalHostReceipt) contracts.ExternalHostReceipt {
	hash, err := ComputeReceiptHash(receipt)
	if err != nil {
		panic(err)
	}
	receipt.ReceiptHash = hash
	return receipt
}
