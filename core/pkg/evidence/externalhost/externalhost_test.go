package externalhost

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

func TestVerifyChain_ActionEffectReceiptVerifies(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	ts := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	r := contracts.ExternalHostReceipt{
		SchemaVersion: contracts.ExternalHostReceiptVersion,
		ReceiptID:     "action-receipt-1",
		HostID:        "host-b",
		AgentID:       "agent-2",
		EventKind:     contracts.EventKindActionEffect,
		ActionEvent: &contracts.ActionEffectEvent{
			ActionID:  "act-001",
			ToolName:  "github.create_issue",
			TargetRef: "org/repo",
			Timestamp: ts,
		},
	}
	r, err = SignReceipt(r, priv)
	if err != nil {
		t.Fatal(err)
	}
	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		ChainID:       "action-chain-1",
		PublicKeys: []contracts.ExternalVerifierKey{{
			KeyID:        "key-1",
			Algorithm:    "Ed25519",
			PublicKeyHex: hex.EncodeToString(pub),
		}},
		Receipts: []contracts.ExternalHostReceipt{r},
	}
	chain.ReceiptChainHash = ComputeChainHash([]string{r.ReceiptHash})

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("action_effect receipt should verify, got checks: %+v", report.Checks)
	}
}

func TestValidateReceipt_ActionEffectMissingActionEventFails(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := contracts.ExternalHostReceipt{
		SchemaVersion: contracts.ExternalHostReceiptVersion,
		ReceiptID:     "bad-action-receipt",
		HostID:        "host-c",
		EventKind:     contracts.EventKindActionEffect,
		// ActionEvent intentionally nil
	}
	r, err = SignReceipt(r, priv)
	if err != nil {
		t.Fatal(err)
	}
	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		Receipts:      []contracts.ExternalHostReceipt{r},
	}
	report, err := VerifyChain(chain, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("nil action_event should fail validation")
	}
	assertFailedCheck(t, report, "external_host:receipt_schema")
}

func TestValidateReceipt_UnknownEventKindFails(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := contracts.ExternalHostReceipt{
		SchemaVersion: contracts.ExternalHostReceiptVersion,
		ReceiptID:     "bogus-kind-receipt",
		HostID:        "host-d",
		EventKind:     "bogus",
	}
	r, err = SignReceipt(r, priv)
	if err != nil {
		t.Fatal(err)
	}
	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		Receipts:      []contracts.ExternalHostReceipt{r},
	}
	report, err := VerifyChain(chain, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("unknown event_kind should fail validation")
	}
	assertFailedCheck(t, report, "external_host:receipt_schema")
}

func TestVerifyChain_NetworkEgressUnchanged(t *testing.T) {
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
		t.Fatalf("egress chain regression: expected verified, got checks: %+v", report.Checks)
	}
}

// TestVerifySignature_PreservedBytesEd25519 verifies that when SignedPayloadB64 is
// set, the signature is checked against the preserved original bytes, not JCS.
func TestVerifySignature_PreservedBytesEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Vendor's original payload bytes (not JCS-canonicalized).
	vendorPayload := []byte(`{"tool":"github.create_pr","action_id":"act-999","ts":"2026-06-15T00:00:00Z"}`)
	sig := ed25519.Sign(priv, vendorPayload)

	ts := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	r := contracts.ExternalHostReceipt{
		SchemaVersion:      contracts.ExternalHostReceiptVersion,
		ReceiptID:          "foreign-1",
		HostID:             "vendor-host",
		EventKind:          contracts.EventKindActionEffect,
		SignatureAlgorithm: "Ed25519",
		Signature:          hex.EncodeToString(sig),
		SignedPayloadB64:   base64.StdEncoding.EncodeToString(vendorPayload),
		ActionEvent: &contracts.ActionEffectEvent{
			ActionID:  "act-999",
			ToolName:  "github.create_pr",
			Timestamp: ts,
		},
	}
	// Compute receipt_hash (HELM JCS chain integrity — independent of signed payload).
	r, err = computeHashOnly(r)
	if err != nil {
		t.Fatal(err)
	}

	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		ChainID:       "foreign-chain-1",
		PublicKeys: []contracts.ExternalVerifierKey{{
			KeyID:        "vendor-key-1",
			Algorithm:    "Ed25519",
			PublicKeyHex: hex.EncodeToString(pub),
		}},
		Receipts: []contracts.ExternalHostReceipt{r},
	}
	chain.ReceiptChainHash = ComputeChainHash([]string{r.ReceiptHash})

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("preserved-bytes Ed25519: expected verified, got checks: %+v", report.Checks)
	}

	// Tamper the preserved payload — signature should now fail.
	r2 := r
	tampered := make([]byte, len(vendorPayload))
	copy(tampered, vendorPayload)
	tampered[0] = 'X'
	r2.SignedPayloadB64 = base64.StdEncoding.EncodeToString(tampered)
	chain2 := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		ChainID:       "foreign-chain-1",
		PublicKeys:    chain.PublicKeys,
		Receipts:      []contracts.ExternalHostReceipt{r2},
	}
	report2, err := VerifyChain(chain2, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if report2.Verified {
		t.Fatal("tampered preserved payload must not verify")
	}
	assertFailedCheck(t, report2, "external_host:signature")
}

// TestVerifySignature_ECDSAP256 verifies ECDSA-P256 signature over preserved bytes.
func TestVerifySignature_ECDSAP256(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	pubHex := hex.EncodeToString(pubBytes)

	vendorPayload := []byte(`{"tool":"linear.create_issue","action_id":"act-p256","ts":"2026-06-15T00:00:00Z"}`)
	h := sha256.Sum256(vendorPayload)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, h[:])
	if err != nil {
		t.Fatal(err)
	}

	ts := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	r := contracts.ExternalHostReceipt{
		SchemaVersion:      contracts.ExternalHostReceiptVersion,
		ReceiptID:          "foreign-p256-1",
		HostID:             "vendor-host-p256",
		EventKind:          contracts.EventKindActionEffect,
		SignatureAlgorithm: "ECDSA-P256",
		Signature:          hex.EncodeToString(sigBytes),
		SignedPayloadB64:   base64.StdEncoding.EncodeToString(vendorPayload),
		ActionEvent: &contracts.ActionEffectEvent{
			ActionID:  "act-p256",
			ToolName:  "linear.create_issue",
			Timestamp: ts,
		},
	}
	r, err = computeHashOnly(r)
	if err != nil {
		t.Fatal(err)
	}

	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		ChainID:       "p256-chain-1",
		PublicKeys: []contracts.ExternalVerifierKey{{
			KeyID:        "vendor-p256-key",
			Algorithm:    "ECDSA-P256",
			PublicKeyHex: pubHex,
		}},
		Receipts: []contracts.ExternalHostReceipt{r},
	}
	chain.ReceiptChainHash = ComputeChainHash([]string{r.ReceiptHash})

	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: pubHex})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("ECDSA-P256: expected verified, got checks: %+v", report.Checks)
	}

	// Tamper the payload — should fail.
	r2 := r
	tampered := make([]byte, len(vendorPayload))
	copy(tampered, vendorPayload)
	tampered[len(tampered)-1] ^= 0xFF
	r2.SignedPayloadB64 = base64.StdEncoding.EncodeToString(tampered)
	chain2 := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		PublicKeys:    chain.PublicKeys,
		Receipts:      []contracts.ExternalHostReceipt{r2},
	}
	report2, err := VerifyChain(chain2, VerifyOptions{RequireKey: true, PublicKeyHex: pubHex})
	if err != nil {
		t.Fatal(err)
	}
	if report2.Verified {
		t.Fatal("tampered ECDSA-P256 payload must not verify")
	}
	assertFailedCheck(t, report2, "external_host:signature")
}

// TestVerifySignature_AlgorithmKeyMismatchFails ensures an Ed25519 key supplied
// for an ECDSA-P256 receipt causes a signature failure, not a silent pass.
func TestVerifySignature_AlgorithmKeyMismatchFails(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ts := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	vendorPayload := []byte(`{"tool":"test","action_id":"act-mismatch","ts":"2026-06-15T00:00:00Z"}`)
	r := contracts.ExternalHostReceipt{
		SchemaVersion:      contracts.ExternalHostReceiptVersion,
		ReceiptID:          "mismatch-1",
		HostID:             "vendor-host-x",
		EventKind:          contracts.EventKindActionEffect,
		SignatureAlgorithm: "ECDSA-P256",
		// Signature is arbitrary hex; verification must fail before it even gets to crypto.
		Signature:        hex.EncodeToString(make([]byte, 64)),
		SignedPayloadB64: base64.StdEncoding.EncodeToString(vendorPayload),
		ActionEvent: &contracts.ActionEffectEvent{
			ActionID:  "act-mismatch",
			ToolName:  "test",
			Timestamp: ts,
		},
	}
	r, err = computeHashOnly(r)
	if err != nil {
		t.Fatal(err)
	}

	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		Receipts:      []contracts.ExternalHostReceipt{r},
	}
	// Supply an Ed25519 key for a receipt that declares ECDSA-P256.
	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("Ed25519 key vs ECDSA-P256 receipt must not verify")
	}
	assertFailedCheck(t, report, "external_host:signature")
}

// TestVerifySignature_HelmNativeUnchanged is a regression test: HELM-native receipts
// (no SignedPayloadB64) continue to verify over JCS canonicalization.
func TestVerifySignature_HelmNativeUnchanged(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	r := testReceipt("native-1", "", ts)
	// Ensure no SignedPayloadB64 is set.
	r.SignedPayloadB64 = ""
	r, err = SignReceipt(r, priv)
	if err != nil {
		t.Fatal(err)
	}
	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		ChainID:       "native-chain-1",
		PublicKeys: []contracts.ExternalVerifierKey{{
			KeyID:        "helm-key-1",
			Algorithm:    "Ed25519",
			PublicKeyHex: hex.EncodeToString(pub),
		}},
		Receipts: []contracts.ExternalHostReceipt{r},
	}
	chain.ReceiptChainHash = ComputeChainHash([]string{r.ReceiptHash})
	report, err := VerifyChain(chain, VerifyOptions{RequireKey: true, PublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("HELM-native JCS path regression: expected verified, got checks: %+v", report.Checks)
	}
}

// computeHashOnly sets ReceiptHash without re-signing (used for foreign receipts
// where HELM owns the hash chain but not the signature).
func computeHashOnly(r contracts.ExternalHostReceipt) (contracts.ExternalHostReceipt, error) {
	hash, err := ComputeReceiptHash(r)
	if err != nil {
		return r, err
	}
	r.ReceiptHash = hash
	return r, nil
}
