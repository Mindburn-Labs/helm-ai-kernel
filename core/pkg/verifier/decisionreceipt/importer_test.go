package decisionreceipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestImportReceiptBuildsEvidencePack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signed, err := SignHelmExternal(contracts.ExternalDecisionReceipt{
		ReceiptID: "edr-imp-1", Action: "github.create_issue", Verdict: "allow", SourceVendor: "vendor-x",
	}, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, _ := json.Marshal(signed)
	fixed := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)

	res, err := ImportReceipt(raw, ImportOptions{PublicKeyHex: hex.EncodeToString(pub), Now: fixed})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !res.Report.Verified || res.Report.Classification != contracts.ClassCryptoConformant {
		t.Fatalf("verified=%v class=%s", res.Report.Verified, res.Report.Classification)
	}
	if res.ManifestHash == "" {
		t.Fatal("missing manifest hash")
	}

	want := map[string]bool{
		"manifest.json": false,
		"host_evidence/helm_external.v1/source.json": false,
		"receipts/external_edr-imp-1.json":           false,
		"compatibility/import_manifest.json":         false,
	}
	for _, e := range res.Entries {
		if _, ok := want[e]; ok {
			want[e] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Fatalf("missing pack entry %q in %v", path, res.Entries)
		}
	}

	// Determinism: same input + same Now => identical manifest hash.
	res2, err := ImportReceipt(raw, ImportOptions{PublicKeyHex: hex.EncodeToString(pub), Now: fixed})
	if err != nil {
		t.Fatalf("import 2: %v", err)
	}
	if res2.ManifestHash != res.ManifestHash {
		t.Fatalf("non-deterministic manifest hash: %s vs %s", res.ManifestHash, res2.ManifestHash)
	}
}

func TestImportReceiptUnverifiedStillImports(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := SignHelmExternal(contracts.ExternalDecisionReceipt{ReceiptID: "edr-imp-2", Action: "x"}, priv)
	raw, _ := json.Marshal(signed)

	// No trusted key -> unverified, but the pack is still built (honestly labeled).
	res, err := ImportReceipt(raw, ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Report.Verified {
		t.Fatal("expected unverified (no trusted key)")
	}
	if res.Report.Classification != contracts.ClassUnverified {
		t.Fatalf("class=%s, want unverified", res.Report.Classification)
	}
	if res.ManifestHash == "" {
		t.Fatal("pack should still be built for an unverified receipt")
	}
}
