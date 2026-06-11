package evidencepack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Golden conformance vectors for the redacted single-entry verification profile
// (MIN-512, protocols/spec/evidence-pack-v1.md §15). The fixture is fully
// deterministic: the pack uses a fixed created_at and fixed receipt bodies, so
// the manifest hash, Merkle root, and every proof regenerate byte-identically on
// any platform. Set HELM_UPDATE_VECTORS=1 to rewrite the fixture.
const inclusionFixturePath = "testdata/inclusion_proof_profile_v1.json"

type inclusionVector struct {
	Name        string         `json:"name"`
	Mutation    string         `json:"mutation"`
	Proof       InclusionProof `json:"proof"`
	ExpectValid bool           `json:"expect_valid"`
}

type inclusionFixture struct {
	Profile      string            `json:"profile"`
	PackID       string            `json:"pack_id"`
	ManifestHash string            `json:"manifest_hash"`
	MerkleRoot   string            `json:"entries_merkle_root"`
	PublicFields []string          `json:"public_receipt_fields"`
	Vectors      []inclusionVector `json:"vectors"`
}

func fixtureManifest(t *testing.T) *Manifest {
	t.Helper()
	b := NewBuilder("pack-min512-golden", "did:helm:agent-golden", "intent-golden", "sha256:"+repeat("b", 64)).
		WithCreatedAt(time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC))
	if err := b.AddReceipt("decision-001", map[string]any{
		"receipt_id":  "rcpt-golden-1",
		"decision_id": "dec-golden-1",
		"verdict":     "DENY",
		"timestamp":   "2026-04-13T12:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	_ = b.AddPolicyDecision("gate", map[string]any{"policy_id": "p1", "outcome": "deny"})
	_ = b.AddToolTranscript("tool-1", map[string]any{"tool_id": "t1", "status": "failure"})
	_ = b.AddReceipt("decision-002", map[string]any{
		"receipt_id":  "rcpt-golden-2",
		"decision_id": "dec-golden-2",
		"verdict":     "ALLOW",
		"timestamp":   "2026-04-13T12:00:05Z",
	})
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func buildFixture(t *testing.T) inclusionFixture {
	t.Helper()
	m := fixtureManifest(t)

	valid, err := BuildInclusionProof(m, "receipts/decision-001.json", &SelectiveDisclosure{PublicClaims: PublicReceiptFields})
	if err != nil {
		t.Fatal(err)
	}

	// Wrong-entry: receipt-001 binding/path but receipt-002's entry+leaf spliced in.
	other, err := BuildInclusionProof(m, "receipts/decision-002.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongEntry := *valid
	wrongEntry.Disclosure = nil
	wrongEntry.Entry = other.Entry
	wrongEntry.LeafHash = other.LeafHash

	// Tampered entry content hash.
	tamperedEntry := *valid
	tamperedEntry.Disclosure = nil
	tamperedEntry.Entry.ContentHash = "sha256:" + repeat("9", 64)

	// Tampered Merkle root in the binding.
	tamperedRoot := *valid
	tamperedRoot.Disclosure = nil
	tamperedRoot.Binding.EntriesMerkleRoot = "sha256:" + repeat("0", 64)

	return inclusionFixture{
		Profile:      "evidence-pack-redacted-verification/v1",
		PackID:       m.PackID,
		ManifestHash: m.ManifestHash,
		MerkleRoot:   m.EntriesMerkleRoot,
		PublicFields: PublicReceiptFields,
		Vectors: []inclusionVector{
			{Name: "valid_receipt_inclusion", Mutation: "none", Proof: *valid, ExpectValid: true},
			{Name: "wrong_entry_spliced", Mutation: "entry+leaf swapped for a sibling", Proof: wrongEntry, ExpectValid: false},
			{Name: "tampered_entry_content_hash", Mutation: "entry.content_hash flipped", Proof: tamperedEntry, ExpectValid: false},
			{Name: "tampered_merkle_root", Mutation: "binding.entries_merkle_root flipped", Proof: tamperedRoot, ExpectValid: false},
		},
	}
}

func TestInclusionProofGoldenVectors(t *testing.T) {
	want := buildFixture(t)

	if os.Getenv("HELM_UPDATE_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(inclusionFixturePath), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		data, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inclusionFixturePath, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		t.Logf("updated %s", inclusionFixturePath)
	}

	raw, err := os.ReadFile(inclusionFixturePath)
	if err != nil {
		t.Fatalf("read fixture (run with HELM_UPDATE_VECTORS=1 to generate): %v", err)
	}
	var fixture inclusionFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	// Determinism: regenerated pack-level hashes must match the committed fixture.
	if fixture.ManifestHash != want.ManifestHash {
		t.Fatalf("manifest hash drift: fixture %s != regenerated %s", fixture.ManifestHash, want.ManifestHash)
	}
	if fixture.MerkleRoot != want.MerkleRoot {
		t.Fatalf("merkle root drift: fixture %s != regenerated %s", fixture.MerkleRoot, want.MerkleRoot)
	}

	// Every vector verifies to its committed expectation.
	for _, v := range fixture.Vectors {
		proof := v.Proof
		err := VerifyInclusionProof(&proof)
		if v.ExpectValid && err != nil {
			t.Fatalf("vector %q: expected valid, got error: %v", v.Name, err)
		}
		if !v.ExpectValid && err == nil {
			t.Fatalf("vector %q: expected FAILURE, but verification passed", v.Name)
		}
	}
}
