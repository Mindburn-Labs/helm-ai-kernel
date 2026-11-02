package evidencepack

import (
	"encoding/json"
	"testing"
	"time"
)

func builtManifest(t *testing.T) *Manifest {
	t.Helper()
	b := NewBuilder("pack-min512", "did:helm:agent-7f3a", "intent-001", "sha256:"+repeat("a", 64)).
		WithCreatedAt(time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC))
	if err := b.AddReceipt("decision-001", map[string]any{
		"receipt_id":  "rcpt-1",
		"decision_id": "dec-1",
		"verdict":     "DENY",
		"timestamp":   "2026-04-13T12:00:00Z",
		"signature":   "ed25519:abcd",
		"prompt":      "SENSITIVE tenant payload",
	}); err != nil {
		t.Fatal(err)
	}
	_ = b.AddPolicyDecision("gate", map[string]any{"policy_id": "p1", "outcome": "deny"})
	_ = b.AddToolTranscript("tool-1", map[string]any{"tool_id": "t1", "status": "failure"})
	m, _, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if m.EntriesMerkleRoot == "" {
		t.Fatal("Build did not populate EntriesMerkleRoot")
	}
	return m
}

func TestBuildAndVerifyInclusionProof_Positive(t *testing.T) {
	m := builtManifest(t)
	proof, err := BuildInclusionProof(m, "receipts/decision-001.json", nil)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	if err := VerifyInclusionProof(proof); err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if proof.Binding.ManifestHash != m.ManifestHash {
		t.Fatal("proof does not bind to manifest hash")
	}
	if proof.Binding.EntriesMerkleRoot != m.EntriesMerkleRoot {
		t.Fatal("proof root does not match manifest root")
	}
}

// The proof must verify WITHOUT the rest of the pack: marshal it, drop the
// manifest, and verify from the artifact alone.
func TestInclusionProof_OfflineNoSiblings(t *testing.T) {
	m := builtManifest(t)
	proof, err := BuildInclusionProof(m, "receipts/decision-001.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	// Confirm the artifact does not leak sibling entry paths or payloads.
	s := string(raw)
	if containsAny(s, "policy/gate.json", "transcripts/tool-1.json", "SENSITIVE") {
		t.Fatal("inclusion proof leaked sibling entry data")
	}
	var roundtrip InclusionProof
	if err := json.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusionProof(&roundtrip); err != nil {
		t.Fatalf("offline verify failed: %v", err)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// NEGATIVE: a wrong-entry proof FAILS — take entry A's path but B's leaf/entry.
func TestInclusionProof_WrongEntryFails(t *testing.T) {
	m := builtManifest(t)
	good, err := BuildInclusionProof(m, "receipts/decision-001.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := BuildInclusionProof(m, "policy/gate.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Splice: keep the receipt path/binding but swap in the policy entry+leaf.
	good.Entry = other.Entry
	good.LeafHash = other.LeafHash
	if err := VerifyInclusionProof(good); err == nil {
		t.Fatal("wrong-entry proof must FAIL verification")
	}
}

// NEGATIVE: tampering the published Merkle root FAILS.
func TestInclusionProof_TamperedRootFails(t *testing.T) {
	m := builtManifest(t)
	proof, err := BuildInclusionProof(m, "receipts/decision-001.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	proof.Binding.EntriesMerkleRoot = "sha256:" + repeat("0", 64)
	// binding_hash now stale -> must fail at binding-integrity step.
	if err := VerifyInclusionProof(proof); err == nil {
		t.Fatal("tampered root must FAIL verification")
	}
}

// NEGATIVE: tampering the disclosed entry record FAILS.
func TestInclusionProof_TamperedEntryFails(t *testing.T) {
	m := builtManifest(t)
	proof, err := BuildInclusionProof(m, "receipts/decision-001.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	proof.Entry.ContentHash = "sha256:" + repeat("9", 64)
	if err := VerifyInclusionProof(proof); err == nil {
		t.Fatal("tampered entry must FAIL verification")
	}
}

// An inclusion proof carries a selective-disclosure presentation verbatim and
// its Merkle membership holds independently of it.
func TestInclusionProof_CarriesPresentationVerbatim(t *testing.T) {
	m := builtManifest(t)
	const presentation = "eyJhbGciOiJFZERTQSJ9.e30.c2ln~"

	proof, err := BuildInclusionProof(m, "receipts/decision-001.json", &SelectiveDisclosure{
		Presentation: presentation,
		PublicClaims: PublicReceiptFields,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusionProof(proof); err != nil {
		t.Fatalf("merkle membership must hold: %v", err)
	}
	if proof.Disclosure == nil || proof.Disclosure.Presentation != presentation {
		t.Fatalf("presentation not carried verbatim: %+v", proof.Disclosure)
	}
}
