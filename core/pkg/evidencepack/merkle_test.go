package evidencepack

import (
	"testing"
)

func sampleEntries() []ManifestEntry {
	return []ManifestEntry{
		{Path: "receipts/decision-001.json", ContentHash: "sha256:" + repeat("2", 64), Size: 1024, ContentType: "application/json"},
		{Path: "policy/gate-evaluation.json", ContentHash: "sha256:" + repeat("1", 64), Size: 512, ContentType: "application/json"},
		{Path: "transcripts/tool-exec-001.json", ContentHash: "sha256:" + repeat("3", 64), Size: 2048, ContentType: "application/json"},
		{Path: "network/egress.log", ContentHash: "sha256:" + repeat("4", 64), Size: 64, ContentType: "text/plain"},
		{Path: "secrets/access.json", ContentHash: "sha256:" + repeat("5", 64), Size: 128, ContentType: "application/json"},
	}
}

func repeat(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}

func TestComputeEntriesMerkleRoot_Deterministic(t *testing.T) {
	entries := sampleEntries()
	root1, err := ComputeEntriesMerkleRoot(entries)
	if err != nil {
		t.Fatalf("root1: %v", err)
	}
	// Shuffle order: root MUST be identical (entries are path-sorted internally).
	shuffled := []ManifestEntry{entries[4], entries[0], entries[2], entries[1], entries[3]}
	root2, err := ComputeEntriesMerkleRoot(shuffled)
	if err != nil {
		t.Fatalf("root2: %v", err)
	}
	if root1 != root2 {
		t.Fatalf("merkle root not order-independent: %s != %s", root1, root2)
	}
	if len(root1) != len("sha256:")+64 {
		t.Fatalf("unexpected root format: %s", root1)
	}
}

func TestComputeEntriesMerkleRoot_EmptyIsError(t *testing.T) {
	if _, err := ComputeEntriesMerkleRoot(nil); err == nil {
		t.Fatal("expected error for empty entries")
	}
}

func TestInclusionPath_RoundTripEveryEntry(t *testing.T) {
	entries := sampleEntries()
	wantRoot, err := ComputeEntriesMerkleRoot(entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		steps, root, err := BuildInclusionPath(entries, e.Path)
		if err != nil {
			t.Fatalf("path for %s: %v", e.Path, err)
		}
		if root != wantRoot {
			t.Fatalf("path root mismatch for %s", e.Path)
		}
		leaf, err := LeafHash(e)
		if err != nil {
			t.Fatal(err)
		}
		derived, err := VerifyInclusionPath(leaf, steps)
		if err != nil {
			t.Fatalf("verify path for %s: %v", e.Path, err)
		}
		if derived != wantRoot {
			t.Fatalf("derived root mismatch for %s: %s != %s", e.Path, derived, wantRoot)
		}
	}
}

func TestInclusionPath_SingleEntryTree(t *testing.T) {
	entries := []ManifestEntry{
		{Path: "receipts/only.json", ContentHash: "sha256:" + repeat("a", 64), Size: 10, ContentType: "application/json"},
	}
	root, err := ComputeEntriesMerkleRoot(entries)
	if err != nil {
		t.Fatal(err)
	}
	steps, pathRoot, err := BuildInclusionPath(entries, "receipts/only.json")
	if err != nil {
		t.Fatal(err)
	}
	if pathRoot != root {
		t.Fatalf("single-entry root mismatch")
	}
	leaf, _ := LeafHash(entries[0])
	derived, err := VerifyInclusionPath(leaf, steps)
	if err != nil {
		t.Fatal(err)
	}
	if derived != root {
		t.Fatalf("single-entry derived root mismatch: %s != %s", derived, root)
	}
}

func TestInclusionPath_EntryNotFound(t *testing.T) {
	if _, _, err := BuildInclusionPath(sampleEntries(), "does/not/exist.json"); err == nil {
		t.Fatal("expected error for missing entry")
	}
}

// NEGATIVE: a wrong-entry proof (correct path, but presented for the wrong leaf)
// must not reach the true root.
func TestInclusionPath_WrongEntryFails(t *testing.T) {
	entries := sampleEntries()
	wantRoot, _ := ComputeEntriesMerkleRoot(entries)

	steps, _, err := BuildInclusionPath(entries, entries[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	// Use a DIFFERENT entry's leaf with entry[0]'s path.
	wrongLeaf, _ := LeafHash(entries[2])
	derived, err := VerifyInclusionPath(wrongLeaf, steps)
	if err != nil {
		t.Fatal(err)
	}
	if derived == wantRoot {
		t.Fatal("wrong-entry proof must NOT reconstruct the true root")
	}
}

// NEGATIVE: a tampered sibling in the path must not reach the true root.
func TestInclusionPath_TamperedSiblingFails(t *testing.T) {
	entries := sampleEntries()
	wantRoot, _ := ComputeEntriesMerkleRoot(entries)
	steps, _, err := BuildInclusionPath(entries, entries[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) == 0 {
		t.Fatal("expected non-empty path")
	}
	steps[0].SiblingHash = "sha256:" + repeat("f", 64)
	leaf, _ := LeafHash(entries[0])
	derived, err := VerifyInclusionPath(leaf, steps)
	if err != nil {
		t.Fatal(err)
	}
	if derived == wantRoot {
		t.Fatal("tampered sibling must NOT reconstruct the true root")
	}
}

func TestVerifyInclusionPath_RejectsMalformedHashes(t *testing.T) {
	if _, err := VerifyInclusionPath("not-a-hash", nil); err == nil {
		t.Fatal("expected error for malformed leaf hash")
	}
	leaf, _ := LeafHash(sampleEntries()[0])
	if _, err := VerifyInclusionPath(leaf, []MerkleProofStep{{SiblingHash: "deadbeef", Right: true}}); err == nil {
		t.Fatal("expected error for malformed sibling hash")
	}
}
