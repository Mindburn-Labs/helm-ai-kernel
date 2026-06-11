package translog

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// rfc6962Leaves are the canonical RFC 6962 test inputs used across CT
// implementations (hex-encoded leaf inputs).
var rfc6962Leaves = []string{
	"",
	"00",
	"10",
	"2021",
	"3031",
	"40414243",
	"5051525354555657",
	"606162636465666768696a6b6c6d6e6f",
}

// rfc6962Roots[i] is MTH over the first i+1 canonical leaves, as
// published in the Certificate Transparency reference test data.
var rfc6962Roots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func rfc6962LeafHashes(t *testing.T, n int) [][HashSize]byte {
	t.Helper()
	hashes := make([][HashSize]byte, n)
	for i := 0; i < n; i++ {
		input, err := hex.DecodeString(rfc6962Leaves[i])
		if err != nil {
			t.Fatalf("bad test leaf %d: %v", i, err)
		}
		hashes[i] = LeafHash(input)
	}
	return hashes
}

func TestEmptyRoot(t *testing.T) {
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	root := EmptyRoot()
	if got := hex.EncodeToString(root[:]); got != want {
		t.Fatalf("empty root = %s, want %s", got, want)
	}
}

func TestRFC6962Roots(t *testing.T) {
	for n := 1; n <= len(rfc6962Leaves); n++ {
		root := RootFromLeafHashes(rfc6962LeafHashes(t, n))
		if got := hex.EncodeToString(root[:]); got != rfc6962Roots[n-1] {
			t.Errorf("MTH(D[%d]) = %s, want %s", n, got, rfc6962Roots[n-1])
		}
	}
}

// TestInclusionProofExhaustive generates and verifies inclusion proofs
// for every (leafIndex, treeSize) pair over trees up to 32 leaves.
func TestInclusionProofExhaustive(t *testing.T) {
	leaves := make([][HashSize]byte, 32)
	for i := range leaves {
		leaves[i] = LeafHash([]byte(fmt.Sprintf("receipt-%d", i)))
	}
	for size := uint64(1); size <= uint64(len(leaves)); size++ {
		root := RootFromLeafHashes(leaves[:size])
		rootHex := hex.EncodeToString(root[:])
		for idx := uint64(0); idx < size; idx++ {
			proof, err := BuildInclusionProof(leaves, idx, size)
			if err != nil {
				t.Fatalf("build inclusion (%d,%d): %v", idx, size, err)
			}
			if proof.RootHash != rootHex {
				t.Fatalf("proof root (%d,%d) = %s, want %s", idx, size, proof.RootHash, rootHex)
			}
			if err := VerifyInclusion(proof, rootHex); err != nil {
				t.Fatalf("verify inclusion (%d,%d): %v", idx, size, err)
			}
		}
	}
}

// TestConsistencyProofExhaustive generates and verifies consistency
// proofs for every (oldSize, newSize) pair over trees up to 32 leaves.
func TestConsistencyProofExhaustive(t *testing.T) {
	leaves := make([][HashSize]byte, 32)
	for i := range leaves {
		leaves[i] = LeafHash([]byte(fmt.Sprintf("receipt-%d", i)))
	}
	for newSize := uint64(1); newSize <= uint64(len(leaves)); newSize++ {
		for oldSize := uint64(1); oldSize <= newSize; oldSize++ {
			proof, err := BuildConsistencyProof(leaves, oldSize, newSize)
			if err != nil {
				t.Fatalf("build consistency (%d,%d): %v", oldSize, newSize, err)
			}
			if err := VerifyConsistency(proof); err != nil {
				t.Fatalf("verify consistency (%d,%d): %v", oldSize, newSize, err)
			}
		}
	}
}

// TestTamperedLeafFailsInclusion is a negative vector: a tampered leaf
// hash must not verify against the honest root.
func TestTamperedLeafFailsInclusion(t *testing.T) {
	leaves := rfc6962LeafHashes(t, 8)
	proof, err := BuildInclusionProof(leaves, 3, 8)
	if err != nil {
		t.Fatal(err)
	}
	tampered := *proof
	tamperedLeaf := LeafHash([]byte("forged receipt"))
	tampered.LeafHash = hex.EncodeToString(tamperedLeaf[:])
	if err := VerifyInclusion(&tampered, rfc6962Roots[7]); err == nil {
		t.Fatal("tampered leaf verified against honest root; want failure")
	}
	// Wrong index for an honest leaf must also fail.
	wrongIndex := *proof
	wrongIndex.LeafIndex = 4
	if err := VerifyInclusion(&wrongIndex, rfc6962Roots[7]); err == nil {
		t.Fatal("inclusion proof with wrong leaf index verified; want failure")
	}
	// Truncated audit path must fail.
	truncated := *proof
	truncated.AuditPath = truncated.AuditPath[:len(truncated.AuditPath)-1]
	if err := VerifyInclusion(&truncated, rfc6962Roots[7]); err == nil {
		t.Fatal("truncated audit path verified; want failure")
	}
}

// TestEquivocationFailsConsistency is a negative vector: two tree heads
// at the same size with different roots (a fork / split view) must
// never satisfy a consistency proof.
func TestEquivocationFailsConsistency(t *testing.T) {
	proof := &ConsistencyProof{
		OldSize:         8,
		NewSize:         8,
		OldRoot:         rfc6962Roots[7],
		NewRoot:         "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604329", // last nibble flipped
		ConsistencyPath: nil,
	}
	if err := VerifyConsistency(proof); err == nil {
		t.Fatal("equivocating roots at same size verified; want failure")
	}
}

// TestForkedLogFailsConsistency is a negative vector: a log that
// rewrites history (fork after a shared prefix) cannot produce a valid
// consistency proof from the honest old head to the forked new head.
func TestForkedLogFailsConsistency(t *testing.T) {
	honest := make([][HashSize]byte, 8)
	forked := make([][HashSize]byte, 8)
	for i := range honest {
		honest[i] = LeafHash([]byte(fmt.Sprintf("receipt-%d", i)))
		forked[i] = honest[i]
	}
	// The fork rewrites leaf 2 (inside the old tree of size 5).
	forked[2] = LeafHash([]byte("contradictory receipt"))

	honestOldRoot := RootFromLeafHashes(honest[:5])
	proof, err := BuildConsistencyProof(forked, 5, 8)
	if err != nil {
		t.Fatal(err)
	}
	// Substitute the honest old root the verifier trusts.
	proof.OldRoot = hex.EncodeToString(honestOldRoot[:])
	if err := VerifyConsistency(proof); err == nil {
		t.Fatal("forked log verified against honest old head; want split-view failure")
	}
}

func TestSTHSignAndVerify(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize) // deterministic zero seed for tests
	signer := crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), "test-root")
	logID := LogIDFromPublicKey(signer.PublicKeyBytes())

	leaves := rfc6962LeafHashes(t, 8)
	root := RootFromLeafHashes(leaves)
	ts := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)

	sth, err := SignTreeHead(signer, logID, 8, root, ts)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTreeHead(sth, signer.PublicKey()); err != nil {
		t.Fatalf("honest STH failed verification: %v", err)
	}

	// JCS determinism: signing bytes must be byte-identical across calls.
	b1, _ := sth.SigningBytes()
	b2, _ := sth.SigningBytes()
	if string(b1) != string(b2) {
		t.Fatal("STH signing bytes are not deterministic")
	}

	// Negative: tampered tree size must fail signature verification.
	tampered := *sth
	tampered.TreeSize = 9
	if err := VerifyTreeHead(&tampered, signer.PublicKey()); err == nil {
		t.Fatal("tampered STH verified; want failure")
	}
}

func TestDetectEquivocation(t *testing.T) {
	a := &SignedTreeHead{LogID: "log-a", TreeSize: 8, RootHash: rfc6962Roots[7]}
	b := &SignedTreeHead{LogID: "log-a", TreeSize: 8, RootHash: rfc6962Roots[6]}
	if !DetectEquivocation(a, b) {
		t.Fatal("same log, same size, different roots: want equivocation detected")
	}
	c := &SignedTreeHead{LogID: "log-a", TreeSize: 8, RootHash: rfc6962Roots[7]}
	if DetectEquivocation(a, c) {
		t.Fatal("identical heads flagged as equivocation")
	}
	d := &SignedTreeHead{LogID: "log-b", TreeSize: 8, RootHash: rfc6962Roots[6]}
	if DetectEquivocation(a, d) {
		t.Fatal("different logs flagged as equivocation")
	}
}

func TestLogPersistence(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l.Size() != 0 {
		t.Fatalf("fresh log size = %d, want 0", l.Size())
	}
	for i := 0; i < 8; i++ {
		input, _ := hex.DecodeString(rfc6962Leaves[i])
		idx, err := l.Append(input)
		if err != nil {
			t.Fatal(err)
		}
		if idx != uint64(i) {
			t.Fatalf("append %d returned index %d", i, idx)
		}
	}
	root, err := l.Root(l.Size())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(root[:]); got != rfc6962Roots[7] {
		t.Fatalf("persisted log root = %s, want %s", got, rfc6962Roots[7])
	}

	// Reopen: state must survive and reproduce the identical root.
	l2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Size() != 8 {
		t.Fatalf("reopened log size = %d, want 8", l2.Size())
	}
	root2, err := l2.Root(8)
	if err != nil {
		t.Fatal(err)
	}
	if root2 != root {
		t.Fatal("reopened log root differs from original")
	}

	// Proofs from the persisted log verify against an older head.
	oldRoot, err := l2.Root(5)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := l2.InclusionProof(2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(inc, hex.EncodeToString(oldRoot[:])); err != nil {
		t.Fatalf("inclusion under old head: %v", err)
	}
	cons, err := l2.ConsistencyProof(5, 8)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(cons); err != nil {
		t.Fatalf("consistency 5->8: %v", err)
	}

	// Negative: corrupt journal must refuse to open.
	if err := os.WriteFile(filepath.Join(dir, leavesFileName), []byte("not-a-hash\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("corrupt journal opened without error")
	}
}

// goldenFixture is the deterministic small-log fixture: canonical
// leaves, expected roots at every size, and frozen proofs and STH.
type goldenFixture struct {
	Description string             `json:"description"`
	Leaves      []string           `json:"leaves"`
	Roots       []string           `json:"roots"`
	Inclusion   []InclusionProof   `json:"inclusion_proofs"`
	Consistency []ConsistencyProof `json:"consistency_proofs"`
	STH         SignedTreeHead     `json:"sth"`
}

func TestGoldenFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "rfc6962_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g goldenFixture
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}

	leaves := make([][HashSize]byte, len(g.Leaves))
	for i, lhex := range g.Leaves {
		input, err := hex.DecodeString(lhex)
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = LeafHash(input)
	}
	for n := 1; n <= len(leaves); n++ {
		root := RootFromLeafHashes(leaves[:n])
		if got := hex.EncodeToString(root[:]); got != g.Roots[n-1] {
			t.Errorf("golden root at size %d = %s, want %s", n, got, g.Roots[n-1])
		}
	}
	for i, want := range g.Inclusion {
		got, err := BuildInclusionProof(leaves, want.LeafIndex, want.TreeSize)
		if err != nil {
			t.Fatalf("golden inclusion %d: %v", i, err)
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("golden inclusion %d drifted:\n got  %s\n want %s", i, gotJSON, wantJSON)
		}
		if err := VerifyInclusion(got, want.RootHash); err != nil {
			t.Errorf("golden inclusion %d does not verify: %v", i, err)
		}
	}
	for i, want := range g.Consistency {
		got, err := BuildConsistencyProof(leaves, want.OldSize, want.NewSize)
		if err != nil {
			t.Fatalf("golden consistency %d: %v", i, err)
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("golden consistency %d drifted:\n got  %s\n want %s", i, gotJSON, wantJSON)
		}
		if err := VerifyConsistency(got); err != nil {
			t.Errorf("golden consistency %d does not verify: %v", i, err)
		}
	}

	// STH: deterministic zero-seed test key, fixed timestamp; Ed25519 is
	// deterministic so the frozen signature must reproduce exactly.
	seed := make([]byte, ed25519.SeedSize)
	signer := crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), "test-root")
	root := RootFromLeafHashes(leaves)
	ts, err := time.Parse(time.RFC3339, g.STH.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	sth, err := SignTreeHead(signer, g.STH.LogID, uint64(len(leaves)), root, ts)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(sth)
	wantJSON, _ := json.Marshal(g.STH)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("golden STH drifted:\n got  %s\n want %s", gotJSON, wantJSON)
	}
	if err := VerifyTreeHead(sth, signer.PublicKey()); err != nil {
		t.Errorf("golden STH does not verify: %v", err)
	}
}
