package evidencepack

// F-10 regression: an inclusion proof verified only against the root it carries
// about itself proves nothing. Every input — leaf, path, binding hash and the
// root they are compared to — comes from the same attacker-supplied document.

import (
	"strings"
	"testing"
)

// forgeSelfAttestedProof builds a proof for an arbitrary entry, with an empty
// audit path so the derived root is the leaf itself, and a binding that names
// that leaf as the pack root. It is internally consistent by construction.
func forgeSelfAttestedProof(t *testing.T) *InclusionProof {
	t.Helper()
	entry := ManifestEntry{
		Path:        "receipts/attacker-supplied.json",
		ContentHash: "sha256:" + strings.Repeat("f", 64),
		Size:        128,
		ContentType: "application/json",
	}
	leaf, err := LeafHash(entry)
	if err != nil {
		t.Fatalf("LeafHash: %v", err)
	}

	proof := &InclusionProof{
		Version:  InclusionProofVersion,
		Entry:    entry,
		LeafHash: leaf,
		Path:     nil, // empty path → derived root == leaf
	}
	proof.Binding.PackID = "pack-forged"
	proof.Binding.ManifestHash = "sha256:" + strings.Repeat("a", 64)
	proof.Binding.PolicyHash = "sha256:" + strings.Repeat("b", 64)
	proof.Binding.EntriesMerkleRoot = leaf // the leaf declares itself the root

	bindingHash, err := computeBindingHash(proof)
	if err != nil {
		t.Fatalf("computeBindingHash: %v", err)
	}
	proof.BindingHash = bindingHash
	return proof
}

func TestF10_SelfAttestedProofIsRejected(t *testing.T) {
	proof := forgeSelfAttestedProof(t)

	if err := VerifyInclusionProof(proof); err == nil {
		t.Fatal("a forged proof whose leaf is its own root verified — any entry could be " +
			"claimed to belong to any pack")
	}
}

func TestF10_ExternalRootIsRequired(t *testing.T) {
	proof := forgeSelfAttestedProof(t)

	if err := VerifyInclusionProofAgainstRoot(proof, ""); err == nil {
		t.Fatal("an empty expected root was accepted — that silently degrades to self-attestation")
	}
}

// The forged proof must fail against a root the attacker does not control, even
// though it is perfectly self-consistent.
func TestF10_ForgedProofFailsAgainstAGenuineRoot(t *testing.T) {
	proof := forgeSelfAttestedProof(t)
	genuineRoot := "sha256:" + strings.Repeat("c", 64)

	err := VerifyInclusionProofAgainstRoot(proof, genuineRoot)
	if err == nil {
		t.Fatal("a forged proof verified against a root it does not reach")
	}
	if !strings.Contains(err.Error(), "does not match the expected pack root") {
		t.Fatalf("error should name the root mismatch, got: %v", err)
	}
}

// Negative control: the forgery really is internally consistent, so the tests
// above are rejecting it for the right reason rather than because it is
// malformed.
func TestF10_ForgedProofIsInternallyConsistent(t *testing.T) {
	proof := forgeSelfAttestedProof(t)

	want, err := computeBindingHash(proof)
	if err != nil {
		t.Fatal(err)
	}
	if proof.BindingHash != want {
		t.Fatal("forged binding hash does not self-check — the test fixture is wrong")
	}
	derived, err := VerifyInclusionPath(proof.LeafHash, proof.Path)
	if err != nil {
		t.Fatal(err)
	}
	if derived != proof.Binding.EntriesMerkleRoot {
		t.Fatal("forged proof does not reconstruct its own declared root — fixture is wrong")
	}
}
