package proofgraph

import "testing"

func TestAppendSignedSetsDefaultAuthorPurpose(t *testing.T) {
	g := NewGraph()

	n, err := g.AppendSigned(NodeTypeIntent, []byte(`{"intent":"plan"}`), "sig-value", "principal-1", 1)
	if err != nil {
		t.Fatal(err)
	}

	if n.Sig != "sig-value" {
		t.Fatalf("signature = %q", n.Sig)
	}
	if n.SigPurpose != SignaturePurposeAuthor {
		t.Fatalf("signature purpose = %q, want %q", n.SigPurpose, SignaturePurposeAuthor)
	}
	if err := n.Validate(); err != nil {
		t.Fatalf("signed node should validate: %v", err)
	}
}

func TestAppendSignedWithPurposeRejectsInvalidPurpose(t *testing.T) {
	g := NewGraph()

	_, err := g.AppendSignedWithPurpose(NodeTypeIntent, []byte(`{}`), "sig-value", "delegate", "principal-1", 1)
	if err == nil {
		t.Fatal("expected invalid signature purpose to be rejected")
	}
	if g.Len() != 0 {
		t.Fatalf("invalid signed append should not persist a node, got len %d", g.Len())
	}
	if g.LamportClock() != 0 {
		t.Fatalf("invalid signed append should not advance lamport, got %d", g.LamportClock())
	}
}

func TestNodeValidateRejectsInvalidSignaturePurpose(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "principal-1", 1)
	n.Sig = "sig-value"
	n.SigPurpose = "delegate"
	n.NodeHash = n.ComputeNodeHash()

	if err := n.Validate(); err == nil {
		t.Fatal("expected invalid signature purpose to fail validation")
	}
}

func TestLegacySignedNodeWithoutPurposeRemainsReadable(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "principal-1", 1)
	n.Sig = "legacy-sig"
	n.NodeHash = n.ComputeNodeHash()

	if err := n.Validate(); err != nil {
		t.Fatalf("legacy signed node without purpose should validate: %v", err)
	}
}
