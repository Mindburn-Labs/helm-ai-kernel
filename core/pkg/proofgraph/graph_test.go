package proofgraph

import (
	"testing"
)

func TestGraph_AppendAndValidate(t *testing.T) {
	g := NewGraph()

	n1, err := g.Append(NodeTypeIntent, []byte(`{"intent":"create_file"}`), "user:1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if n1.Lamport != 1 {
		t.Errorf("lamport = %d, want 1", n1.Lamport)
	}

	n2, err := g.Append(NodeTypeAttestation, []byte(`{"decision":"PASS"}`), "user:1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if n2.Lamport != 2 {
		t.Errorf("lamport = %d, want 2", n2.Lamport)
	}
	// n2 should have n1 as parent
	if len(n2.Parents) != 1 || n2.Parents[0] != n1.NodeHash {
		t.Errorf("n2 parents = %v, want [%s]", n2.Parents, n1.NodeHash)
	}

	n3, err := g.Append(NodeTypeEffect, []byte(`{"effect":"file_created"}`), "user:1", 3)
	if err != nil {
		t.Fatal(err)
	}

	// Validate full chain
	if err := g.ValidateChain(n3.NodeHash); err != nil {
		t.Fatalf("chain validation failed: %v", err)
	}

	if g.Len() != 3 {
		t.Errorf("graph len = %d, want 3", g.Len())
	}
}

func TestGraph_LamportMonotonicity(t *testing.T) {
	g := NewGraph()

	var prevClock uint64
	for i := 0; i < 100; i++ {
		n, err := g.Append(NodeTypeEffect, []byte(`{}`), "auto", uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if n.Lamport <= prevClock {
			t.Fatalf("lamport not monotonic: %d <= %d at step %d", n.Lamport, prevClock, i)
		}
		prevClock = n.Lamport
	}
}

func TestNode_HashIntegrity(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`"test"`), 1, "p", 1)
	if err := n.Validate(); err != nil {
		t.Fatalf("fresh node should validate: %v", err)
	}

	// Tamper with payload
	n.Payload = []byte(`"tampered"`) // Valid JSON string but different content
	if err := n.Validate(); err == nil {
		t.Fatal("tampered node should fail validation")
	}
}

func TestGraph_TrustEvent(t *testing.T) {
	g := NewGraph()

	payload := []byte(`{"event":"KEY_ROTATED","key_id":"k-1","public_key":"abc123"}`)
	n, err := g.Append(NodeTypeTrustEvent, payload, "p", 1)
	if err != nil {
		t.Fatal(err)
	}
	if n.Kind != NodeTypeTrustEvent {
		t.Errorf("type = %s, want TRUST_EVENT", n.Kind)
	}
}

func TestNode_JCSConsistency(t *testing.T) {
	// Verify that ComputeNodeHash is deterministic: same node → same hash every time
	n := NewNode(NodeTypeIntent, []string{"parent1", "parent2"}, []byte(`{"key":"value","nested":{"a":1}}`), 42, "principal:test", 7)
	hash1 := n.ComputeNodeHash()
	hash2 := n.ComputeNodeHash()
	if hash1 != hash2 {
		t.Fatalf("JCS hashing not deterministic: %s != %s", hash1, hash2)
	}
	if hash1 != n.NodeHash {
		t.Fatalf("node hash mismatch after construction: computed=%s stored=%s", hash1, n.NodeHash)
	}
}

func TestNode_JCSDeterminism(t *testing.T) {
	// Two independently constructed nodes with identical data must produce identical hashes
	payload := []byte(`{"tool":"web_search","query":"test"}`)
	n1 := &Node{
		Kind:         NodeTypeEffect,
		Parents:      []string{"abc123"},
		Lamport:      10,
		Principal:    "user:alice",
		PrincipalSeq: 3,
		Payload:      payload,
		Sig:          "sig-data",
		Timestamp:    1708200000000,
	}
	n2 := &Node{
		Kind:         NodeTypeEffect,
		Parents:      []string{"abc123"},
		Lamport:      10,
		Principal:    "user:alice",
		PrincipalSeq: 3,
		Payload:      payload,
		Sig:          "sig-data",
		Timestamp:    1708200000000,
	}
	h1 := n1.ComputeNodeHash()
	h2 := n2.ComputeNodeHash()
	if h1 == "" || h2 == "" {
		t.Fatal("hash computation failed")
	}
	if h1 != h2 {
		t.Fatalf("independent nodes with same data produced different hashes: %s != %s", h1, h2)
	}
}

func TestGraph_AppendSigned(t *testing.T) {
	g := NewGraph()

	// Append a regular node first
	n1, err := g.Append(NodeTypeIntent, []byte(`{"intent":"deploy"}`), "user:1", 1)
	if err != nil {
		t.Fatal(err)
	}

	// AppendSigned: the node must be stored under the post-signature hash
	n2, err := g.AppendSigned(NodeTypeAttestation, []byte(`{"decision":"PASS"}`), "sig-abc123", "user:1", 2)
	if err != nil {
		t.Fatal(err)
	}

	// Signature must be set
	if n2.Sig != "sig-abc123" {
		t.Fatalf("sig = %q, want %q", n2.Sig, "sig-abc123")
	}

	// Node must be retrievable by the returned hash
	got, ok := g.Get(n2.NodeHash)
	if !ok {
		t.Fatal("AppendSigned node not found by its NodeHash (stale map key)")
	}
	if got.Sig != "sig-abc123" {
		t.Fatalf("retrieved node sig = %q, want %q", got.Sig, "sig-abc123")
	}

	// Hash must be self-consistent
	if err := n2.Validate(); err != nil {
		t.Fatalf("signed node fails validation: %v", err)
	}

	// Chain must be valid
	if err := g.ValidateChain(n2.NodeHash); err != nil {
		t.Fatalf("chain validation failed: %v", err)
	}

	// Parents must reference n1
	if len(n2.Parents) != 1 || n2.Parents[0] != n1.NodeHash {
		t.Errorf("parents = %v, want [%s]", n2.Parents, n1.NodeHash)
	}

	// Lamport must be monotonic
	if n2.Lamport <= n1.Lamport {
		t.Errorf("lamport %d not > %d", n2.Lamport, n1.Lamport)
	}

	// Heads must point to the signed node
	heads := g.Heads()
	if len(heads) != 1 || heads[0] != n2.NodeHash {
		t.Errorf("heads = %v, want [%s]", heads, n2.NodeHash)
	}
}
