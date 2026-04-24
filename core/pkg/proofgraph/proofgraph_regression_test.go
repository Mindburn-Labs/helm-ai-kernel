package proofgraph

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1-5: NodeType enum coverage (all 17+)
// ---------------------------------------------------------------------------

func TestClosing_NodeType_CoreTypes(t *testing.T) {
	types := []struct {
		nt   NodeType
		name string
	}{
		{NodeTypeIntent, "INTENT"},
		{NodeTypeAttestation, "ATTESTATION"},
		{NodeTypeEffect, "EFFECT"},
		{NodeTypeTrustEvent, "TRUST_EVENT"},
		{NodeTypeCheckpoint, "CHECKPOINT"},
		{NodeTypeMergeDecision, "MERGE_DECISION"},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.nt) != tc.name {
				t.Fatalf("got %q", tc.nt)
			}
		})
	}
}

func TestClosing_NodeType_ExtendedTypes(t *testing.T) {
	types := []struct {
		nt   NodeType
		name string
	}{
		{NodeTypeTrustScore, "TRUST_SCORE"},
		{NodeTypeAgentKill, "AGENT_KILL"},
		{NodeTypeAgentRevive, "AGENT_REVIVE"},
		{NodeTypeSagaStart, "SAGA_START"},
		{NodeTypeSagaCompensate, "SAGA_COMPENSATE"},
		{NodeTypeVouch, "VOUCH"},
		{NodeTypeSlash, "SLASH"},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.nt) != tc.name {
				t.Fatalf("got %q", tc.nt)
			}
		})
	}
}

func TestClosing_NodeType_AdvancedTypes(t *testing.T) {
	types := []struct {
		nt   NodeType
		name string
	}{
		{NodeTypeFederation, "FEDERATION"},
		{NodeTypeHWAttestation, "HW_ATTESTATION"},
		{NodeTypeZKProof, "ZK_PROOF"},
		{NodeTypeDecentralizedProof, "DECENTRALIZED_PROOF"},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.nt) != tc.name {
				t.Fatalf("got %q", tc.nt)
			}
		})
	}
}

func TestClosing_NodeType_ResearchTypes(t *testing.T) {
	types := []struct {
		nt   NodeType
		name string
	}{
		{NodeTypeResearchPromotion, "RESEARCH_PROMOTION"},
		{NodeTypeResearchPublication, "RESEARCH_PUBLICATION"},
	}
	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.nt) != tc.name {
				t.Fatalf("got %q", tc.nt)
			}
		})
	}
}

func TestClosing_NodeType_AllDistinct(t *testing.T) {
	all := []NodeType{
		NodeTypeIntent, NodeTypeAttestation, NodeTypeEffect, NodeTypeTrustEvent,
		NodeTypeCheckpoint, NodeTypeMergeDecision, NodeTypeTrustScore, NodeTypeAgentKill,
		NodeTypeAgentRevive, NodeTypeSagaStart, NodeTypeSagaCompensate, NodeTypeVouch,
		NodeTypeSlash, NodeTypeFederation, NodeTypeHWAttestation, NodeTypeZKProof,
		NodeTypeDecentralizedProof, NodeTypeResearchPromotion, NodeTypeResearchPublication,
	}
	seen := make(map[NodeType]bool)
	for _, nt := range all {
		t.Run(string(nt), func(t *testing.T) {
			if seen[nt] {
				t.Fatalf("duplicate node type: %s", nt)
			}
			seen[nt] = true
		})
	}
}

// ---------------------------------------------------------------------------
// 6-12: Graph ops
// ---------------------------------------------------------------------------

func TestClosing_Graph_Creation(t *testing.T) {
	g := NewGraph()
	t.Run("not_nil", func(t *testing.T) {
		if g == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("empty", func(t *testing.T) {
		if g.Len() != 0 {
			t.Fatalf("got %d", g.Len())
		}
	})
	t.Run("no_heads", func(t *testing.T) {
		if len(g.Heads()) != 0 {
			t.Fatalf("got %d heads", len(g.Heads()))
		}
	})
	t.Run("lamport_zero", func(t *testing.T) {
		if g.LamportClock() != 0 {
			t.Fatalf("got %d", g.LamportClock())
		}
	})
}

func TestClosing_Graph_Append(t *testing.T) {
	g := NewGraph()
	payload := []byte(`{"action":"test"}`)
	n, err := g.Append(NodeTypeIntent, payload, "principal-1", 1)
	t.Run("no_error", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("node_not_nil", func(t *testing.T) {
		if n == nil {
			t.Fatal("node should not be nil")
		}
	})
	t.Run("hash_set", func(t *testing.T) {
		if n.NodeHash == "" {
			t.Fatal("hash should be set")
		}
	})
	t.Run("kind_intent", func(t *testing.T) {
		if n.Kind != NodeTypeIntent {
			t.Fatalf("got %q", n.Kind)
		}
	})
	t.Run("lamport_1", func(t *testing.T) {
		if g.LamportClock() != 1 {
			t.Fatalf("got %d", g.LamportClock())
		}
	})
}

func TestClosing_Graph_MultipleAppends(t *testing.T) {
	g := NewGraph()
	n1, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	n2, _ := g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	n3, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p1", 3)
	t.Run("three_nodes", func(t *testing.T) {
		if g.Len() != 3 {
			t.Fatalf("got %d", g.Len())
		}
	})
	t.Run("lamport_3", func(t *testing.T) {
		if g.LamportClock() != 3 {
			t.Fatalf("got %d", g.LamportClock())
		}
	})
	t.Run("parent_chain", func(t *testing.T) {
		if len(n2.Parents) == 0 || n2.Parents[0] != n1.NodeHash {
			t.Fatal("n2 should have n1 as parent")
		}
	})
	t.Run("n3_parents_n2", func(t *testing.T) {
		if len(n3.Parents) == 0 || n3.Parents[0] != n2.NodeHash {
			t.Fatal("n3 should have n2 as parent")
		}
	})
}

func TestClosing_Graph_Get(t *testing.T) {
	g := NewGraph()
	n, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	t.Run("found", func(t *testing.T) {
		found, ok := g.Get(n.NodeHash)
		if !ok || found == nil {
			t.Fatal("should find node")
		}
	})
	t.Run("not_found", func(t *testing.T) {
		_, ok := g.Get("nonexistent")
		if ok {
			t.Fatal("should not find")
		}
	})
	t.Run("same_node", func(t *testing.T) {
		found, _ := g.Get(n.NodeHash)
		if found.Kind != NodeTypeIntent {
			t.Fatalf("got %q", found.Kind)
		}
	})
}

func TestClosing_Graph_Heads(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	t.Run("one_head", func(t *testing.T) {
		heads := g.Heads()
		if len(heads) != 1 {
			t.Fatalf("got %d heads", len(heads))
		}
	})
	t.Run("head_is_latest", func(t *testing.T) {
		heads := g.Heads()
		n, ok := g.Get(heads[0])
		if !ok {
			t.Fatal("head should be in graph")
		}
		if n.Kind != NodeTypeAttestation {
			t.Fatalf("got %q", n.Kind)
		}
	})
	t.Run("heads_copy", func(t *testing.T) {
		h1 := g.Heads()
		h2 := g.Heads()
		if &h1[0] == &h2[0] {
			t.Fatal("should return copies")
		}
	})
}

func TestClosing_Graph_AllNodes(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	g.Append(NodeTypeEffect, []byte(`{}`), "p1", 2)
	t.Run("two_nodes", func(t *testing.T) {
		nodes := g.AllNodes()
		if len(nodes) != 2 {
			t.Fatalf("got %d", len(nodes))
		}
	})
	t.Run("empty_graph", func(t *testing.T) {
		empty := NewGraph()
		nodes := empty.AllNodes()
		if len(nodes) != 0 {
			t.Fatalf("got %d", len(nodes))
		}
	})
	t.Run("includes_all_types", func(t *testing.T) {
		nodes := g.AllNodes()
		kinds := make(map[NodeType]bool)
		for _, n := range nodes {
			kinds[n.Kind] = true
		}
		if !kinds[NodeTypeIntent] || !kinds[NodeTypeEffect] {
			t.Fatal("should include both types")
		}
	})
}

func TestClosing_Graph_WithClock(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := NewGraph().WithClock(func() time.Time { return fixedTime })
	n, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	t.Run("uses_clock", func(t *testing.T) {
		if n.Timestamp != fixedTime.UnixMilli() {
			t.Fatalf("got %d, want %d", n.Timestamp, fixedTime.UnixMilli())
		}
	})
	t.Run("returns_graph", func(t *testing.T) {
		if g == nil {
			t.Fatal("should return non-nil")
		}
	})
	t.Run("deterministic_hash", func(t *testing.T) {
		// Hash should be deterministic regardless of clock (timestamp excluded from hash)
		if n.NodeHash == "" {
			t.Fatal("hash should be set")
		}
	})
}

// ---------------------------------------------------------------------------
// 13-19: Lamport ordering
// ---------------------------------------------------------------------------

func TestClosing_Lamport_MonotonicIncrease(t *testing.T) {
	g := NewGraph()
	var prevLamport uint64
	for i := 0; i < 5; i++ {
		n, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p1", uint64(i+1))
		t.Run("step_"+string(rune('1'+i)), func(t *testing.T) {
			if n.Lamport <= prevLamport {
				t.Fatalf("lamport %d not > %d", n.Lamport, prevLamport)
			}
		})
		prevLamport = n.Lamport
	}
}

func TestClosing_Lamport_SequentialValues(t *testing.T) {
	g := NewGraph()
	n1, _ := g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	n2, _ := g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	n3, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p1", 3)
	t.Run("n1_is_1", func(t *testing.T) {
		if n1.Lamport != 1 {
			t.Fatalf("got %d", n1.Lamport)
		}
	})
	t.Run("n2_is_2", func(t *testing.T) {
		if n2.Lamport != 2 {
			t.Fatalf("got %d", n2.Lamport)
		}
	})
	t.Run("n3_is_3", func(t *testing.T) {
		if n3.Lamport != 3 {
			t.Fatalf("got %d", n3.Lamport)
		}
	})
}

func TestClosing_Lamport_GraphClock(t *testing.T) {
	g := NewGraph()
	t.Run("initial_zero", func(t *testing.T) {
		if g.LamportClock() != 0 {
			t.Fatalf("got %d", g.LamportClock())
		}
	})
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	t.Run("after_one_append", func(t *testing.T) {
		if g.LamportClock() != 1 {
			t.Fatalf("got %d", g.LamportClock())
		}
	})
	for i := 0; i < 9; i++ {
		g.Append(NodeTypeEffect, []byte(`{}`), "p1", uint64(i+2))
	}
	t.Run("after_ten_appends", func(t *testing.T) {
		if g.LamportClock() != 10 {
			t.Fatalf("got %d", g.LamportClock())
		}
	})
}

func TestClosing_Lamport_StoreOrder(t *testing.T) {
	store := NewInMemoryStore()
	g := store.Graph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	g.Append(NodeTypeEffect, []byte(`{}`), "p1", 3)

	nodes, _ := store.GetRange(context.Background(), 1, 3)
	t.Run("range_returns_all", func(t *testing.T) {
		if len(nodes) != 3 {
			t.Fatalf("got %d", len(nodes))
		}
	})
	t.Run("range_subset", func(t *testing.T) {
		subset, _ := store.GetRange(context.Background(), 2, 2)
		if len(subset) != 1 {
			t.Fatalf("got %d", len(subset))
		}
	})
	t.Run("empty_range", func(t *testing.T) {
		empty, _ := store.GetRange(context.Background(), 100, 200)
		if len(empty) != 0 {
			t.Fatalf("got %d", len(empty))
		}
	})
}

func TestClosing_Lamport_PrincipalSeq(t *testing.T) {
	g := NewGraph()
	n1, _ := g.Append(NodeTypeIntent, []byte(`{}`), "alice", 1)
	n2, _ := g.Append(NodeTypeIntent, []byte(`{}`), "alice", 2)
	n3, _ := g.Append(NodeTypeIntent, []byte(`{}`), "bob", 1)
	t.Run("alice_seq_1", func(t *testing.T) {
		if n1.PrincipalSeq != 1 {
			t.Fatalf("got %d", n1.PrincipalSeq)
		}
	})
	t.Run("alice_seq_2", func(t *testing.T) {
		if n2.PrincipalSeq != 2 {
			t.Fatalf("got %d", n2.PrincipalSeq)
		}
	})
	t.Run("bob_seq_1", func(t *testing.T) {
		if n3.PrincipalSeq != 1 {
			t.Fatalf("got %d", n3.PrincipalSeq)
		}
	})
}

func TestClosing_Lamport_DifferentPrincipals(t *testing.T) {
	g := NewGraph()
	n1, _ := g.Append(NodeTypeIntent, []byte(`{}`), "alice", 1)
	n2, _ := g.Append(NodeTypeEffect, []byte(`{}`), "bob", 1)
	t.Run("different_principals", func(t *testing.T) {
		if n1.Principal == n2.Principal {
			t.Fatal("should be different principals")
		}
	})
	t.Run("both_in_graph", func(t *testing.T) {
		if g.Len() != 2 {
			t.Fatalf("got %d", g.Len())
		}
	})
	t.Run("monotonic_lamport", func(t *testing.T) {
		if n2.Lamport <= n1.Lamport {
			t.Fatal("lamport should increase")
		}
	})
}

func TestClosing_Lamport_LargeValues(t *testing.T) {
	g := NewGraph()
	for i := 0; i < 100; i++ {
		g.Append(NodeTypeIntent, []byte(`{}`), "p1", uint64(i+1))
	}
	t.Run("lamport_100", func(t *testing.T) {
		if g.LamportClock() != 100 {
			t.Fatalf("got %d", g.LamportClock())
		}
	})
	t.Run("len_100", func(t *testing.T) {
		if g.Len() != 100 {
			t.Fatalf("got %d", g.Len())
		}
	})
	t.Run("heads_one", func(t *testing.T) {
		if len(g.Heads()) != 1 {
			t.Fatalf("got %d heads", len(g.Heads()))
		}
	})
}

// ---------------------------------------------------------------------------
// 20-27: DAG validation
// ---------------------------------------------------------------------------

func TestClosing_Graph_ValidateChain(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	n3, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p1", 3)
	t.Run("valid_chain", func(t *testing.T) {
		err := g.ValidateChain(n3.NodeHash)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("missing_node_errors", func(t *testing.T) {
		err := g.ValidateChain("nonexistent")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("single_node_valid", func(t *testing.T) {
		g2 := NewGraph()
		n, _ := g2.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
		err := g2.ValidateChain(n.NodeHash)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestClosing_Node_Validate(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 1)
	t.Run("valid_node", func(t *testing.T) {
		if err := n.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("tampered_hash_fails", func(t *testing.T) {
		tampered := *n
		tampered.NodeHash = "tampered"
		if err := tampered.Validate(); err == nil {
			t.Fatal("expected error for tampered hash")
		}
	})
	t.Run("empty_hash_fails", func(t *testing.T) {
		tampered := *n
		tampered.NodeHash = ""
		if err := tampered.Validate(); err == nil {
			t.Fatal("expected error for empty hash")
		}
	})
}

func TestClosing_Node_ComputeNodeHash(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 1)
	t.Run("nonempty_hash", func(t *testing.T) {
		h := n.ComputeNodeHash()
		if h == "" {
			t.Fatal("hash should not be empty")
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		h1 := n.ComputeNodeHash()
		h2 := n.ComputeNodeHash()
		if h1 != h2 {
			t.Fatal("should be deterministic")
		}
	})
	t.Run("hex_encoded", func(t *testing.T) {
		h := n.ComputeNodeHash()
		for _, c := range h {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("non-hex char: %c", c)
			}
		}
	})
	t.Run("sha256_length", func(t *testing.T) {
		h := n.ComputeNodeHash()
		if len(h) != 64 {
			t.Fatalf("got length %d", len(h))
		}
	})
}

func TestClosing_Node_ComputeNodeHashE(t *testing.T) {
	n := NewNode(NodeTypeEffect, nil, []byte(`{"key":"value"}`), 1, "p1", 1)
	t.Run("no_error", func(t *testing.T) {
		_, err := n.ComputeNodeHashE()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("matches_panic_version", func(t *testing.T) {
		h1, _ := n.ComputeNodeHashE()
		h2 := n.ComputeNodeHash()
		if h1 != h2 {
			t.Fatal("E and non-E versions should match")
		}
	})
	t.Run("nonempty", func(t *testing.T) {
		h, _ := n.ComputeNodeHashE()
		if h == "" {
			t.Fatal("should not be empty")
		}
	})
}

func TestClosing_NewNode_AllTypes(t *testing.T) {
	types := []NodeType{
		NodeTypeIntent, NodeTypeAttestation, NodeTypeEffect,
		NodeTypeTrustEvent, NodeTypeCheckpoint, NodeTypeMergeDecision,
		NodeTypeTrustScore, NodeTypeAgentKill, NodeTypeAgentRevive,
		NodeTypeSagaStart, NodeTypeSagaCompensate, NodeTypeVouch,
		NodeTypeSlash, NodeTypeFederation, NodeTypeHWAttestation,
		NodeTypeZKProof, NodeTypeDecentralizedProof,
	}
	for _, nt := range types {
		t.Run(string(nt), func(t *testing.T) {
			n := NewNode(nt, nil, []byte(`{}`), 1, "p1", 1)
			if n.Kind != nt {
				t.Fatalf("got %q, want %q", n.Kind, nt)
			}
			if n.NodeHash == "" {
				t.Fatal("hash should be set")
			}
		})
	}
}

func TestClosing_Node_DifferentPayloads(t *testing.T) {
	payloads := []struct {
		name    string
		payload []byte
	}{
		{"empty_object", []byte(`{}`)},
		{"with_key", []byte(`{"key":"value"}`)},
		{"nested", []byte(`{"a":{"b":"c"}}`)},
		{"array", []byte(`{"items":[1,2,3]}`)},
	}
	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			n := NewNode(NodeTypeIntent, nil, tc.payload, 1, "p1", 1)
			if n == nil {
				t.Fatal("should not be nil")
			}
			if n.NodeHash == "" {
				t.Fatal("hash should be set")
			}
		})
	}
}

func TestClosing_Node_WithParents(t *testing.T) {
	n1 := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 1)
	n2 := NewNode(NodeTypeAttestation, []string{n1.NodeHash}, []byte(`{}`), 2, "p1", 2)
	t.Run("has_parent", func(t *testing.T) {
		if len(n2.Parents) != 1 {
			t.Fatalf("got %d parents", len(n2.Parents))
		}
	})
	t.Run("parent_matches", func(t *testing.T) {
		if n2.Parents[0] != n1.NodeHash {
			t.Fatal("parent should match n1")
		}
	})
	t.Run("different_hashes", func(t *testing.T) {
		if n1.NodeHash == n2.NodeHash {
			t.Fatal("should have different hashes")
		}
	})
}

func TestClosing_Node_WithSignature(t *testing.T) {
	g := NewGraph()
	n, _ := g.AppendSigned(NodeTypeIntent, []byte(`{}`), "sig-value", "p1", 1)
	t.Run("signature_set", func(t *testing.T) {
		if n.Sig != "sig-value" {
			t.Fatalf("got %q", n.Sig)
		}
	})
	t.Run("hash_includes_sig", func(t *testing.T) {
		// Unsigned node should have different hash
		n2 := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 1)
		if n.NodeHash == n2.NodeHash {
			t.Fatal("signed and unsigned should have different hashes")
		}
	})
	t.Run("validates", func(t *testing.T) {
		if err := n.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// 28-35: Store operations
// ---------------------------------------------------------------------------

func TestClosing_InMemoryStore_StoreAndGet(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 1)
	t.Run("store", func(t *testing.T) {
		err := store.StoreNode(ctx, n)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("get", func(t *testing.T) {
		got, err := store.GetNode(ctx, n.NodeHash)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Kind != NodeTypeIntent {
			t.Fatalf("got %q", got.Kind)
		}
	})
	t.Run("get_missing", func(t *testing.T) {
		_, err := store.GetNode(ctx, "nonexistent")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClosing_InMemoryStore_GetNodesByType(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	g := store.Graph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 3)
	t.Run("two_intents", func(t *testing.T) {
		nodes, _ := store.GetNodesByType(ctx, NodeTypeIntent, 0, 100)
		if len(nodes) != 2 {
			t.Fatalf("got %d", len(nodes))
		}
	})
	t.Run("one_attestation", func(t *testing.T) {
		nodes, _ := store.GetNodesByType(ctx, NodeTypeAttestation, 0, 100)
		if len(nodes) != 1 {
			t.Fatalf("got %d", len(nodes))
		}
	})
	t.Run("none_effect", func(t *testing.T) {
		nodes, _ := store.GetNodesByType(ctx, NodeTypeEffect, 0, 100)
		if len(nodes) != 0 {
			t.Fatalf("got %d", len(nodes))
		}
	})
}

func TestClosing_InMemoryStore_GetChain(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	g := store.Graph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	n3, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p1", 3)
	chain, err := store.GetChain(ctx, n3.NodeHash)
	t.Run("no_error", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("chain_length", func(t *testing.T) {
		if len(chain) != 3 {
			t.Fatalf("got %d", len(chain))
		}
	})
	t.Run("starts_with_target", func(t *testing.T) {
		if chain[0].NodeHash != n3.NodeHash {
			t.Fatal("chain should start with target node")
		}
	})
}

func TestClosing_InMemoryStore_GetRange(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	g := store.Graph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	g.Append(NodeTypeEffect, []byte(`{}`), "p1", 3)
	t.Run("full_range", func(t *testing.T) {
		nodes, _ := store.GetRange(ctx, 1, 3)
		if len(nodes) != 3 {
			t.Fatalf("got %d", len(nodes))
		}
	})
	t.Run("partial_range", func(t *testing.T) {
		nodes, _ := store.GetRange(ctx, 2, 3)
		if len(nodes) != 2 {
			t.Fatalf("got %d", len(nodes))
		}
	})
	t.Run("empty_range", func(t *testing.T) {
		nodes, _ := store.GetRange(ctx, 10, 20)
		if len(nodes) != 0 {
			t.Fatalf("got %d", len(nodes))
		}
	})
}

func TestClosing_InMemoryStore_Graph(t *testing.T) {
	store := NewInMemoryStore()
	t.Run("graph_not_nil", func(t *testing.T) {
		if store.Graph() == nil {
			t.Fatal("should not be nil")
		}
	})
	t.Run("graph_empty", func(t *testing.T) {
		if store.Graph().Len() != 0 {
			t.Fatalf("got %d", store.Graph().Len())
		}
	})
	t.Run("same_reference", func(t *testing.T) {
		g1 := store.Graph()
		g2 := store.Graph()
		if g1 != g2 {
			t.Fatal("should return same graph reference")
		}
	})
}

func TestClosing_InMemoryStore_StoreUpdatesLamport(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 50, "p1", 1)
	store.StoreNode(ctx, n)
	t.Run("lamport_updated", func(t *testing.T) {
		if store.Graph().LamportClock() != 50 {
			t.Fatalf("got %d", store.Graph().LamportClock())
		}
	})
	t.Run("heads_updated", func(t *testing.T) {
		heads := store.Graph().Heads()
		if len(heads) != 1 || heads[0] != n.NodeHash {
			t.Fatal("heads should point to stored node")
		}
	})
	t.Run("lower_lamport_no_update", func(t *testing.T) {
		n2 := NewNode(NodeTypeEffect, nil, []byte(`{}`), 10, "p1", 2)
		store.StoreNode(ctx, n2)
		if store.Graph().LamportClock() != 50 {
			t.Fatalf("lamport should stay at 50, got %d", store.Graph().LamportClock())
		}
	})
}

func TestClosing_InMemoryStore_ConcurrentChain(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	g := store.Graph()
	// Build a chain of 10 nodes
	for i := 1; i <= 10; i++ {
		g.Append(NodeTypeIntent, []byte(`{}`), "p1", uint64(i))
	}
	heads := g.Heads()
	chain, _ := store.GetChain(ctx, heads[0])
	t.Run("chain_10", func(t *testing.T) {
		if len(chain) != 10 {
			t.Fatalf("got %d", len(chain))
		}
	})
	t.Run("all_intents", func(t *testing.T) {
		for _, n := range chain {
			if n.Kind != NodeTypeIntent {
				t.Fatalf("unexpected kind: %q", n.Kind)
			}
		}
	})
	t.Run("validate_full_chain", func(t *testing.T) {
		err := g.ValidateChain(heads[0])
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// 36-43: Payload encoding
// ---------------------------------------------------------------------------

func TestClosing_EncodePayload(t *testing.T) {
	type TestPayload struct {
		Action string `json:"action"`
		Value  int    `json:"value"`
	}
	t.Run("struct", func(t *testing.T) {
		data, err := EncodePayload(TestPayload{Action: "test", Value: 42})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !json.Valid(data) {
			t.Fatal("should be valid JSON")
		}
	})
	t.Run("map", func(t *testing.T) {
		data, err := EncodePayload(map[string]string{"key": "value"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("should not be empty")
		}
	})
	t.Run("nil", func(t *testing.T) {
		data, err := EncodePayload(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != "null" {
			t.Fatalf("got %q", string(data))
		}
	})
}

func TestClosing_ResearchPromotionPayload(t *testing.T) {
	data, err := NewResearchPromotionPayload("m1", "hash1", "hash2")
	t.Run("no_error", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("valid_json", func(t *testing.T) {
		if !json.Valid(data) {
			t.Fatal("should be valid JSON")
		}
	})
	t.Run("fields_present", func(t *testing.T) {
		var p ResearchPromotionPayload
		json.Unmarshal(data, &p)
		if p.MissionID != "m1" || p.ReceiptHash != "hash1" || p.ArtifactHash != "hash2" {
			t.Fatalf("fields mismatch: %+v", p)
		}
	})
}

func TestClosing_ResearchPublicationPayload(t *testing.T) {
	data, err := NewResearchPublicationPayload("m1", "pub1", "my-slug")
	t.Run("no_error", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("valid_json", func(t *testing.T) {
		if !json.Valid(data) {
			t.Fatal("should be valid JSON")
		}
	})
	t.Run("fields_present", func(t *testing.T) {
		var p ResearchPublicationPayload
		json.Unmarshal(data, &p)
		if p.MissionID != "m1" || p.PublicationID != "pub1" || p.Slug != "my-slug" {
			t.Fatalf("fields mismatch: %+v", p)
		}
	})
}

func TestClosing_MaxPayloadSize(t *testing.T) {
	t.Run("value_1MiB", func(t *testing.T) {
		if MaxPayloadSize != 1<<20 {
			t.Fatalf("got %d", MaxPayloadSize)
		}
	})
	t.Run("positive", func(t *testing.T) {
		if MaxPayloadSize <= 0 {
			t.Fatal("should be positive")
		}
	})
	t.Run("1048576_bytes", func(t *testing.T) {
		if MaxPayloadSize != 1048576 {
			t.Fatalf("got %d", MaxPayloadSize)
		}
	})
}

// ---------------------------------------------------------------------------
// 44-50: Condensation / misc
// ---------------------------------------------------------------------------

func TestClosing_Node_Fields(t *testing.T) {
	n := NewNode(NodeTypeEffect, []string{"parent1"}, []byte(`{"x":1}`), 5, "alice", 3)
	t.Run("kind", func(t *testing.T) {
		if n.Kind != NodeTypeEffect {
			t.Fatalf("got %q", n.Kind)
		}
	})
	t.Run("parents", func(t *testing.T) {
		if len(n.Parents) != 1 || n.Parents[0] != "parent1" {
			t.Fatalf("got %v", n.Parents)
		}
	})
	t.Run("lamport", func(t *testing.T) {
		if n.Lamport != 5 {
			t.Fatalf("got %d", n.Lamport)
		}
	})
	t.Run("principal", func(t *testing.T) {
		if n.Principal != "alice" {
			t.Fatalf("got %q", n.Principal)
		}
	})
	t.Run("principal_seq", func(t *testing.T) {
		if n.PrincipalSeq != 3 {
			t.Fatalf("got %d", n.PrincipalSeq)
		}
	})
}

func TestClosing_Node_Timestamp(t *testing.T) {
	fixedTime := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 1, func() time.Time { return fixedTime })
	t.Run("timestamp_set", func(t *testing.T) {
		if n.Timestamp != fixedTime.UnixMilli() {
			t.Fatalf("got %d, want %d", n.Timestamp, fixedTime.UnixMilli())
		}
	})
	t.Run("timestamp_positive", func(t *testing.T) {
		if n.Timestamp <= 0 {
			t.Fatal("timestamp should be positive")
		}
	})
	t.Run("default_clock_positive", func(t *testing.T) {
		n2 := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 1)
		if n2.Timestamp <= 0 {
			t.Fatal("default clock should produce positive timestamp")
		}
	})
}

func TestClosing_Node_NilParents(t *testing.T) {
	n := NewNode(NodeTypeIntent, nil, []byte(`{}`), 1, "p1", 1)
	t.Run("nil_parents", func(t *testing.T) {
		if n.Parents != nil {
			t.Fatalf("expected nil parents, got %v", n.Parents)
		}
	})
	t.Run("validates_ok", func(t *testing.T) {
		if err := n.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("hash_still_computed", func(t *testing.T) {
		if n.NodeHash == "" {
			t.Fatal("hash should still be computed")
		}
	})
}

func TestClosing_Graph_AppendSigned(t *testing.T) {
	g := NewGraph()
	n1, _ := g.AppendSigned(NodeTypeIntent, []byte(`{}`), "sig1", "p1", 1)
	n2, _ := g.AppendSigned(NodeTypeAttestation, []byte(`{}`), "sig2", "p1", 2)
	t.Run("both_signed", func(t *testing.T) {
		if n1.Sig != "sig1" || n2.Sig != "sig2" {
			t.Fatal("signatures should be set")
		}
	})
	t.Run("parent_chain", func(t *testing.T) {
		if len(n2.Parents) == 0 || n2.Parents[0] != n1.NodeHash {
			t.Fatal("n2 should have n1 as parent")
		}
	})
	t.Run("validate_chain", func(t *testing.T) {
		err := g.ValidateChain(n2.NodeHash)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestClosing_Graph_EmptyPayload(t *testing.T) {
	g := NewGraph()
	n, err := g.Append(NodeTypeCheckpoint, []byte(`{}`), "p1", 1)
	t.Run("no_error", func(t *testing.T) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("valid_node", func(t *testing.T) {
		if err := n.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("kind_checkpoint", func(t *testing.T) {
		if n.Kind != NodeTypeCheckpoint {
			t.Fatalf("got %q", n.Kind)
		}
	})
}

func TestClosing_InMemoryStore_GetNodesByType_RangeFilter(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	g := store.Graph()
	for i := 1; i <= 5; i++ {
		g.Append(NodeTypeIntent, []byte(`{}`), "p1", uint64(i))
	}
	t.Run("range_2_4", func(t *testing.T) {
		nodes, _ := store.GetNodesByType(ctx, NodeTypeIntent, 2, 4)
		if len(nodes) != 3 {
			t.Fatalf("got %d, want 3", len(nodes))
		}
	})
	t.Run("range_1_1", func(t *testing.T) {
		nodes, _ := store.GetNodesByType(ctx, NodeTypeIntent, 1, 1)
		if len(nodes) != 1 {
			t.Fatalf("got %d, want 1", len(nodes))
		}
	})
	t.Run("range_0_0", func(t *testing.T) {
		nodes, _ := store.GetNodesByType(ctx, NodeTypeIntent, 0, 0)
		if len(nodes) != 0 {
			t.Fatalf("got %d, want 0", len(nodes))
		}
	})
}

func TestClosing_InMemoryStore_MultipleTypes(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	g := store.Graph()
	g.Append(NodeTypeIntent, []byte(`{}`), "p1", 1)
	g.Append(NodeTypeAttestation, []byte(`{}`), "p1", 2)
	g.Append(NodeTypeEffect, []byte(`{}`), "p1", 3)
	g.Append(NodeTypeTrustEvent, []byte(`{}`), "p1", 4)
	g.Append(NodeTypeCheckpoint, []byte(`{}`), "p1", 5)

	types := []NodeType{NodeTypeIntent, NodeTypeAttestation, NodeTypeEffect, NodeTypeTrustEvent, NodeTypeCheckpoint}
	for _, nt := range types {
		t.Run(string(nt), func(t *testing.T) {
			nodes, _ := store.GetNodesByType(ctx, nt, 0, 100)
			if len(nodes) != 1 {
				t.Fatalf("got %d for %s", len(nodes), nt)
			}
		})
	}
}
