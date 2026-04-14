package proofgraph

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// ── Graph with 500 nodes ────────────────────────────────────────────────

func TestStress_Graph500Nodes(t *testing.T) {
	g := NewGraph()
	for i := range 500 {
		_, err := g.Append(NodeTypeEffect, []byte(fmt.Sprintf(`{"i":%d}`, i)), "principal", uint64(i))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if g.Len() != 500 {
		t.Fatalf("expected 500, got %d", g.Len())
	}
}

func TestStress_GraphNodeRetrieval(t *testing.T) {
	g := NewGraph()
	node, _ := g.Append(NodeTypeIntent, []byte(`{"test":true}`), "p1", 1)
	got, ok := g.Get(node.NodeHash)
	if !ok || got.NodeHash != node.NodeHash {
		t.Fatal("node retrieval failed")
	}
}

func TestStress_GraphHeadsUpdate(t *testing.T) {
	g := NewGraph()
	for i := range 10 {
		g.Append(NodeTypeAttestation, []byte(fmt.Sprintf(`{"i":%d}`, i)), "p", uint64(i))
	}
	heads := g.Heads()
	if len(heads) != 1 {
		t.Fatalf("expected 1 head, got %d", len(heads))
	}
}

func TestStress_GraphLamportIncrement(t *testing.T) {
	g := NewGraph()
	n1, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p", 0)
	n2, _ := g.Append(NodeTypeEffect, []byte(`{}`), "p", 1)
	if n2.Lamport <= n1.Lamport {
		t.Fatal("lamport should increment")
	}
}

// ── All NodeTypes ───────────────────────────────────────────────────────

func TestStress_AllNodeTypes(t *testing.T) {
	types := []NodeType{
		NodeTypeIntent, NodeTypeAttestation, NodeTypeEffect, NodeTypeTrustEvent,
		NodeTypeCheckpoint, NodeTypeMergeDecision, NodeTypeTrustScore, NodeTypeAgentKill,
		NodeTypeAgentRevive, NodeTypeSagaStart, NodeTypeSagaCompensate, NodeTypeVouch,
		NodeTypeSlash, NodeTypeFederation, NodeTypeHWAttestation, NodeTypeZKProof,
		NodeTypeDecentralizedProof,
	}
	g := NewGraph()
	for i, nt := range types {
		_, err := g.Append(nt, []byte(`{}`), "p", uint64(i))
		if err != nil {
			t.Fatalf("append %s: %v", nt, err)
		}
	}
	if g.Len() != len(types) {
		t.Fatalf("expected %d nodes, got %d", len(types), g.Len())
	}
}

// ── Node hash determinism ───────────────────────────────────────────────

func TestStress_NodeHashDeterministic(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedTime }
	node := NewNode(NodeTypeEffect, nil, []byte(`{"k":"v"}`), 1, "p", 0, clock)
	h1 := node.ComputeNodeHash()
	h2 := node.ComputeNodeHash()
	if h1 != h2 {
		t.Fatal("node hash should be deterministic")
	}
}

func TestStress_NodeHashIncludesPayload(t *testing.T) {
	fixedClock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	n1 := NewNode(NodeTypeEffect, nil, []byte(`{"a":1}`), 1, "p", 0, fixedClock)
	n2 := NewNode(NodeTypeEffect, nil, []byte(`{"a":2}`), 1, "p", 0, fixedClock)
	if n1.NodeHash == n2.NodeHash {
		t.Fatal("different payloads should produce different hashes")
	}
}

// ── AppendSigned ────────────────────────────────────────────────────────

func TestStress_AppendSigned(t *testing.T) {
	g := NewGraph()
	node, err := g.AppendSigned(NodeTypeAttestation, []byte(`{"sig":"yes"}`), "sig-value", "p", 0)
	if err != nil {
		t.Fatalf("append signed: %v", err)
	}
	if node.Sig != "sig-value" {
		t.Fatal("signature not set")
	}
}

// ── Graph with clock override ───────────────────────────────────────────

func TestStress_GraphWithClock(t *testing.T) {
	fixedTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	g := NewGraph().WithClock(func() time.Time { return fixedTime })
	node, _ := g.Append(NodeTypeCheckpoint, []byte(`{}`), "p", 0)
	if node.Timestamp != fixedTime.UnixMilli() {
		t.Fatalf("expected %d, got %d", fixedTime.UnixMilli(), node.Timestamp)
	}
}

// ── 200 nodes with parent chain ─────────────────────────────────────────

func TestStress_GraphParentChain200(t *testing.T) {
	g := NewGraph()
	var lastHash string
	for i := range 200 {
		node, _ := g.Append(NodeTypeEffect, []byte(fmt.Sprintf(`{"i":%d}`, i)), "p", uint64(i))
		if i > 0 && len(node.Parents) == 0 {
			t.Fatalf("node %d should have parents", i)
		}
		if i > 0 && node.Parents[0] != lastHash {
			t.Fatalf("parent mismatch at %d", i)
		}
		lastHash = node.NodeHash
	}
}

// ── Node JSON roundtrip ─────────────────────────────────────────────────

func TestStress_NodeJSONRoundtrip(t *testing.T) {
	g := NewGraph()
	node, _ := g.Append(NodeTypeIntent, []byte(`{"action":"test"}`), "principal-1", 42)
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Node
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.NodeHash != node.NodeHash {
		t.Fatal("hash mismatch after roundtrip")
	}
}

// ── Graph empty state ───────────────────────────────────────────────────

func TestStress_GraphEmptyLen(t *testing.T) {
	g := NewGraph()
	if g.Len() != 0 {
		t.Fatal("new graph should have 0 nodes")
	}
}

func TestStress_GraphEmptyHeads(t *testing.T) {
	g := NewGraph()
	if len(g.Heads()) != 0 {
		t.Fatal("new graph should have no heads")
	}
}

func TestStress_GraphGetMissing(t *testing.T) {
	g := NewGraph()
	_, ok := g.Get("nonexistent")
	if ok {
		t.Fatal("should not find nonexistent node")
	}
}

// ── Concurrent appends ──────────────────────────────────────────────────

func TestStress_GraphConcurrentAppends(t *testing.T) {
	g := NewGraph()
	done := make(chan struct{}, 100)
	for i := range 100 {
		go func(idx int) {
			g.Append(NodeTypeEffect, []byte(fmt.Sprintf(`{"c":%d}`, idx)), "p", uint64(idx))
			done <- struct{}{}
		}(i)
	}
	for range 100 {
		<-done
	}
	if g.Len() != 100 {
		t.Fatalf("expected 100 nodes, got %d", g.Len())
	}
}

// ── Large payload ───────────────────────────────────────────────────────

func TestStress_GraphLargePayload(t *testing.T) {
	g := NewGraph()
	// Build a large but valid JSON payload
	payload := []byte(`{"data":"` + string(make([]byte, 0)) + `"}`)
	largeData := make([]byte, 0, 64*1024)
	largeData = append(largeData, []byte(`{"data":"`)...)
	for i := range 64 * 1024 {
		largeData = append(largeData, "abcdefghij"[i%10])
	}
	largeData = append(largeData, []byte(`"}`)...)
	_ = payload
	_, err := g.Append(NodeTypeEffect, largeData, "p", 0)
	if err != nil {
		t.Fatalf("large payload: %v", err)
	}
}

// ── Node kind values ────────────────────────────────────────────────────

func TestStress_NodeKindIntent(t *testing.T) {
	if NodeTypeIntent != "INTENT" {
		t.Fatalf("got %s", NodeTypeIntent)
	}
}

func TestStress_NodeKindAttestation(t *testing.T) {
	if NodeTypeAttestation != "ATTESTATION" {
		t.Fatalf("got %s", NodeTypeAttestation)
	}
}

func TestStress_NodeKindEffect(t *testing.T) {
	if NodeTypeEffect != "EFFECT" {
		t.Fatalf("got %s", NodeTypeEffect)
	}
}

func TestStress_NodeKindCheckpoint(t *testing.T) {
	if NodeTypeCheckpoint != "CHECKPOINT" {
		t.Fatalf("got %s", NodeTypeCheckpoint)
	}
}

func TestStress_NodeKindTrustEvent(t *testing.T) {
	if NodeTypeTrustEvent != "TRUST_EVENT" {
		t.Fatalf("got %s", NodeTypeTrustEvent)
	}
}

func TestStress_NodeKindMergeDecision(t *testing.T) {
	if NodeTypeMergeDecision != "MERGE_DECISION" {
		t.Fatalf("got %s", NodeTypeMergeDecision)
	}
}

// ── Graph snapshot ──────────────────────────────────────────────────────

func TestStress_GraphLenAfter10Appends(t *testing.T) {
	g := NewGraph()
	for i := range 10 {
		g.Append(NodeTypeEffect, []byte(fmt.Sprintf(`{"i":%d}`, i)), "p", uint64(i))
	}
	if g.Len() != 10 {
		t.Fatalf("expected 10, got %d", g.Len())
	}
}

func TestStress_GraphLenGrowsAfterAppend(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeEffect, []byte(`{"a":1}`), "p", 0)
	l1 := g.Len()
	g.Append(NodeTypeEffect, []byte(`{"a":2}`), "p", 1)
	l2 := g.Len()
	if l2 != l1+1 {
		t.Fatal("len should grow after append")
	}
}

func TestStress_NodeKindAgentKill(t *testing.T) {
	if NodeTypeAgentKill != "AGENT_KILL" {
		t.Fatalf("got %s", NodeTypeAgentKill)
	}
}

func TestStress_NodeKindAgentRevive(t *testing.T) {
	if NodeTypeAgentRevive != "AGENT_REVIVE" {
		t.Fatalf("got %s", NodeTypeAgentRevive)
	}
}

func TestStress_NodeKindSagaStart(t *testing.T) {
	if NodeTypeSagaStart != "SAGA_START" {
		t.Fatalf("got %s", NodeTypeSagaStart)
	}
}

func TestStress_NodeKindSagaCompensate(t *testing.T) {
	if NodeTypeSagaCompensate != "SAGA_COMPENSATE" {
		t.Fatalf("got %s", NodeTypeSagaCompensate)
	}
}

func TestStress_NodeKindVouch(t *testing.T) {
	if NodeTypeVouch != "VOUCH" {
		t.Fatalf("got %s", NodeTypeVouch)
	}
}

func TestStress_NodeKindSlash(t *testing.T) {
	if NodeTypeSlash != "SLASH" {
		t.Fatalf("got %s", NodeTypeSlash)
	}
}

func TestStress_NodeKindFederation(t *testing.T) {
	if NodeTypeFederation != "FEDERATION" {
		t.Fatalf("got %s", NodeTypeFederation)
	}
}

func TestStress_NodeKindHWAttestation(t *testing.T) {
	if NodeTypeHWAttestation != "HW_ATTESTATION" {
		t.Fatalf("got %s", NodeTypeHWAttestation)
	}
}

func TestStress_NodeKindZKProof(t *testing.T) {
	if NodeTypeZKProof != "ZK_PROOF" {
		t.Fatalf("got %s", NodeTypeZKProof)
	}
}

func TestStress_NodeKindDecentralizedProof(t *testing.T) {
	if NodeTypeDecentralizedProof != "DECENTRALIZED_PROOF" {
		t.Fatalf("got %s", NodeTypeDecentralizedProof)
	}
}

func TestStress_NodeKindTrustScore(t *testing.T) {
	if NodeTypeTrustScore != "TRUST_SCORE" {
		t.Fatalf("got %s", NodeTypeTrustScore)
	}
}

func TestStress_GraphAppendSignedSetsHash(t *testing.T) {
	g := NewGraph()
	n, _ := g.AppendSigned(NodeTypeEffect, []byte(`{"x":1}`), "my-sig", "p", 0)
	if n.NodeHash == "" {
		t.Fatal("signed node should have hash")
	}
}

func TestStress_GraphAppendPreservesKind(t *testing.T) {
	g := NewGraph()
	n, _ := g.Append(NodeTypeTrustEvent, []byte(`{}`), "p", 0)
	if n.Kind != NodeTypeTrustEvent {
		t.Fatal("kind should be preserved")
	}
}

func TestStress_NodeComputeHashE(t *testing.T) {
	fixedClock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	n := NewNode(NodeTypeEffect, nil, []byte(`{}`), 1, "p", 0, fixedClock)
	h, err := n.ComputeNodeHashE()
	if err != nil {
		t.Fatalf("compute hash: %v", err)
	}
	if h != n.NodeHash {
		t.Fatal("computed hash should match node hash")
	}
}

func TestStress_GraphMultipleHeadsAfterReset(t *testing.T) {
	g := NewGraph()
	g.Append(NodeTypeEffect, []byte(`{"a":1}`), "p", 0)
	heads := g.Heads()
	if len(heads) != 1 {
		t.Fatalf("expected 1 head, got %d", len(heads))
	}
}

func TestStress_NodePrincipalPreserved(t *testing.T) {
	g := NewGraph()
	n, _ := g.Append(NodeTypeIntent, []byte(`{}`), "admin-42", 0)
	if n.Principal != "admin-42" {
		t.Fatal("principal should be preserved")
	}
}
