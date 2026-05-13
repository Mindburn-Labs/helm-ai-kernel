package crdt

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

func TestSyncProtocol_TwoNodes(t *testing.T) {
	gsetA := NewGSet()
	gsetB := NewGSet()

	transportA := NewMemoryTransport("node-a")
	transportB := NewMemoryTransport("node-b")
	transportA.Connect(transportB)

	// Add unique nodes to each set.
	nA := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"from":"a"}`), 1, "a", 1)
	nB := proofgraph.NewNode(proofgraph.NodeTypeEffect, nil, []byte(`{"from":"b"}`), 2, "b", 1)

	if err := gsetA.Add(nA); err != nil {
		t.Fatal(err)
	}
	if err := gsetB.Add(nB); err != nil {
		t.Fatal(err)
	}

	syncA := NewSyncProtocol("node-a", gsetA, transportA).WithInterval(10 * time.Millisecond)
	syncB := NewSyncProtocol("node-b", gsetB, transportB).WithInterval(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go syncA.Start(ctx)
	go syncB.Start(ctx)

	// Wait for convergence.
	deadline := time.After(2 * time.Second)
	for {
		if gsetA.Len() == 2 && gsetB.Len() == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("convergence timeout: a=%d, b=%d", gsetA.Len(), gsetB.Len())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Verify both have both nodes.
	if !gsetA.Contains(nB.NodeHash) {
		t.Error("node-a missing nB")
	}
	if !gsetB.Contains(nA.NodeHash) {
		t.Error("node-b missing nA")
	}

	syncA.Stop()
	syncB.Stop()
}

func TestSyncProtocol_ThreeNodes(t *testing.T) {
	gsetA := NewGSet()
	gsetB := NewGSet()
	gsetC := NewGSet()

	tA := NewMemoryTransport("a")
	tB := NewMemoryTransport("b")
	tC := NewMemoryTransport("c")

	// Fully connected.
	tA.Connect(tB)
	tA.Connect(tC)
	tB.Connect(tC)

	nA := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"node":"a"}`), 1, "a", 1)
	nB := proofgraph.NewNode(proofgraph.NodeTypeEffect, nil, []byte(`{"node":"b"}`), 2, "b", 1)
	nC := proofgraph.NewNode(proofgraph.NodeTypeAttestation, nil, []byte(`{"node":"c"}`), 3, "c", 1)

	if err := gsetA.Add(nA); err != nil {
		t.Fatal(err)
	}
	if err := gsetB.Add(nB); err != nil {
		t.Fatal(err)
	}
	if err := gsetC.Add(nC); err != nil {
		t.Fatal(err)
	}

	sA := NewSyncProtocol("a", gsetA, tA).WithInterval(10 * time.Millisecond)
	sB := NewSyncProtocol("b", gsetB, tB).WithInterval(10 * time.Millisecond)
	sC := NewSyncProtocol("c", gsetC, tC).WithInterval(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go sA.Start(ctx)
	go sB.Start(ctx)
	go sC.Start(ctx)

	deadline := time.After(5 * time.Second)
	for {
		if gsetA.Len() == 3 && gsetB.Len() == 3 && gsetC.Len() == 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("convergence timeout: a=%d, b=%d, c=%d", gsetA.Len(), gsetB.Len(), gsetC.Len())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	sA.Stop()
	sB.Stop()
	sC.Stop()
}

func TestSyncProtocol_PartitionRecovery(t *testing.T) {
	gsetA := NewGSet()
	gsetB := NewGSet()

	tA := NewMemoryTransport("a")
	tB := NewMemoryTransport("b")

	// Initially disconnected (partition).
	nA := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"partition":"a"}`), 1, "a", 1)
	nB := proofgraph.NewNode(proofgraph.NodeTypeEffect, nil, []byte(`{"partition":"b"}`), 2, "b", 1)

	if err := gsetA.Add(nA); err != nil {
		t.Fatal(err)
	}
	if err := gsetB.Add(nB); err != nil {
		t.Fatal(err)
	}

	sA := NewSyncProtocol("a", gsetA, tA).WithInterval(10 * time.Millisecond)
	sB := NewSyncProtocol("b", gsetB, tB).WithInterval(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go sA.Start(ctx)
	go sB.Start(ctx)

	// Let them try to gossip while partitioned (no peers).
	time.Sleep(50 * time.Millisecond)

	// They should still only have their own nodes.
	if gsetA.Len() != 1 || gsetB.Len() != 1 {
		t.Fatalf("should not have synced during partition: a=%d, b=%d", gsetA.Len(), gsetB.Len())
	}

	// Heal the partition.
	tA.Connect(tB)

	// Wait for convergence.
	deadline := time.After(5 * time.Second)
	for {
		if gsetA.Len() == 2 && gsetB.Len() == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("convergence timeout after partition heal: a=%d, b=%d", gsetA.Len(), gsetB.Len())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	sA.Stop()
	sB.Stop()
}

func TestSyncProtocol_DigestPullPush(t *testing.T) {
	// Test the full message exchange cycle manually without the gossip loop.
	gsetA := NewGSet()
	gsetB := NewGSet()

	nA := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, []byte(`{"manual":"a"}`), 1, "a", 1)
	nB := proofgraph.NewNode(proofgraph.NodeTypeEffect, nil, []byte(`{"manual":"b"}`), 2, "b", 1)
	shared := proofgraph.NewNode(proofgraph.NodeTypeCheckpoint, nil, []byte(`{"shared":true}`), 3, "s", 1)

	if err := gsetA.Add(nA); err != nil {
		t.Fatal(err)
	}
	if err := gsetA.Add(shared); err != nil {
		t.Fatal(err)
	}
	if err := gsetB.Add(nB); err != nil {
		t.Fatal(err)
	}
	if err := gsetB.Add(shared); err != nil {
		t.Fatal(err)
	}

	tA := NewMemoryTransport("a")
	tB := NewMemoryTransport("b")
	tA.Connect(tB)

	syncA := NewSyncProtocol("a", gsetA, tA)
	syncB := NewSyncProtocol("b", gsetB, tB)

	ctx := context.Background()

	// Step 1: A sends DIGEST to B.
	digestMsg := &SyncMessage{
		SenderID:    "a",
		MessageType: SyncDigest,
		Hashes:      hashList(gsetA.Hashes()),
		Timestamp:   time.Now(),
	}

	// Step 2: B handles the digest. B should:
	//   - Push nB to A (since A doesn't have it)
	//   - Return a PULL for nA (since B doesn't have it)
	resp, err := syncB.HandleMessage(ctx, digestMsg)
	if err != nil {
		t.Fatalf("B.HandleMessage(DIGEST): %v", err)
	}

	// B should have sent a PUSH to A's inbox (nB).
	select {
	case pushMsg := <-tA.inbox:
		if pushMsg.MessageType != SyncPush {
			t.Errorf("expected PUSH, got %s", pushMsg.MessageType)
		}
		if len(pushMsg.Nodes) != 1 {
			t.Errorf("PUSH has %d nodes, want 1", len(pushMsg.Nodes))
		}
		// A handles the push.
		if _, err := syncA.HandleMessage(ctx, pushMsg); err != nil {
			t.Fatalf("A.HandleMessage(PUSH): %v", err)
		}
	default:
		t.Fatal("expected PUSH message in A's inbox")
	}

	// resp should be a PULL for nA.
	if resp == nil {
		t.Fatal("expected PULL response from B, got nil")
	}
	if resp.MessageType != SyncPull {
		t.Errorf("expected PULL, got %s", resp.MessageType)
	}
	if len(resp.Hashes) != 1 {
		t.Errorf("PULL has %d hashes, want 1", len(resp.Hashes))
	}

	// Step 3: A handles B's PULL by sending nA.
	resp.SenderID = "b" // simulate receiving from B
	if _, err := syncA.HandleMessage(ctx, resp); err != nil {
		t.Fatalf("A.HandleMessage(PULL): %v", err)
	}

	// B should receive a PUSH with nA.
	select {
	case pushMsg := <-tB.inbox:
		if pushMsg.MessageType != SyncPush {
			t.Errorf("expected PUSH, got %s", pushMsg.MessageType)
		}
		if _, err := syncB.HandleMessage(ctx, pushMsg); err != nil {
			t.Fatalf("B.HandleMessage(PUSH): %v", err)
		}
	default:
		t.Fatal("expected PUSH message in B's inbox")
	}

	// Both should now have all 3 nodes.
	if gsetA.Len() != 3 {
		t.Errorf("a has %d nodes, want 3", gsetA.Len())
	}
	if gsetB.Len() != 3 {
		t.Errorf("b has %d nodes, want 3", gsetB.Len())
	}
}

func hashList(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for h := range m {
		result = append(result, h)
	}
	return result
}
