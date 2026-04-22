package crdt

import (
	"context"
	"fmt"
	"sync"
)

// MemoryTransport is an in-process transport for testing multi-node sync.
// Each MemoryTransport instance represents one node in the cluster.
type MemoryTransport struct {
	mu     sync.RWMutex
	nodeID string
	peers  map[string]*MemoryTransport
	inbox  chan *SyncMessage
}

// NewMemoryTransport creates a new in-memory transport with the given node ID.
func NewMemoryTransport(nodeID string) *MemoryTransport {
	return &MemoryTransport{
		nodeID: nodeID,
		peers:  make(map[string]*MemoryTransport),
		inbox:  make(chan *SyncMessage, 256),
	}
}

// Connect establishes a bidirectional link between this transport and a peer.
func (t *MemoryTransport) Connect(peer *MemoryTransport) {
	t.mu.Lock()
	t.peers[peer.nodeID] = peer
	t.mu.Unlock()

	peer.mu.Lock()
	peer.peers[t.nodeID] = t
	peer.mu.Unlock()
}

// Disconnect removes the bidirectional link between this transport and a peer.
// Useful for simulating network partitions.
func (t *MemoryTransport) Disconnect(peer *MemoryTransport) {
	t.mu.Lock()
	delete(t.peers, peer.nodeID)
	t.mu.Unlock()

	peer.mu.Lock()
	delete(peer.peers, t.nodeID)
	peer.mu.Unlock()
}

// Send delivers a message to a specific peer's inbox.
func (t *MemoryTransport) Send(ctx context.Context, peerID string, msg *SyncMessage) error {
	t.mu.RLock()
	peer, ok := t.peers[peerID]
	t.mu.RUnlock()

	if !ok {
		return fmt.Errorf("peer %s not connected", peerID)
	}

	select {
	case peer.inbox <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Receive blocks until a message arrives or the context is cancelled.
func (t *MemoryTransport) Receive(ctx context.Context) (*SyncMessage, error) {
	select {
	case msg := <-t.inbox:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Peers returns the IDs of all connected peers.
func (t *MemoryTransport) Peers() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]string, 0, len(t.peers))
	for id := range t.peers {
		result = append(result, id)
	}
	return result
}
