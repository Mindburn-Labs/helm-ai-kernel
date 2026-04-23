package crdt

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// SyncMessageType identifies the kind of gossip message.
type SyncMessageType string

const (
	// SyncDigest is sent to advertise which nodes the sender has (hash list).
	SyncDigest SyncMessageType = "DIGEST"
	// SyncPush carries nodes the receiver is missing.
	SyncPush SyncMessageType = "PUSH"
	// SyncPull requests nodes the sender is missing (hash list).
	SyncPull SyncMessageType = "PULL"
)

// DefaultSyncInterval is the default gossip tick interval.
const DefaultSyncInterval = 5 * time.Second

// SyncMessage is exchanged between nodes during gossip.
type SyncMessage struct {
	SenderID    string             `json:"sender_id"`
	MessageType SyncMessageType    `json:"message_type"`
	Hashes      []string           `json:"hashes,omitempty"` // for DIGEST and PULL messages
	Nodes       []*proofgraph.Node `json:"nodes,omitempty"`  // for PUSH messages
	Timestamp   time.Time          `json:"timestamp"`
}

// Transport is the network layer for gossip messages.
type Transport interface {
	// Send delivers a message to a specific peer.
	Send(ctx context.Context, peerID string, msg *SyncMessage) error
	// Receive blocks until a message arrives or the context is cancelled.
	Receive(ctx context.Context) (*SyncMessage, error)
	// Peers returns the IDs of all known peers.
	Peers() []string
}

// SyncProtocol manages gossip-based ProofGraph synchronization.
type SyncProtocol struct {
	nodeID    string
	gset      *GSet
	transport Transport
	interval  time.Duration
	clock     func() time.Time
	done      chan struct{}
}

// NewSyncProtocol creates a new gossip sync protocol.
func NewSyncProtocol(nodeID string, gset *GSet, transport Transport) *SyncProtocol {
	return &SyncProtocol{
		nodeID:    nodeID,
		gset:      gset,
		transport: transport,
		interval:  DefaultSyncInterval,
		clock:     time.Now,
		done:      make(chan struct{}),
	}
}

// WithInterval overrides the default gossip interval.
func (s *SyncProtocol) WithInterval(d time.Duration) *SyncProtocol {
	s.interval = d
	return s
}

// WithClock overrides the timestamp source (useful for testing).
func (s *SyncProtocol) WithClock(clock func() time.Time) *SyncProtocol {
	s.clock = clock
	return s
}

// Start begins the gossip loop. It runs two goroutines:
// 1. A ticker that periodically sends digests to a random peer.
// 2. A receiver that processes incoming messages.
// Start blocks until ctx is cancelled or Stop is called.
func (s *SyncProtocol) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// When Stop() is called, cancel the context.
	go func() {
		select {
		case <-s.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	// Start the receiver goroutine.
	go s.receiveLoop(ctx)

	// Gossip ticker.
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.gossipOnce(ctx)
		}
	}
}

// Stop gracefully shuts down the gossip loop.
func (s *SyncProtocol) Stop() {
	select {
	case <-s.done:
		// Already stopped.
	default:
		close(s.done)
	}
}

// HandleMessage processes an incoming sync message and returns a response (or nil).
func (s *SyncProtocol) HandleMessage(ctx context.Context, msg *SyncMessage) (*SyncMessage, error) {
	switch msg.MessageType {
	case SyncDigest:
		return s.handleDigest(ctx, msg)
	case SyncPush:
		return s.handlePush(ctx, msg)
	case SyncPull:
		return s.handlePull(ctx, msg)
	default:
		return nil, nil
	}
}

// handleDigest processes a DIGEST message.
// It computes what the sender is missing (nodes we have that they don't)
// and what we are missing (hashes they have that we don't).
// Returns a combined PUSH (nodes for them) + triggers a PULL (hashes we need).
func (s *SyncProtocol) handleDigest(ctx context.Context, msg *SyncMessage) (*SyncMessage, error) {
	peerHashes := make(map[string]bool, len(msg.Hashes))
	for _, h := range msg.Hashes {
		peerHashes[h] = true
	}

	// Nodes we have that the peer is missing -> PUSH to them.
	nodesToPush := s.gset.Delta(peerHashes)

	// Hashes the peer has that we are missing -> PULL from them.
	ourHashes := s.gset.Hashes()
	var hashesToPull []string
	for _, h := range msg.Hashes {
		if !ourHashes[h] {
			hashesToPull = append(hashesToPull, h)
		}
	}

	// Send PUSH with our delta.
	if len(nodesToPush) > 0 {
		pushMsg := &SyncMessage{
			SenderID:    s.nodeID,
			MessageType: SyncPush,
			Nodes:       nodesToPush,
			Timestamp:   s.clock(),
		}
		if err := s.transport.Send(ctx, msg.SenderID, pushMsg); err != nil {
			return nil, err
		}
	}

	// Send PULL for what we need.
	if len(hashesToPull) > 0 {
		pullMsg := &SyncMessage{
			SenderID:    s.nodeID,
			MessageType: SyncPull,
			Hashes:      hashesToPull,
			Timestamp:   s.clock(),
		}
		return pullMsg, nil
	}

	return nil, nil
}

// handlePush processes a PUSH message by adding nodes to our GSet.
func (s *SyncProtocol) handlePush(_ context.Context, msg *SyncMessage) (*SyncMessage, error) {
	var errCount int
	for _, node := range msg.Nodes {
		if err := s.gset.Add(node); err != nil {
			errCount++
			slog.Warn("crdt sync: failed to add node from push",
				"sender", msg.SenderID,
				"node_hash", node.NodeHash,
				"error", err,
			)
		}
	}
	if errCount > 0 {
		slog.Warn("crdt sync: push contained invalid nodes",
			"sender", msg.SenderID,
			"total", len(msg.Nodes),
			"errors", errCount,
		)
	}
	return nil, nil
}

// handlePull processes a PULL message by sending requested nodes.
func (s *SyncProtocol) handlePull(ctx context.Context, msg *SyncMessage) (*SyncMessage, error) {
	var nodes []*proofgraph.Node
	for _, h := range msg.Hashes {
		if n, ok := s.gset.Get(h); ok {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	resp := &SyncMessage{
		SenderID:    s.nodeID,
		MessageType: SyncPush,
		Nodes:       nodes,
		Timestamp:   s.clock(),
	}
	if err := s.transport.Send(ctx, msg.SenderID, resp); err != nil {
		return nil, err
	}
	return nil, nil
}

// gossipOnce picks a random peer and sends a digest.
func (s *SyncProtocol) gossipOnce(ctx context.Context) {
	peers := s.transport.Peers()
	if len(peers) == 0 {
		return
	}

	peer := peers[rand.IntN(len(peers))]

	hashes := s.gset.Hashes()
	hashList := make([]string, 0, len(hashes))
	for h := range hashes {
		hashList = append(hashList, h)
	}

	msg := &SyncMessage{
		SenderID:    s.nodeID,
		MessageType: SyncDigest,
		Hashes:      hashList,
		Timestamp:   s.clock(),
	}

	_ = s.transport.Send(ctx, peer, msg)
}

// receiveLoop continuously receives messages and processes them.
func (s *SyncProtocol) receiveLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := s.transport.Receive(ctx)
		if err != nil {
			// Context cancelled or transport closed.
			return
		}

		resp, err := s.HandleMessage(ctx, msg)
		if err != nil {
			continue
		}
		if resp != nil {
			_ = s.transport.Send(ctx, msg.SenderID, resp)
		}
	}
}
