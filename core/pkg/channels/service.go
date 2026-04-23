package channels

import (
	"context"
	"fmt"
	"sync"
)

// OutboundMessage is the normalised representation of a message to be sent via a channel adapter.
type OutboundMessage struct {
	// Text is the plain-text body of the outbound message.
	Text string `json:"text"`
	// ThreadID is the optional platform-native thread or conversation identifier.
	// When non-empty the adapter must deliver the message into that thread.
	ThreadID string `json:"thread_id,omitempty"`
	// Attachments holds artifact IDs to include in the outbound message.
	Attachments []string `json:"attachments,omitempty"`
	// RequireAck indicates that the caller requires a delivery acknowledgement.
	RequireAck bool `json:"require_ack"`
}

// Adapter is the interface that every channel integration must implement.
// Adapters handle both inbound normalisation and outbound delivery for a single platform.
type Adapter interface {
	// Kind returns the ChannelKind this adapter handles.
	Kind() ChannelKind
	// NormalizeInbound parses a raw inbound wire payload and returns a ChannelEnvelope.
	// The returned envelope must satisfy ValidateEnvelope.
	NormalizeInbound(ctx context.Context, raw []byte) (ChannelEnvelope, error)
	// Send delivers an outbound message to the given tenant session.
	Send(ctx context.Context, tenantID string, sessionID string, body OutboundMessage) error
	// Health returns nil when the adapter's downstream dependencies are reachable.
	Health(ctx context.Context) error
}

// AdapterRegistry is a thread-safe registry of channel adapters keyed by ChannelKind.
// Each ChannelKind may have at most one registered adapter.
type AdapterRegistry struct {
	mu       sync.RWMutex
	adapters map[ChannelKind]Adapter
}

// NewAdapterRegistry returns an empty AdapterRegistry.
func NewAdapterRegistry() *AdapterRegistry {
	return &AdapterRegistry{
		adapters: make(map[ChannelKind]Adapter),
	}
}

// Register adds an adapter to the registry.
// It returns an error if an adapter for the same ChannelKind is already registered,
// or if the adapter is nil.
func (r *AdapterRegistry) Register(adapter Adapter) error {
	if adapter == nil {
		return fmt.Errorf("channels: cannot register nil adapter")
	}
	kind := adapter.Kind()
	if !ValidChannelKind(kind) {
		return fmt.Errorf("channels: adapter has invalid kind %q", kind)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.adapters[kind]; exists {
		return fmt.Errorf("channels: adapter for kind %q is already registered", kind)
	}
	r.adapters[kind] = adapter
	return nil
}

// Get returns the adapter registered for the given ChannelKind.
// It returns an error when no adapter is registered for that kind.
func (r *AdapterRegistry) Get(kind ChannelKind) (Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	a, ok := r.adapters[kind]
	if !ok {
		return nil, fmt.Errorf("channels: no adapter registered for kind %q", kind)
	}
	return a, nil
}

// List returns the ChannelKinds of all registered adapters in undefined order.
func (r *AdapterRegistry) List() []ChannelKind {
	r.mu.RLock()
	defer r.mu.RUnlock()

	kinds := make([]ChannelKind, 0, len(r.adapters))
	for k := range r.adapters {
		kinds = append(kinds, k)
	}
	return kinds
}
