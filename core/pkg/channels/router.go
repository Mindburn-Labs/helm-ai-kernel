package channels

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// SessionRoute describes the HELM session that an inbound envelope should be delivered to.
type SessionRoute struct {
	TenantID  string
	SessionID string
	Channel   ChannelKind
}

// Router maps inbound envelopes to HELM sessions, creating new sessions as required.
type Router interface {
	// Route resolves the SessionRoute for an inbound envelope.
	// Implementations may create a new session when no existing session matches.
	Route(ctx context.Context, env ChannelEnvelope) (*SessionRoute, error)
	// CreateSession creates a new session for the given tenant and channel,
	// returning the new session ID.
	CreateSession(ctx context.Context, tenantID string, channel ChannelKind) (string, error)
}

// sessionKey is the composite key used for session lookup.
type sessionKey struct {
	tenantID string
	senderID string
	channel  ChannelKind
}

// DefaultRouter routes inbound envelopes based on the tenant + sender + channel combination.
// It maintains an in-memory session map and creates new sessions on first contact.
// For production deployments the session map should be backed by a persistent store.
type DefaultRouter struct {
	mu       sync.RWMutex
	sessions map[sessionKey]string // sessionKey → sessionID
}

// NewRouter returns a DefaultRouter with an empty session map.
func NewRouter() *DefaultRouter {
	return &DefaultRouter{
		sessions: make(map[sessionKey]string),
	}
}

// Route resolves the SessionRoute for the given envelope.
// If no existing session matches the tenant+sender+channel combination a new session is created.
// The envelope must have a non-empty TenantID and SenderID.
func (r *DefaultRouter) Route(ctx context.Context, env ChannelEnvelope) (*SessionRoute, error) {
	if env.TenantID == "" {
		return nil, fmt.Errorf("channels/router: envelope has empty tenant_id")
	}
	if env.SenderID == "" {
		return nil, fmt.Errorf("channels/router: envelope has empty sender_id")
	}
	if !ValidChannelKind(env.Channel) {
		return nil, fmt.Errorf("channels/router: envelope has invalid channel %q", env.Channel)
	}

	key := sessionKey{
		tenantID: env.TenantID,
		senderID: env.SenderID,
		channel:  env.Channel,
	}

	// Fast path: existing session.
	r.mu.RLock()
	sessionID, ok := r.sessions[key]
	r.mu.RUnlock()

	if ok {
		return &SessionRoute{
			TenantID:  env.TenantID,
			SessionID: sessionID,
			Channel:   env.Channel,
		}, nil
	}

	// Slow path: create a new session under write lock.
	r.mu.Lock()
	defer r.mu.Unlock()

	// Re-check under write lock to avoid a race.
	if sessionID, ok = r.sessions[key]; ok {
		return &SessionRoute{
			TenantID:  env.TenantID,
			SessionID: sessionID,
			Channel:   env.Channel,
		}, nil
	}

	sessionID = uuid.NewString()
	r.sessions[key] = sessionID

	return &SessionRoute{
		TenantID:  env.TenantID,
		SessionID: sessionID,
		Channel:   env.Channel,
	}, nil
}

// CreateSession explicitly allocates a new session for the given tenant and channel.
// It returns an error when tenantID is empty or channel is invalid.
func (r *DefaultRouter) CreateSession(_ context.Context, tenantID string, channel ChannelKind) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("channels/router: tenantID must not be empty")
	}
	if !ValidChannelKind(channel) {
		return "", fmt.Errorf("channels/router: invalid channel %q", channel)
	}

	sessionID := uuid.NewString()

	// Store with a synthetic sender key so the session is addressable.
	key := sessionKey{
		tenantID: tenantID,
		senderID: "__explicit__" + sessionID,
		channel:  channel,
	}

	r.mu.Lock()
	r.sessions[key] = sessionID
	r.mu.Unlock()

	return sessionID, nil
}
