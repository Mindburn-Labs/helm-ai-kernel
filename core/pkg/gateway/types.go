// Package gateway defines the public auth contracts for the HELM MCP Gateway.
//
// The Gateway provides the canonical authentication and authorization surface
// for MCP (Model Context Protocol) connections. This OSS package defines the
// contract types for gateway authentication, session binding, and token exchange.
//
// The commercial HELM Platform provides the managed gateway with enterprise
// identity federation, SSO, and multi-tenant isolation.
package gateway

import (
	"context"
	"time"
)

// AuthMethod defines how a client authenticates to the gateway.
type AuthMethod string

const (
	AuthMethodAPIKey AuthMethod = "API_KEY"
	AuthMethodJWT    AuthMethod = "JWT"
	AuthMethodMTLS   AuthMethod = "MTLS"
	AuthMethodOIDC   AuthMethod = "OIDC"
)

// AuthRequest is the canonical gateway authentication input.
type AuthRequest struct {
	RequestID  string            `json:"request_id"`
	Method     AuthMethod        `json:"method"`
	Credential string            `json:"credential"`
	ClientID   string            `json:"client_id,omitempty"`
	Scopes     []string          `json:"scopes,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
}

// AuthResult is the gateway authentication outcome.
type AuthResult struct {
	RequestID     string    `json:"request_id"`
	Authenticated bool      `json:"authenticated"`
	PrincipalID   string    `json:"principal_id,omitempty"`
	SessionID     string    `json:"session_id,omitempty"`
	GrantedScopes []string  `json:"granted_scopes,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	ReasonCode    string    `json:"reason_code,omitempty"`
}

// SessionBinding ties a gateway session to a principal and scope.
type SessionBinding struct {
	SessionID   string    `json:"session_id"`
	PrincipalID string    `json:"principal_id"`
	ClientID    string    `json:"client_id"`
	Scopes      []string  `json:"scopes"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Revoked     bool      `json:"revoked"`
}

// Authenticator is the canonical gateway authentication interface.
type Authenticator interface {
	Authenticate(ctx context.Context, req *AuthRequest) (*AuthResult, error)
	ValidateSession(ctx context.Context, sessionID string) (*SessionBinding, error)
	RevokeSession(ctx context.Context, sessionID string) error
}

// RateLimitPolicy defines rate limiting for gateway connections.
type RateLimitPolicy struct {
	PolicyID  string        `json:"policy_id"`
	MaxRPM    int           `json:"max_rpm"` // Requests per minute
	MaxRPS    int           `json:"max_rps"` // Requests per second
	BurstSize int           `json:"burst_size"`
	ScopeType string        `json:"scope_type"` // "GLOBAL", "PER_PRINCIPAL", "PER_CLIENT"
	Window    time.Duration `json:"window"`
}
