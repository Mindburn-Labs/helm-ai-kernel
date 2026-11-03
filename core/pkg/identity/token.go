package identity

import (
	"github.com/golang-jwt/jwt/v5"
)

// IdentityClaims extends standard JWT claims with HELM specific fields.
// Fields must align with auth.HelmClaims so tokens are consumable by auth middleware.
type IdentityClaims struct {
	jwt.RegisteredClaims
	Type        PrincipalType `json:"type"`
	TenantID    string        `json:"tenant_id,omitempty"`
	Roles       []string      `json:"roles,omitempty"`
	DelegatorID string        `json:"delegator_id,omitempty"` // For agents
	Scopes      []string      `json:"scopes,omitempty"`
}

// TokenManager handles token generation and validation.
type TokenManager struct {
	keySet KeySet
}
