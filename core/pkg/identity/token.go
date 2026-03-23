package identity

import (
	"context"
	"time"

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
// TokenManager handles token generation and validation.
type TokenManager struct {
	keySet KeySet
}

func NewTokenManager(ks KeySet) *TokenManager {
	return &TokenManager{
		keySet: ks,
	}
}

// GenerateToken creates a signed JWT for a Principal.
func (tm *TokenManager) GenerateToken(p Principal, duration time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := IdentityClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        p.ID(), // JTI
			Subject:   p.ID(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			Issuer:    "helm.mindburn.run/identity",
			Audience:  jwt.ClaimStrings{"helm.internal"},
		},
		Type: p.Type(),
	}

	if agent, ok := p.(*AgentIdentity); ok {
		claims.DelegatorID = agent.DelegatorID
		claims.Scopes = agent.Scopes
	}

	// Use KeySet for signing (RSA)
	return tm.keySet.Sign(context.Background(), claims)
}

// ValidateToken parses and validates a JWT string.
func (tm *TokenManager) ValidateToken(tokenString string) (*IdentityClaims, error) {
	// Parse with KeyFunc from KeySet (handles kid lookup)
	token, err := jwt.ParseWithClaims(tokenString, &IdentityClaims{}, tm.keySet.KeyFunc())

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*IdentityClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrTokenSignatureInvalid
}
