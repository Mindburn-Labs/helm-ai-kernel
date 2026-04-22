package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeySet manages active signing keys and verification of past keys.
// Support key rotation without downtime.
type KeySet interface {
	// Sign creates a signed token with the current active key.
	Sign(ctx context.Context, claims jwt.Claims) (string, error)
	// KeyFunc returns the key for verification based on the token header.
	KeyFunc() jwt.Keyfunc
}

// InMemoryKeySet holds keys in memory. MVP implementation.
type InMemoryKeySet struct {
	mu         sync.RWMutex
	currentKID string
	keys       map[string]ed25519.PrivateKey
}

func NewInMemoryKeySet() (*InMemoryKeySet, error) {
	ks := &InMemoryKeySet{
		keys: make(map[string]ed25519.PrivateKey),
	}
	// Rotation: Generate initial key
	if err := ks.Rotate(); err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *InMemoryKeySet) Rotate() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Generate new Ed25519 key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	kid := fmt.Sprintf("key-%d", time.Now().UnixNano())
	ks.keys[kid] = privateKey
	ks.currentKID = kid

	// Ensure map doesn't grow indefinitely (simple eviction)
	if len(ks.keys) > 10 {
		// MVP: clear oldest keys. Real impl would use expiration.
		// For now simple map size limit
		for k := range ks.keys {
			if k != kid {
				delete(ks.keys, k)
				break // Evict one
			}
		}
	}
	return nil
}

func (ks *InMemoryKeySet) Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	ks.mu.RLock()
	key := ks.keys[ks.currentKID]
	kid := ks.currentKID
	ks.mu.RUnlock()

	if key == nil {
		return "", fmt.Errorf("no active key")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

func (ks *InMemoryKeySet) KeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in header")
		}

		ks.mu.RLock()
		defer ks.mu.RUnlock()
		key, exists := ks.keys[kid]
		if !exists {
			return nil, fmt.Errorf("key not found: %s", kid)
		}

		return key.Public(), nil
	}
}
