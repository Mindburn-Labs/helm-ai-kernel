package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

type contextKey string

type authenticatedCredentialHashKey struct{}

const (
	principalKey contextKey = "principal"
)

// WithPrincipal attaches a Principal to the context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// WithAuthenticatedCredential records a one-way digest of a credential only
// after an authentication boundary has validated it. The raw credential never
// leaves the middleware and the private context key prevents request payloads
// from manufacturing equivalent evidence.
func WithAuthenticatedCredential(ctx context.Context, credential string) context.Context {
	if strings.TrimSpace(credential) == "" {
		return ctx
	}
	sum := sha256.Sum256([]byte(credential))
	return context.WithValue(ctx, authenticatedCredentialHashKey{}, hex.EncodeToString(sum[:]))
}

// AuthenticatedCredentialHash returns credential evidence installed by a
// successful authentication boundary.
func AuthenticatedCredentialHash(ctx context.Context) (string, bool) {
	hash, ok := ctx.Value(authenticatedCredentialHashKey{}).(string)
	hash = strings.TrimSpace(hash)
	return hash, ok && hash != ""
}

// GetPrincipal retrieves the Principal from the context.
func GetPrincipal(ctx context.Context) (Principal, error) {
	p, ok := ctx.Value(principalKey).(Principal)
	if !ok {
		return nil, errors.New("no principal in context")
	}
	return p, nil
}

// GetTenantID is a helper to get the TenantID from the context's Principal.
func GetTenantID(ctx context.Context) (string, error) {
	p, err := GetPrincipal(ctx)
	if err != nil {
		return "", err
	}
	return p.GetTenantID(), nil
}

// MustGetTenantID panics if tenant ID is missing (use only when middleware guarantees it).
func MustGetTenantID(ctx context.Context) string {
	tid, err := GetTenantID(ctx)
	if err != nil {
		panic(err)
	}
	return tid
}
