package auth

import (
	"context"
	"errors"
)

type contextKey string

const (
	principalKey contextKey = "principal"
)

// WithPrincipal attaches a Principal to the context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
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
