package mcp

import "context"

type oauthAuthorizationKey struct{}

// OAuthAuthorization captures validated OAuth token metadata relevant to MCP policy.
type OAuthAuthorization struct {
	Scopes    []string
	Resources []string
}

// WithOAuthAuthorization attaches validated OAuth authorization metadata to ctx.
func WithOAuthAuthorization(ctx context.Context, auth OAuthAuthorization) context.Context {
	return context.WithValue(ctx, oauthAuthorizationKey{}, auth)
}

// OAuthAuthorizationFromContext returns OAuth metadata previously attached to ctx.
func OAuthAuthorizationFromContext(ctx context.Context) (OAuthAuthorization, bool) {
	auth, ok := ctx.Value(oauthAuthorizationKey{}).(OAuthAuthorization)
	return auth, ok
}

func hasAllOAuthScopes(ctx context.Context, required []string) bool {
	if len(required) == 0 {
		return true
	}
	auth, ok := OAuthAuthorizationFromContext(ctx)
	if !ok {
		return false
	}
	present := make(map[string]struct{}, len(auth.Scopes))
	for _, scope := range auth.Scopes {
		present[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := present[scope]; !ok {
			return false
		}
	}
	return true
}
