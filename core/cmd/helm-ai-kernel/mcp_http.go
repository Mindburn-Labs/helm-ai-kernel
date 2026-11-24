package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/a2a"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

func newLocalMCPHTTPServerWithDataDir(port int, authMode, dataDir string) (*http.Server, error) {
	return newLocalMCPHTTPServerWithDataDirAndPolicy(port, authMode, dataDir, nil)
}

func newLocalMCPHTTPServerWithDataDirAndPolicy(port int, authMode, dataDir string, policyGraph *prg.Graph) (*http.Server, error) {
	// SEC: Default to localhost to prevent accidental network exposure. The
	// MCP server reads its own bind variable, and `--auth none` is refused off
	// loopback (audit S-02).
	mcpBind := listenerBindAddr(mcpBindAddrEnv)
	if err := requireListenerAuth("mcp serve", mcpBind, authMode != "none", "use --auth static-header or --auth oauth"); err != nil {
		return nil, err
	}
	baseURL := fmt.Sprintf("http://%s:%d", mcpBind, port)
	catalog, executor, err := newLocalMCPRuntimeWithDataDirAndPolicy(dataDir, policyGraph)
	if err != nil {
		return nil, err
	}
	gateway := mcppkg.NewGateway(catalog, mcppkg.GatewayConfig{
		BaseURL:  baseURL,
		AuthMode: authMode,
	}, mcppkg.WithGovernedExecutor(executor))

	mux := newListenerRouteMux(listenerMCP)
	registerLocalMCPRoutes(mux, gateway, baseURL)

	handler, err := wrapMCPAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}), authMode, baseURL)
	if err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:              fmt.Sprintf("%s:%d", mcpBind, port),
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}, nil
}

// registerLocalMCPRoutes mounts the mcp serve listener's routes. The gateway
// registers on its own mux, so the listener forwards the gateway paths it
// declares; a path the gateway adds is not served until it is declared here.
func registerLocalMCPRoutes(mux routeMux, gateway *mcppkg.Gateway, baseURL string) {
	gatewayMux := http.NewServeMux()
	gateway.RegisterRoutes(gatewayMux)
	for _, route := range []string{"/mcp", "/mcp/v1/capabilities", "/mcp/v1/execute", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		mux.Handle(route, gatewayMux)
	}

	// A2A agent card discovery (/.well-known/agent-card.json)
	a2a.RegisterWellKnownRoute(mux, a2a.NewKernelCardProvider(a2a.KernelCardConfig{
		EndpointURL: baseURL,
	}))

	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "ok",
			"transport": "http",
		})
	}
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)
}

func wrapMCPAuth(next http.Handler, authMode, baseURL string) (http.Handler, error) {
	switch authMode {
	case "none":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := withMCPTransportIdentity(r.Context(), "mcp-local", "mcp-local:"+baseURL)
			next.ServeHTTP(w, r.WithContext(ctx))
		}), nil
	case "static-header":
		expectedKey := mindburnAPIKeyFromEnv(os.Getenv, os.Stderr)
		if expectedKey == "" {
			return nil, fmt.Errorf("MINDBURN_HELM_API_KEY must be set when --auth static-header is used (HELM_API_KEY is a deprecated fallback)")
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provided := r.Header.Get("X-HELM-API-Key")
			if provided == "" && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				provided = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}
			if !secretEqual(provided, expectedKey) {
				http.Error(w, "missing or invalid MCP API key", http.StatusUnauthorized)
				return
			}
			ctx := withMCPTransportIdentity(r.Context(), "mcp-static", provided)
			next.ServeHTTP(w, r.WithContext(ctx))
		}), nil
	case "oauth":
		jwksURL := os.Getenv("HELM_OAUTH_JWKS_URL")
		metadataURL := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-protected-resource/mcp"
		resource := strings.TrimSpace(os.Getenv("HELM_OAUTH_RESOURCE"))
		if resource == "" {
			resource = strings.TrimRight(baseURL, "/") + "/mcp"
		}

		if jwksURL != "" {
			// Production JWKS/OIDC validation.
			issuer := os.Getenv("HELM_OAUTH_ISSUER")
			audience := os.Getenv("HELM_OAUTH_AUDIENCE")
			if issuer == "" || audience == "" {
				return nil, fmt.Errorf("HELM_OAUTH_ISSUER and HELM_OAUTH_AUDIENCE must be set when HELM_OAUTH_JWKS_URL is configured")
			}
			scopes := parseMCPEnvList(os.Getenv("HELM_OAUTH_SCOPES"))

			validator := mcppkg.NewJWKSValidator(mcppkg.JWKSConfig{
				JWKSURL:  jwksURL,
				Issuer:   issuer,
				Audience: audience,
				Resource: resource,
				Scopes:   scopes,
			})

			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
					next.ServeHTTP(w, r)
					return
				}
				authz := r.Header.Get("Authorization")
				if !strings.HasPrefix(authz, "Bearer ") {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="helm-mcp", resource_metadata="%s", resource="%s"`, metadataURL, resource))
					http.Error(w, "missing bearer token", http.StatusUnauthorized)
					return
				}
				tokenStr := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
				claims, err := validator.ValidateAuthorization(tokenStr)
				if err != nil {
					challenge := fmt.Sprintf(`Bearer realm="helm-mcp", resource_metadata="%s", resource="%s"`, metadataURL, resource)
					if validErr, ok := err.(*mcppkg.JWKSValidationError); ok && validErr.Kind == mcppkg.JWKSErrMissingScope {
						challenge += fmt.Sprintf(`, error="insufficient_scope", error_description="%s"`, validErr.Message)
					}
					w.Header().Set("WWW-Authenticate", challenge)
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}
				principalID := strings.TrimSpace(claims.RegisteredClaims.Subject)
				if principalID == "" {
					http.Error(w, "OAuth token subject is required", http.StatusUnauthorized)
					return
				}
				ctx := withMCPTransportIdentity(r.Context(), principalID, tokenStr)
				ctx = mcppkg.WithOAuthAuthorization(ctx, mcppkg.OAuthAuthorization{
					Scopes:    claims.Scopes,
					Resources: claims.Resources,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
			}), nil
		}

		// Dev-only fallback: simple bearer token comparison.
		expectedToken := os.Getenv("HELM_OAUTH_BEARER_TOKEN")
		if expectedToken == "" {
			return nil, fmt.Errorf("either HELM_OAUTH_JWKS_URL (production) or HELM_OAUTH_BEARER_TOKEN (dev fallback) must be set when --auth oauth is used")
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
				next.ServeHTTP(w, r)
				return
			}
			authz := r.Header.Get("Authorization")
			provided := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
			if !strings.HasPrefix(authz, "Bearer ") || !secretEqual(provided, expectedToken) {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="helm-mcp", resource_metadata="%s", resource="%s"`, metadataURL, resource))
				http.Error(w, "missing or invalid OAuth bearer token", http.StatusUnauthorized)
				return
			}
			ctx := withMCPTransportIdentity(r.Context(), "mcp-oauth-dev", provided)
			ctx = mcppkg.WithOAuthAuthorization(ctx, mcppkg.OAuthAuthorization{
				Scopes:    parseMCPEnvList(os.Getenv("HELM_OAUTH_SCOPES")),
				Resources: []string{resource},
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		}), nil
	default:
		return nil, fmt.Errorf("unknown auth mode %q", authMode)
	}
}

func withMCPTransportIdentity(ctx context.Context, principalID, credential string) context.Context {
	ctx = helmauth.WithPrincipal(ctx, &helmauth.BasePrincipal{
		ID:       principalID,
		TenantID: helmauth.SystemTenantID,
		Roles:    []string{"service"},
	})
	return helmauth.WithAuthenticatedCredential(ctx, credential)
}

func parseMCPEnvList(raw string) []string {
	var values []string
	for _, value := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}
