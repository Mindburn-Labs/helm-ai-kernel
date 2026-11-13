package main

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
)

// Sidecar listeners (`proxy`, `mcp serve --transport http`) each read their
// own bind variable. HELM_BIND_ADDR belongs to `serve`; a sidecar that
// inherited it was exposed, unauthenticated, whenever the API server was
// (audit S-01, S-02).
const (
	proxyBindAddrEnv = "HELM_PROXY_BIND_ADDR"
	mcpBindAddrEnv   = "HELM_MCP_BIND_ADDR"
	sharedBindEnv    = "HELM_BIND_ADDR"
)

// listenerBindAddr resolves a sidecar's bind address from its own variable,
// defaulting to loopback.
func listenerBindAddr(envName string) string {
	if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
		return value
	}
	return "127.0.0.1"
}

// noteIgnoredSharedBind tells an operator who still sets HELM_BIND_ADDR for a
// sidecar that it no longer applies there.
func noteIgnoredSharedBind(w io.Writer, server, envName string) {
	if os.Getenv(sharedBindEnv) != "" && os.Getenv(envName) == "" {
		_, _ = fmt.Fprintf(w, "Note: %s applies to `serve` only; %s binds 127.0.0.1 unless %s is set\n", sharedBindEnv, server, envName)
	}
}

// isLoopbackBindAddr reports whether a listen host accepts loopback
// connections only. An empty host or a wildcard listens on every interface.
func isLoopbackBindAddr(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requireListenerAuth refuses to expose an unauthenticated listener beyond
// loopback. remedy names the setting that turns authentication on.
func requireListenerAuth(server, bindAddr string, authenticated bool, remedy string) error {
	if authenticated || isLoopbackBindAddr(bindAddr) {
		return nil
	}
	return fmt.Errorf("%s bind address %q is not loopback and no authentication is configured; %s", server, bindAddr, remedy)
}

// secretEqual compares a presented credential with the configured one in
// constant time, so response timing does not reveal a matching prefix.
func secretEqual(provided, expected string) bool {
	return expected != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// bearerToken returns the token of an `Authorization: Bearer` header.
func bearerToken(r *http.Request) (string, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return strings.TrimSpace(token), ok
}

// proxyTokenEnv names the token callers of `helm-ai-kernel proxy` present as
// their bearer credential, e.g. OPENAI_API_KEY=<token> in an OpenAI SDK.
const proxyTokenEnv = "HELM_PROXY_TOKEN"

// wrapProxyAuth requires the proxy token on every route except health: the
// proxy forwards the operator's --api-key and serves the receipt log and the
// ProofGraph. The token is removed before forwarding, so the upstream sees only
// --api-key, and its digest becomes the request's transport credential. An
// empty token leaves the handler unwrapped; runProxyCmd allows that on
// loopback only.
func wrapProxyAuth(next http.Handler, token string) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		provided, ok := bearerToken(r)
		if !ok || !secretEqual(provided, token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="helm-proxy"`)
			httperr.WriteError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "missing or invalid HELM proxy token")
			return
		}
		r.Header.Del("Authorization")
		next.ServeHTTP(w, r.WithContext(helmauth.WithAuthenticatedCredential(r.Context(), provided)))
	})
}

// metricsBearerTokenEnv names the token a remote scraper presents for /metrics.
const metricsBearerTokenEnv = "HELM_METRICS_BEARER_TOKEN"

// protectedMetricsHandler is the /metrics handler the server mounts. The
// health and metrics listeners share the API bind address, so without a token
// /metrics answers loopback peers only; with HELM_METRICS_BEARER_TOKEN set,
// every scrape must present it (audit S-07).
func protectedMetricsHandler(services *Services, token string) http.HandlerFunc {
	next := metricsHandler(services)
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			if !requestFromLoopback(r) {
				httperr.WriteError(w, http.StatusForbidden, http.StatusText(http.StatusForbidden), "metrics are served to loopback clients only; set "+metricsBearerTokenEnv+" to scrape remotely")
				return
			}
			next(w, r)
			return
		}
		if provided, ok := bearerToken(r); !ok || !secretEqual(provided, token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="helm-metrics"`)
			httperr.WriteError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "missing or invalid metrics bearer token")
			return
		}
		next(w, r)
	}
}
