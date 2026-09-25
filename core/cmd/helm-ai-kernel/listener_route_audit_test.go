package main

// C-03 / HELM-747: every route the binary serves is declared. The API listener
// is TestRuntimeRouteCatalogEqualsRegistry's; these tests cover the binary's
// other listeners: the server's health and metrics listeners and the mcp serve,
// proxy and spend-proxy subcommands. Each walks the production registrar on the
// checked mux, so a route cannot escape by living in another file or taking
// its path from a constant.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/spendproxy"
)

// listenerRouteMuxes mounts every listener's production routes, under each
// configuration that changes what the listener mounts.
func listenerRouteMuxes() []*runtimeRouteMux {
	ok := func(http.ResponseWriter, *http.Request) {}

	healthWithMetrics := newListenerRouteMux(listenerHealth)
	registerHealthRoutes(healthWithMetrics, ok)
	healthOnly := newListenerRouteMux(listenerHealth)
	registerHealthRoutes(healthOnly, nil)
	metrics := newListenerRouteMux(listenerMetrics)
	registerMetricsRoutes(metrics, ok)

	mcp := newListenerRouteMux(listenerMCP)
	registerLocalMCPRoutes(mcp, mcppkg.NewGateway(mcppkg.NewToolCatalog(), mcppkg.GatewayConfig{}), "http://127.0.0.1:9100")

	proxy := newListenerRouteMux(listenerProxy)
	registerProxyRoutes(proxy, &proxyRuntime{handler: http.NotFoundHandler()})

	spend := newListenerRouteMux(listenerSpendProxy)
	(&spendproxy.Server{}).RegisterRoutes(spend)

	return []*runtimeRouteMux{healthWithMetrics, healthOnly, metrics, mcp, proxy, spend}
}

// mountListenerRoutes reports the checked mux's refusal of an undeclared route
// as a test failure rather than a panic that ends the test binary.
func mountListenerRoutes(t *testing.T) (muxes []*runtimeRouteMux) {
	t.Helper()
	defer func() {
		if refused := recover(); refused != nil {
			t.Fatalf("mounting the listeners' routes: %v", refused)
		}
	}()
	return listenerRouteMuxes()
}

func TestListenerRouteCatalogsEqualRegistry(t *testing.T) {
	mounted := map[string]bool{}
	for _, mux := range mountListenerRoutes(t) {
		for _, pattern := range mux.Mounted() {
			mounted[mux.listener+" "+pattern] = true
		}
	}

	declared := map[string]bool{}
	for _, spec := range ListenerRouteSpecs() {
		key := spec.Listener + " " + spec.MuxPattern
		if declared[key] {
			t.Errorf("duplicate listener route %s", key)
		}
		declared[key] = true
		if !mounted[key] {
			t.Errorf("the %s listener declares %q but does not mount it", spec.Listener, spec.MuxPattern)
		}
		switch spec.Auth {
		case RouteAuthPublic, RouteAuthMetricsToken, RouteAuthListenerCredential:
		default:
			t.Errorf("the %s listener's %q declares auth %q, which no listener enforces", spec.Listener, spec.MuxPattern, spec.Auth)
		}
		if strings.TrimSpace(spec.Scope) == "" {
			t.Errorf("the %s listener's %q declares no scope", spec.Listener, spec.MuxPattern)
		}
	}
	// The mux already panics on an undeclared pattern; checking again means a
	// weakened mux fails here instead of passing silently.
	for key := range mounted {
		if !declared[key] {
			t.Errorf("%s is mounted but not declared in ListenerRouteSpecs()", key)
		}
	}
}

// TestListenerRoutesRefuseCallersWithoutTheirDeclaredCredential sends a
// credential-free request from a non-loopback peer to every non-public
// listener route, on the listener's handler with its credential configured.
func TestListenerRoutesRefuseCallersWithoutTheirDeclaredCredential(t *testing.T) {
	t.Setenv("HELM_API_KEY", "probe-mcp-key")
	mcpServer, err := newLocalMCPHTTPServerWithDataDir(9100, "static-header", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	health := newListenerRouteMux(listenerHealth)
	registerHealthRoutes(health, protectedMetricsHandler(nil, ""))
	metrics := newListenerRouteMux(listenerMetrics)
	registerMetricsRoutes(metrics, protectedMetricsHandler(nil, "probe-metrics-token"))
	proxy := newListenerRouteMux(listenerProxy)
	registerProxyRoutes(proxy, &proxyRuntime{handler: http.NotFoundHandler()})
	handlers := map[string]http.Handler{
		listenerHealth:  health,
		listenerMetrics: metrics,
		listenerMCP:     mcpServer.Handler,
		listenerProxy:   wrapProxyAuth(proxy, "probe-proxy-token"),
	}

	for _, spec := range ListenerRouteSpecs() {
		if spec.Auth == RouteAuthPublic {
			continue
		}
		handler, ok := handlers[spec.Listener]
		if !ok {
			t.Errorf("the %s listener's %q is not public and has no probe", spec.Listener, spec.MuxPattern)
			continue
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, spec.MuxPattern, nil))
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Errorf("the %s listener's %q (%s) answered %d to a caller without a credential", spec.Listener, spec.MuxPattern, spec.Auth, rec.Code)
		}
	}
}

// TestNoServeMuxEscapesTheRegistry: the walks enumerate the listeners they
// know. A listener built on a bare http.ServeMux, or a route on
// http.DefaultServeMux, would escape them, so neither may appear in this
// package outside the functions that build a checked mux or an inner mux the
// checked mux forwards declared paths to.
func TestNoServeMuxEscapesTheRegistry(t *testing.T) {
	allowed := map[string]bool{
		"newRuntimeRouteMux":        true,
		"newListenerRouteMux":       true,
		"registerDeployedMCPRoutes": true,
		"registerLocalMCPRoutes":    true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, decl := range parsed.Decls {
			owner := ""
			if fn, ok := decl.(*ast.FuncDecl); ok {
				owner = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "http" {
					return true
				}
				switch sel.Sel.Name {
				case "NewServeMux", "Handle", "HandleFunc":
					if !allowed[owner] {
						t.Errorf("%s: http.%s in %q escapes the route registry; mount routes on newRuntimeRouteMux or newListenerRouteMux", fset.Position(call.Pos()), sel.Sel.Name, owner)
					}
				}
				return true
			})
		}
	}
	if checked < 100 {
		t.Fatalf("parsed only %d source files: the scan is not reading this package", checked)
	}
}
