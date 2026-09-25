package main

import (
	"fmt"
	"net/http"
	"strings"
)

// routeMux is what the API route registrars need from a mux. The API listener
// passes a *runtimeRouteMux; tests that exercise one handler in isolation may
// still pass a plain *http.ServeMux.
type routeMux interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// runtimeRouteMux is the API listener's mux. It refuses to mount a pattern that
// RuntimeRouteSpecs() does not declare, so every served route has a declared
// auth tier, rate class and contract status, and the registry is the complete
// list of what the listener serves (H22). The refusal is a panic at startup:
// an undeclared route is a build defect, and serving it is worse than not
// starting.
//
// A mux made by newListenerRouteMux checks one of the binary's other listeners
// against ListenerRouteSpecs() in the same way.
type runtimeRouteMux struct {
	mux      *http.ServeMux
	listener string // empty for the API listener
	mounted  []string
}

func newRuntimeRouteMux() *runtimeRouteMux {
	return &runtimeRouteMux{mux: http.NewServeMux()}
}

func newListenerRouteMux(listener string) *runtimeRouteMux {
	return &runtimeRouteMux{mux: http.NewServeMux(), listener: listener}
}

func (m *runtimeRouteMux) Handle(pattern string, handler http.Handler) {
	m.declare(pattern)
	m.mux.Handle(pattern, handler)
}

func (m *runtimeRouteMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.declare(pattern)
	m.mux.HandleFunc(pattern, handler)
}

func (m *runtimeRouteMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mux.ServeHTTP(w, r)
}

// Handler reports the handler and pattern the listener would use for r.
func (m *runtimeRouteMux) Handler(r *http.Request) (http.Handler, string) {
	return m.mux.Handler(r)
}

// Mounted returns the patterns registered so far, in registration order.
func (m *runtimeRouteMux) Mounted() []string {
	return append([]string(nil), m.mounted...)
}

func (m *runtimeRouteMux) declare(pattern string) {
	if m.listener != "" {
		if !listenerRouteDeclared(m.listener, pattern) {
			panic(fmt.Sprintf("%s listener route %q is not declared in ListenerRouteSpecs(); declare its auth tier and scope before mounting it", m.listener, pattern))
		}
	} else if len(declaredRouteSpecs(pattern)) == 0 {
		panic(fmt.Sprintf("route %q is not declared in RuntimeRouteSpecs(); declare its auth tier, rate class and contract status before mounting it", pattern))
	}
	m.mounted = append(m.mounted, pattern)
}

func listenerRouteDeclared(listener, pattern string) bool {
	for _, spec := range ListenerRouteSpecs() {
		if spec.Listener == listener && spec.MuxPattern == pattern {
			return true
		}
	}
	return false
}

// declaredRouteSpecs returns the registry entries a mux pattern serves. A
// method-qualified pattern ("GET /path") matches that method only; a bare
// pattern matches every entry with the same MuxPattern.
func declaredRouteSpecs(pattern string) []RuntimeRouteSpec {
	method, path := "", pattern
	if before, after, ok := strings.Cut(pattern, " "); ok {
		method, path = before, strings.TrimSpace(after)
	}
	var specs []RuntimeRouteSpec
	for _, spec := range RuntimeRouteSpecs() {
		if spec.MuxPattern == path && (method == "" || spec.Method == method) {
			specs = append(specs, spec)
		}
	}
	return specs
}

// registerRuntimeAPIRoutes mounts the routes the API listener serves once
// services are up. main and the route-guard tests share it, so the tests probe
// the production composition rather than a copy of it.
func registerRuntimeAPIRoutes(mux routeMux, services *Services, opts serverOptions) {
	RegisterSubsystemRoutes(mux, services)
	RegisterConsoleRoutes(mux, services, opts)
	RegisterLocalFirstRunRoutes(mux, services, opts)
	RegisterPrincipalBindingRoutes(mux, services, opts)
}

// registerHealthRoutes mounts the health listener's routes, and /metrics when
// the metrics listener shares its port (metrics is nil otherwise).
func registerHealthRoutes(mux routeMux, metrics http.HandlerFunc) {
	health := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/healthz", health)
	if metrics != nil {
		mux.HandleFunc("/metrics", metrics)
	}
}

// registerMetricsRoutes mounts the metrics listener's routes.
func registerMetricsRoutes(mux routeMux, metrics http.HandlerFunc) {
	mux.HandleFunc("/metrics", metrics)
}
