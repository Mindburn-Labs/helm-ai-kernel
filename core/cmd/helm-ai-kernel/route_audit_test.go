package main

// F-11 regression: every route registered in subsystems.go must either be an
// explicitly declared public endpoint or be wrapped in an auth guard.
//
// Twelve handlers had slipped the gate — including POST /api/v1/memory/promote
// (unauthenticated mutation of governed memory), GET /api/v1/memory/list (raw
// namespace from the query string with no tenant scoping), the economic ledger
// endpoints, and GET /api/v1/boundary/check (an egress-policy oracle). None of
// them appeared in the route contract registry either, so they were both
// unauthenticated and undocumented.
//
// Wrapping those twelve was the fix; this test is what stops the thirteenth.
// It reads the source rather than the mux because net/http exposes no way to
// enumerate registered patterns together with their handler chain.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// publicRoutes are endpoints that are unauthenticated by design. Adding to this
// list is the deliberate, reviewable act of publishing an endpoint.
var publicRoutes = map[string]string{
	"/api/v1/version": "build identity, no tenant data",
	"/version":        "build identity, no tenant data",
	"/healthz":        "liveness probe",
}

var handleFuncRe = regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"\s*,\s*(.*)`)

// scanRoutes returns the routes that are neither auth-wrapped nor declared
// public, plus the total number of registrations seen.
func scanRoutes(src string) (unguarded []string, seen int) {
	for _, line := range strings.Split(src, "\n") {
		m := handleFuncRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		seen++
		route, rest := m[1], m[2]

		if _, ok := publicRoutes[route]; ok {
			continue
		}
		// Recognised guards. protectRuntimeHandler covers admin/service/tenant;
		// auth.RequireAdminAuth is the older mux.Handle form.
		if strings.Contains(rest, "protectRuntimeHandler(") ||
			strings.Contains(rest, "RequireAdminAuth(") ||
			strings.Contains(rest, "RequireServiceAuth(") {
			continue
		}
		unguarded = append(unguarded, route)
	}
	return unguarded, seen
}

// TestScanRoutesDetectsAnUnguardedRoute is the negative control. Without it,
// TestSubsystemRoutes... passing proves only that the scan found nothing —
// which is also what a broken scan returns.
func TestScanRoutesDetectsAnUnguardedRoute(t *testing.T) {
	const src = `
	mux.HandleFunc("/api/v1/guarded", protectRuntimeHandler(RouteAuthAdmin, func(w http.ResponseWriter, r *http.Request) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
	mux.HandleFunc("/api/v1/leaked", func(w http.ResponseWriter, r *http.Request) {
`
	unguarded, seen := scanRoutes(src)
	if seen != 3 {
		t.Fatalf("saw %d registrations, want 3 — the pattern no longer matches real code", seen)
	}
	if len(unguarded) != 1 || unguarded[0] != "/api/v1/leaked" {
		t.Fatalf("unguarded = %v, want exactly [/api/v1/leaked]: the scan does not detect "+
			"an unwrapped handler, so the guard test would pass vacuously", unguarded)
	}
}

func TestSubsystemRoutesAreAuthenticatedOrExplicitlyPublic(t *testing.T) {
	data, err := os.ReadFile("subsystems.go")
	if err != nil {
		t.Fatalf("read subsystems.go: %v", err)
	}

	unguarded, seen := scanRoutes(string(data))

	if seen == 0 {
		t.Fatal("no mux.HandleFunc registrations found — this test has stopped checking anything")
	}

	if len(unguarded) > 0 {
		t.Fatalf("these routes are neither auth-wrapped nor declared public: %v\n\n"+
			"Wrap the handler in protectRuntimeHandler(RouteAuthAdmin, ...), or — if the "+
			"endpoint really must be reachable without credentials — add it to publicRoutes "+
			"with the reason. Note that HELM_BIND_ADDR=0.0.0.0 makes these internet-facing.",
			unguarded)
	}
}

// The allowlist must stay small and deliberate. If it grows, someone should
// have to justify it in review rather than append quietly.
func TestPublicRouteAllowlistStaysMinimal(t *testing.T) {
	const maxPublic = 6
	if len(publicRoutes) > maxPublic {
		t.Fatalf("publicRoutes has %d entries (limit %d): every unauthenticated endpoint is "+
			"attack surface on a 0.0.0.0 deployment", len(publicRoutes), maxPublic)
	}
	for route, reason := range publicRoutes {
		if strings.TrimSpace(reason) == "" {
			t.Fatalf("public route %q has no stated reason", route)
		}
	}
}
