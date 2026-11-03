package api_test

import (
	"net/http"
)

func allowAutonomyAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// ──────────────────────────────────────────────────────────────
// Autonomy Handler tests
// ──────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────
// Decision Handler tests
// ──────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────
// Control Endpoint tests (D3)
// ──────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────
// D3: Empty title rejection (Untitled gating)
// ──────────────────────────────────────────────────────────────
