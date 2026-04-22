// Package api provides HTTP handlers for the research runtime, mounted at
// /api/research/* within the HELM API server.
package api

import (
	"encoding/json"
	"net/http"
)

// writeJSON serialises v as JSON, sets Content-Type, and writes the given
// HTTP status code.  Encoding errors are silently swallowed — the response has
// already been started at that point.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON object {"error": msg} with the given status.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
