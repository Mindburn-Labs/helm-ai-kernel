// api.go provides HTTP handlers for real-time compliance scoring.
// These handlers expose the ComplianceScorer over REST for continuous
// auditing, SIEM integration, and dashboard consumption.
//
// Routes:
//
//	GET  /api/v1/compliance/status                    — All frameworks
//	GET  /api/v1/compliance/status?framework=hipaa    — Single framework
//	GET  /api/v1/compliance/health                    — Quick health check
//	POST /api/v1/compliance/event                     — Record compliance event
//
// Design invariants:
//   - All responses are JSON (application/json)
//   - Read endpoints are lock-free snapshots (no blocking)
//   - No authentication in this layer (delegate to gateway/middleware)
//   - Content-Type enforced on POST
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// APIHandler exposes compliance scoring over HTTP.
type APIHandler struct {
	scorer *ComplianceScorer
	clock  func() time.Time
}

// NewAPIHandler creates a new compliance API handler backed by the given scorer.
func NewAPIHandler(scorer *ComplianceScorer) *APIHandler {
	return &APIHandler{
		scorer: scorer,
		clock:  time.Now,
	}
}

// WithAPIClock overrides the clock for deterministic testing.
func (h *APIHandler) WithAPIClock(clock func() time.Time) *APIHandler {
	h.clock = clock
	return h
}

// RegisterRoutes registers compliance API routes on the given mux.
func (h *APIHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/compliance/status", h.handleStatus)
	mux.HandleFunc("/api/v1/compliance/health", h.handleHealth)
	mux.HandleFunc("/api/v1/compliance/event", h.handleRecordEvent)
}

// StatusResponse is the response for GET /api/v1/compliance/status.
type StatusResponse struct {
	Frameworks      map[string]*ComplianceScore `json:"frameworks"`
	OverallCompliant bool                       `json:"overall_compliant"`
	Threshold       int                         `json:"threshold"`
	Timestamp       time.Time                   `json:"timestamp"`
	ResponseHash    string                      `json:"response_hash"` // SHA-256 for audit trail
}

// HealthResponse is the response for GET /api/v1/compliance/health.
type HealthResponse struct {
	Status          string `json:"status"`           // "healthy", "degraded", "critical"
	FrameworkCount  int    `json:"framework_count"`
	LowestScore     int    `json:"lowest_score"`
	LowestFramework string `json:"lowest_framework"`
	Timestamp       time.Time `json:"timestamp"`
}

// EventRequest is the request body for POST /api/v1/compliance/event.
type EventRequest struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	Passed    bool   `json:"passed"`
	Reason    string `json:"reason,omitempty"`
}

// EventResponse is the response for POST /api/v1/compliance/event.
type EventResponse struct {
	Accepted  bool             `json:"accepted"`
	Score     *ComplianceScore `json:"score,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

func (h *APIHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	now := h.clock()
	threshold := 70 // Default compliance threshold

	// Check for framework filter.
	framework := r.URL.Query().Get("framework")

	var frameworks map[string]*ComplianceScore
	if framework != "" {
		score := h.scorer.GetScore(framework)
		if score == nil {
			writeError(w, http.StatusNotFound, fmt.Sprintf("framework %q not registered", framework))
			return
		}
		frameworks = map[string]*ComplianceScore{framework: score}
	} else {
		frameworks = h.scorer.GetAllScores()
	}

	resp := StatusResponse{
		Frameworks:       frameworks,
		OverallCompliant: h.scorer.IsCompliant(threshold),
		Threshold:        threshold,
		Timestamp:        now,
	}

	// Compute response hash for audit trail.
	data, _ := json.Marshal(resp)
	hash := sha256.Sum256(data)
	resp.ResponseHash = "sha256:" + hex.EncodeToString(hash[:])

	writeJSON(w, http.StatusOK, resp)
}

func (h *APIHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	scores := h.scorer.GetAllScores()
	now := h.clock()

	lowestScore := 100
	lowestFramework := ""
	for name, score := range scores {
		if score.Score < lowestScore {
			lowestScore = score.Score
			lowestFramework = name
		}
	}

	status := "healthy"
	if lowestScore < 70 {
		status = "degraded"
	}
	if lowestScore < 40 {
		status = "critical"
	}
	if len(scores) == 0 {
		status = "healthy"
		lowestScore = 100
	}

	resp := HealthResponse{
		Status:          status,
		FrameworkCount:  len(scores),
		LowestScore:     lowestScore,
		LowestFramework: lowestFramework,
		Timestamp:       now,
	}

	statusCode := http.StatusOK
	if status == "critical" {
		statusCode = http.StatusServiceUnavailable
	}

	writeJSON(w, statusCode, resp)
}

func (h *APIHandler) handleRecordEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	var req EventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.Framework == "" {
		writeError(w, http.StatusBadRequest, "framework is required")
		return
	}
	if req.ControlID == "" {
		writeError(w, http.StatusBadRequest, "control_id is required")
		return
	}

	now := h.clock()
	h.scorer.RecordEvent(ComplianceEvent{
		Framework: req.Framework,
		ControlID: req.ControlID,
		Passed:    req.Passed,
		Reason:    req.Reason,
		Timestamp: now,
	})

	score := h.scorer.GetScore(req.Framework)

	writeJSON(w, http.StatusOK, EventResponse{
		Accepted:  true,
		Score:     score,
		Timestamp: now,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
