// Package trust provides HTTP API handlers for the Trust Registry.
// These handlers expose the trust registry as a queryable substrate via REST.
package trust

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust/registry"
)

// Handler provides Trust Registry HTTP endpoints.
type Handler struct {
	registry *registry.Registry
	logger   *slog.Logger
}

// NewHandler creates a new trust API handler.
func NewHandler(reg *registry.Registry, logger *slog.Logger) *Handler {
	return &Handler{
		registry: reg,
		logger:   logger,
	}
}

// RegisterRoutes registers trust API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/trust/snapshot", h.HandleGetSnapshot)
	mux.HandleFunc("POST /v1/trust/events", h.HandlePostEvent)
	mux.HandleFunc("GET /v1/trust/state", h.HandleGetState)
	mux.HandleFunc("GET /v1/trust/events", h.HandleListEvents)
}

// HandleGetSnapshot returns a trust snapshot at the specified lamport height.
// GET /v1/trust/snapshot?lamport=L
func (h *Handler) HandleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	lamportStr := r.URL.Query().Get("lamport")

	var snapshot *registry.TrustSnapshot
	var err error

	if lamportStr == "" || lamportStr == "current" {
		// Return current state snapshot
		snapshot, err = registry.SnapshotFromRegistry(h.registry)
	} else {
		lamport, parseErr := strconv.ParseUint(lamportStr, 10, 64)
		if parseErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid lamport parameter"})
			return
		}
		// For historical snapshots, we need the store — use current state if lamport >= current
		if lamport >= h.registry.CurrentLamport() {
			snapshot, err = registry.SnapshotFromRegistry(h.registry)
		} else {
			// Historical snapshot: fetch events up to the requested lamport and reduce
			events, listErr := h.registry.ListEventsUpTo(r.Context(), lamport)
			if listErr != nil {
				h.logger.Error("failed to list events for historical snapshot", "error", listErr, "lamport", lamport)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load events"})
				return
			}
			historicalState := registry.NewTrustState()
			if reduceErr := historicalState.Reduce(events); reduceErr != nil {
				h.logger.Error("failed to reduce historical state", "error", reduceErr, "lamport", lamport)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to reduce state"})
				return
			}
			snapshot = &registry.TrustSnapshot{
				Lamport: historicalState.Lamport,
				State:   *historicalState,
			}
		}
	}

	if err != nil {
		h.logger.Error("failed to create snapshot", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "snapshot creation failed"})
		return
	}

	writeJSON(w, http.StatusOK, snapshot)
}

// HandlePostEvent appends a new trust event (admin-only, signed).
// POST /v1/trust/events
func (h *Handler) HandlePostEvent(w http.ResponseWriter, r *http.Request) {
	var event registry.TrustEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event payload: " + err.Error()})
		return
	}

	// Verify author key against known keys in the trust registry.
	// In production, AuthorKID must match a known key.
	if event.AuthorKID != "" {
		state := h.registry.State()
		if len(state.Keys) > 0 {
			found := false
			for _, key := range state.Keys {
				if key.KID == event.AuthorKID && key.RevokedAtLamport == nil {
					found = true
					break
				}
			}
			if !found {
				h.logger.Warn("trust event from unknown or revoked author key", "author_kid", event.AuthorKID)
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "author key not found or revoked in trust registry",
				})
				return
			}
		} else {
			h.logger.Warn("trust registry has no keys — allowing bootstrap write", "author_kid", event.AuthorKID)
		}
	} else {
		h.logger.Warn("trust event submitted without author_kid field")
	}

	if event.EventType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event_type is required"})
		return
	}
	if event.SubjectID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_id is required"})
		return
	}

	if err := h.registry.AppendEvent(r.Context(), &event); err != nil {
		h.logger.Error("failed to append trust event", "error", err, "event_type", event.EventType)
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	h.logger.Info("trust event appended",
		"event_id", event.ID,
		"event_type", event.EventType,
		"lamport", event.Lamport,
		"subject_id", event.SubjectID,
	)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"event_id": event.ID,
		"lamport":  event.Lamport,
		"hash":     event.Hash,
	})
}

// HandleGetState returns the current trust state (without snapshot hashing overhead).
// GET /v1/trust/state
func (h *Handler) HandleGetState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.registry.State())
}

// HandleListEvents returns recent trust events.
// GET /v1/trust/events?since=L&subject=S
func (h *Handler) HandleListEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	subjectID := r.URL.Query().Get("subject")
	if subjectID != "" {
		events, err := h.registry.ListEventsBySubject(ctx, subjectID)
		if err != nil {
			h.logger.Error("failed to list events by subject", "error", err, "subject", subjectID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list events"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"events":          events,
			"current_lamport": h.registry.CurrentLamport(),
		})
		return
	}

	var sinceLamport uint64
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		val, err := strconv.ParseUint(sinceStr, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid since parameter"})
			return
		}
		sinceLamport = val
	}

	events, err := h.registry.ListEvents(ctx, sinceLamport)
	if err != nil {
		h.logger.Error("failed to list events", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list events"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events":          events,
		"current_lamport": h.registry.CurrentLamport(),
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
