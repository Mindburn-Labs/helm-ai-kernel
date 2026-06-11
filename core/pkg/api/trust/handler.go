// Package trust provides HTTP API handlers for the Trust Registry.
// These handlers expose the trust registry as a queryable substrate via REST.
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust/registry"
)

// Handler provides Trust Registry HTTP endpoints.
type Handler struct {
	registry                *registry.Registry
	logger                  *slog.Logger
	trustedAuthorPublicKeys map[string]string
}

var snapshotFromRegistry = registry.SnapshotFromRegistry

// NewHandler creates a new trust API handler.
func NewHandler(reg *registry.Registry, logger *slog.Logger) *Handler {
	return &Handler{
		registry: reg,
		logger:   logger,
	}
}

// NewHandlerWithTrustedAuthorKeys creates a trust API handler that can verify
// signed network mutations against operator-configured author public keys.
func NewHandlerWithTrustedAuthorKeys(reg *registry.Registry, logger *slog.Logger, keys map[string]string) *Handler {
	h := NewHandler(reg, logger)
	h.trustedAuthorPublicKeys = normalizeAuthorKeys(keys)
	return h
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
		snapshot, err = snapshotFromRegistry(h.registry)
	} else {
		lamport, parseErr := strconv.ParseUint(lamportStr, 10, 64)
		if parseErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid lamport parameter"})
			return
		}
		// For historical snapshots, we need the store — use current state if lamport >= current
		if lamport >= h.registry.CurrentLamport() {
			snapshot, err = snapshotFromRegistry(h.registry)
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

	if event.EventType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event_type is required"})
		return
	}
	if event.SubjectID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subject_id is required"})
		return
	}
	if err := h.verifyAuthorSignature(event); err != nil {
		h.logger.Warn("trust event signature verification failed", "author_kid", event.AuthorKID, "error", err)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
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

func (h *Handler) verifyAuthorSignature(event registry.TrustEvent) error {
	authorKID := strings.TrimSpace(event.AuthorKID)
	if authorKID == "" {
		return fmt.Errorf("author_kid is required")
	}
	if strings.TrimSpace(event.AuthorSig) == "" {
		return fmt.Errorf("author_sig is required")
	}

	state := h.registry.State()
	if len(state.Keys) == 0 {
		return fmt.Errorf("trust registry must be bootstrapped offline before network mutations")
	}
	key, ok := state.Keys[authorKID]
	if !ok || key.RevokedAtLamport != nil {
		return fmt.Errorf("author key not found or revoked in trust registry")
	}

	publicKeyHex := strings.TrimSpace(h.trustedAuthorPublicKeys[authorKID])
	if publicKeyHex == "" {
		return fmt.Errorf("trusted author public key is not configured")
	}
	if got := ed25519PublicKeyHash(publicKeyHex); !strings.EqualFold(got, strings.TrimSpace(key.PublicKeyHash)) {
		return fmt.Errorf("trusted author public key does not match registry key hash")
	}
	ok, err := helmcrypto.Verify(publicKeyHex, event.AuthorSig, TrustEventAuthorSignatureMaterial(event))
	if err != nil {
		return fmt.Errorf("verify author signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("author signature verification failed")
	}
	return nil
}

// TrustEventAuthorSignatureMaterial is the canonical, domain-separated payload
// an author signs before submitting a network trust-registry mutation. Lamport,
// created_at, prev_hash, hash, and author_sig are excluded because the registry
// assigns those append-only chain fields at commit time.
func TrustEventAuthorSignatureMaterial(event registry.TrustEvent) []byte {
	material := struct {
		Domain      string             `json:"domain"`
		ID          string             `json:"id"`
		EventType   registry.EventType `json:"event_type"`
		SubjectID   string             `json:"subject_id"`
		SubjectType string             `json:"subject_type,omitempty"`
		Payload     json.RawMessage    `json:"payload"`
		AuthorKID   string             `json:"author_kid"`
	}{
		Domain:      "helm:trust-registry-event-author:v1",
		ID:          strings.TrimSpace(event.ID),
		EventType:   event.EventType,
		SubjectID:   strings.TrimSpace(event.SubjectID),
		SubjectType: strings.TrimSpace(event.SubjectType),
		Payload:     event.Payload,
		AuthorKID:   strings.TrimSpace(event.AuthorKID),
	}
	data, err := canonicalize.JCS(material)
	if err != nil {
		return []byte(fmt.Sprintf("helm:trust-registry-event-author:v1:%s:%s:%s", event.ID, event.EventType, event.SubjectID))
	}
	return data
}

func normalizeAuthorKeys(keys map[string]string) map[string]string {
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]string, len(keys))
	for kid, publicKey := range keys {
		kid = strings.TrimSpace(kid)
		publicKey = strings.TrimSpace(publicKey)
		if kid != "" && publicKey != "" {
			out[kid] = publicKey
		}
	}
	return out
}

func ed25519PublicKeyHash(publicKeyHex string) string {
	raw, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
