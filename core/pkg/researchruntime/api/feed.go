package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// getFeed handles GET /api/research/feed.
// Returns the 50 most recent feed events as JSON.
func (r *Router) getFeed(w http.ResponseWriter, req *http.Request) {
	events, err := r.cfg.Feed.Latest(req.Context(), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = nil // writeJSON will encode as null; callers should tolerate this
	}
	writeJSON(w, http.StatusOK, events)
}

// streamFeed handles GET /api/research/feed/stream using Server-Sent Events.
// It polls the feed every 5 seconds and pushes the latest 20 events to the client.
func (r *Router) streamFeed(w http.ResponseWriter, req *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if present

	// Send an initial ping so the client knows the stream is open.
	fmt.Fprint(w, ": ping\n\n")
	flusher.Flush()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-req.Context().Done():
			return
		case <-ticker.C:
			events, err := r.cfg.Feed.Latest(req.Context(), 20)
			if err != nil {
				// Non-fatal: skip this tick rather than closing the stream.
				continue
			}
			data, err := json.Marshal(events)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
