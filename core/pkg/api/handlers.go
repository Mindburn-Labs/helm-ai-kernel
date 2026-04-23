package api

import (
	"encoding/json"
	"net/http"
)

// HandleIngest handles the /memory/ingest endpoint.
func (s *MemoryService) HandleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	var req IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "Invalid request body")
		return
	}

	// Basic validation
	if req.TenantID == "" || req.SourceID == "" {
		WriteBadRequest(w, "Missing required fields: tenant_id, source_id")
		return
	}

	resp, err := s.Ingest(r.Context(), req)
	if err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// SearchRequest represents a memory search.
type SearchRequest struct {
	Query      string `json:"query"`
	TenantID   string `json:"tenant_id"`
	MaxResults int    `json:"max_results"`
}

// HandleSearch handles the /memory/search endpoint.
func (s *MemoryService) HandleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "Invalid request body")
		return
	}

	// Execute Search
	results, err := s.Search(r.Context(), req.Query, req.TenantID, req.MaxResults)
	if err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}
