package mcp

import (
	"encoding/json"
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// SentinelConnector handles external execution proposals from BGT Labs Sentinel.
type SentinelConnector struct {
	guard *guardian.Guardian
}

// NewSentinelConnector creates a new SentinelConnector instance.
func NewSentinelConnector(g *guardian.Guardian) *SentinelConnector {
	return &SentinelConnector{guard: g}
}

// SentinelIntent maps BGT Labs Sentinel's universal authorization request payload.
type SentinelIntent struct {
	Principal string                 `json:"principal"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Context   map[string]interface{} `json:"context"`
}

// ServeHTTP exposes a standard gateway endpoint for BGT Labs Sentinel integration.
func (s *SentinelConnector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var intent SentinelIntent
	if err := json.NewDecoder(r.Body).Decode(&intent); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Map Sentinel universal intent to HELM DecisionRequest parameters
	req := guardian.DecisionRequest{
		Principal: intent.Principal,
		Action:    intent.Action,
		Resource:  intent.Resource,
		Context:   intent.Context,
	}

	decision, err := s.guard.EvaluateDecision(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Encodes HELM's Ed25519-signed receipt to the response for verification
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}
