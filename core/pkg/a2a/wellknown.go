// Package a2a — wellknown.go
// HTTP handler for /.well-known/agent-card.json (IETF RFC 8615).
//
// Serves the HELM kernel's AgentCard document for A2A discovery.
// The card is built from runtime configuration and cached with a
// stable content hash. Refreshes on config change.

package a2a

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

// AgentCardProvider supplies the AgentCard for the well-known handler.
type AgentCardProvider interface {
	GetCard() *AgentCard
}

// WellKnownHandler serves GET /.well-known/agent-card.json.
type WellKnownHandler struct {
	provider AgentCardProvider
}

// NewWellKnownHandler creates a new handler for agent card discovery.
func NewWellKnownHandler(provider AgentCardProvider) *WellKnownHandler {
	return &WellKnownHandler{provider: provider}
}

// ServeHTTP implements http.Handler.
func (h *WellKnownHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	card := h.provider.GetCard()
	if card == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"agent card not configured"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(card)
}

// RegisterWellKnownRoute registers the /.well-known/agent-card.json handler.
func RegisterWellKnownRoute(mux *http.ServeMux, provider AgentCardProvider) {
	handler := NewWellKnownHandler(provider)
	mux.Handle("/.well-known/agent-card.json", handler)
}

// ── Default Card Provider ────────────────────────────────────────

// KernelCardProvider builds an AgentCard from environment and MCP catalog.
type KernelCardProvider struct {
	mu   sync.RWMutex
	card *AgentCard
}

// KernelCardConfig controls how the default card is built.
type KernelCardConfig struct {
	AgentID       string
	Name          string
	Description   string
	EndpointURL   string // defaults to HELM_PUBLIC_URL env
	Organization  string
	OrgURL        string
	AuthMethods   []AuthMethod
	Features      []Feature
	MCPToolSkills []AgentSkill // injected from MCP catalog
}

// NewKernelCardProvider builds a card provider from kernel config.
func NewKernelCardProvider(cfg KernelCardConfig) *KernelCardProvider {
	endpoint := cfg.EndpointURL
	if endpoint == "" {
		endpoint = os.Getenv("HELM_PUBLIC_URL")
	}
	if endpoint == "" {
		endpoint = "http://localhost:9100"
	}

	name := cfg.Name
	if name == "" {
		name = "HELM Governance Verifier"
	}

	agentID := cfg.AgentID
	if agentID == "" {
		agentID = "helm-governance"
	}

	description := cfg.Description
	if description == "" {
		description = "Fail-closed execution authority verifier. Governs agent actions, emits cryptographic receipts, and provides deterministic proof surfaces."
	}

	// Build default governance skills.
	skills := []AgentSkill{
		{
			ID:          "helm.verify",
			Name:        "Verify agent action",
			Description: "Evaluate an agent action against HELM governance policy and emit a cryptographic receipt.",
			Examples:    []string{"Verify whether agent X may execute tool Y", "Check if this action complies with workspace policy"},
			InputModes:  []string{"structured"},
			OutputModes: []string{"structured"},
		},
		{
			ID:          "helm.evaluate",
			Name:        "Evaluate A2A envelope",
			Description: "Negotiate A2A protocol features and verify envelope signatures for cross-agent communication.",
			Examples:    []string{"Evaluate this A2A envelope for trust negotiation", "Verify agent signature on this delegation request"},
			InputModes:  []string{"structured"},
			OutputModes: []string{"structured"},
		},
	}
	skills = append(skills, cfg.MCPToolSkills...)

	authMethods := cfg.AuthMethods
	if len(authMethods) == 0 {
		authMethods = []AuthMethod{AuthMethodAPIKey}
	}

	features := cfg.Features
	if len(features) == 0 {
		features = []Feature{
			FeatureMeteringReceipts,
			FeatureDisputeReplay,
			FeatureProofGraphSync,
			FeatureEvidenceExport,
		}
	}

	now := time.Now()
	card := &AgentCard{
		AgentID:     agentID,
		Name:        name,
		Description: description,
		Endpoint:    endpoint,
		Provider: &AgentProvider{
			Organization: cfg.Organization,
			URL:          cfg.OrgURL,
		},
		SupportedVersions:  []SchemaVersion{CurrentVersion},
		Skills:             skills,
		AuthMethods:        authMethods,
		Features:           features,
		DefaultInputModes:  []string{"structured"},
		DefaultOutputModes: []string{"structured"},
		Capabilities: AgentCapabilities{
			Streaming:              false,
			PushNotifications:      false,
			StateTransitionHistory: true,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	card.ContentHash = ComputeCardHash(card)

	if card.Provider != nil && card.Provider.Organization == "" {
		card.Provider = nil
	}

	return &KernelCardProvider{card: card}
}

// GetCard returns the cached AgentCard.
func (p *KernelCardProvider) GetCard() *AgentCard {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.card
}

// Refresh rebuilds the card (called on config change).
func (p *KernelCardProvider) Refresh(cfg KernelCardConfig) {
	fresh := NewKernelCardProvider(cfg)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.card = fresh.card
}
