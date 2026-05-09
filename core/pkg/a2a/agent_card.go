// Package a2a — agent_card.go
// Agent Card: discovery metadata for A2A agents.
//
// An AgentCard is the public identity document of an A2A agent. It contains
// the agent's capabilities, supported protocol versions, authentication
// requirements, and endpoint information. Cards are served at a well-known
// URL (/.well-known/agent.json) and must be verifiable via signature.
//
// Invariants:
//   - Agent ID must be non-empty.
//   - At least one skill must be declared.
//   - Supported versions must include at least one entry.
//   - Endpoint URL must be non-empty.
//   - Cards are immutable once signed; changes require re-signing.

package a2a

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ── Agent Card ───────────────────────────────────────────────────

// AgentCard is the public identity and capability document for an A2A agent.
// Aligned with Linux Foundation A2A v1.0 GA schema.
type AgentCard struct {
	AgentID            string            `json:"agent_id"`
	Name               string            `json:"name"`
	Description        string            `json:"description,omitempty"`
	Endpoint           string            `json:"endpoint"`
	Provider           *AgentProvider    `json:"provider,omitempty"`
	SupportedVersions  []SchemaVersion   `json:"supported_versions"`
	Skills             []AgentSkill      `json:"skills"`
	AuthMethods        []AuthMethod      `json:"auth_methods,omitempty"`
	Features           []Feature         `json:"features,omitempty"`
	DefaultInputModes  []string          `json:"defaultInputModes,omitempty"`
	DefaultOutputModes []string          `json:"defaultOutputModes,omitempty"`
	Capabilities       AgentCapabilities `json:"capabilities,omitempty"`
	Signature          string            `json:"signature,omitempty"`
	ContentHash        string            `json:"content_hash,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// AgentProvider identifies the organization that hosts the agent.
type AgentProvider struct {
	Organization string `json:"organization"`
	URL          string `json:"url,omitempty"`
}

// AgentCapabilities describes optional protocol features the agent supports.
type AgentCapabilities struct {
	Streaming              bool `json:"streaming"`
	PushNotifications      bool `json:"pushNotifications"`
	StateTransitionHistory bool `json:"stateTransitionHistory"`
}

// AgentSkill describes one capability that an agent offers.
type AgentSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Examples    []string `json:"examples,omitempty"`
	InputModes  []string `json:"input_modes,omitempty"`  // "text", "file", "structured"
	OutputModes []string `json:"output_modes,omitempty"` // "text", "artifact", "structured"
}

// AuthMethod describes a supported authentication mechanism.
type AuthMethod string

const (
	AuthMethodIATP   AuthMethod = "IATP" // IATP challenge-response
	AuthMethodAPIKey AuthMethod = "API_KEY"
	AuthMethodOAuth2 AuthMethod = "OAUTH2"
	AuthMethodMTLS   AuthMethod = "MTLS"
)

// ValidateAgentCard checks that a card meets all required invariants.
func ValidateAgentCard(card *AgentCard) error {
	if card == nil {
		return errors.New("agent_card: nil card")
	}
	if card.AgentID == "" {
		return errors.New("agent_card: agent_id is required")
	}
	if card.Endpoint == "" {
		return errors.New("agent_card: endpoint is required")
	}
	if len(card.SupportedVersions) == 0 {
		return errors.New("agent_card: at least one supported_version is required")
	}
	if len(card.Skills) == 0 {
		return errors.New("agent_card: at least one skill is required")
	}
	if card.Provider != nil && card.Provider.Organization == "" {
		return errors.New("agent_card: provider.organization is required when provider is set")
	}
	for i, skill := range card.Skills {
		if skill.ID == "" {
			return fmt.Errorf("agent_card: skill[%d].id is required", i)
		}
		if skill.Name == "" {
			return fmt.Errorf("agent_card: skill[%d].name is required", i)
		}
	}
	return nil
}

// ComputeCardHash creates a deterministic SHA-256 hash of the card content.
// All identity-bearing fields are included; mutable metadata (timestamps,
// signature) is excluded so the hash is stable across re-signings.
func ComputeCardHash(card *AgentCard) string {
	hashable := struct {
		AgentID            string            `json:"agent_id"`
		Name               string            `json:"name"`
		Endpoint           string            `json:"endpoint"`
		Provider           *AgentProvider    `json:"provider,omitempty"`
		SupportedVersions  []SchemaVersion   `json:"supported_versions"`
		Skills             []AgentSkill      `json:"skills"`
		Features           []Feature         `json:"features"`
		DefaultInputModes  []string          `json:"defaultInputModes,omitempty"`
		DefaultOutputModes []string          `json:"defaultOutputModes,omitempty"`
		Capabilities       AgentCapabilities `json:"capabilities,omitempty"`
	}{
		AgentID:            card.AgentID,
		Name:               card.Name,
		Endpoint:           card.Endpoint,
		Provider:           card.Provider,
		SupportedVersions:  card.SupportedVersions,
		Skills:             card.Skills,
		Features:           card.Features,
		DefaultInputModes:  card.DefaultInputModes,
		DefaultOutputModes: card.DefaultOutputModes,
		Capabilities:       card.Capabilities,
	}
	data, _ := json.Marshal(hashable)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ── Agent Registry ───────────────────────────────────────────────

// AgentRegistry manages discovery and lookup of agent cards.
type AgentRegistry struct {
	mu    sync.RWMutex
	cards map[string]*AgentCard // agentID -> card
}

// NewAgentRegistry creates an empty agent registry.
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		cards: make(map[string]*AgentCard),
	}
}

// Register adds or updates an agent card in the registry.
// Returns an error if the card fails validation.
func (r *AgentRegistry) Register(card *AgentCard) error {
	if err := ValidateAgentCard(card); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	card.ContentHash = ComputeCardHash(card)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cards[card.AgentID] = card
	return nil
}

// Lookup returns the card for the given agent ID.
func (r *AgentRegistry) Lookup(agentID string) (*AgentCard, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	card, ok := r.cards[agentID]
	return card, ok
}

// Deregister removes an agent card from the registry.
func (r *AgentRegistry) Deregister(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, existed := r.cards[agentID]
	delete(r.cards, agentID)
	return existed
}

// ListAgents returns all registered agent IDs.
func (r *AgentRegistry) ListAgents() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.cards))
	for id := range r.cards {
		ids = append(ids, id)
	}
	return ids
}

// FindBySkill returns all agents that offer the given skill ID.
func (r *AgentRegistry) FindBySkill(skillID string) []*AgentCard {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*AgentCard
	for _, card := range r.cards {
		for _, skill := range card.Skills {
			if skill.ID == skillID {
				result = append(result, card)
				break
			}
		}
	}
	return result
}

// FindByFeature returns all agents that support the given feature.
func (r *AgentRegistry) FindByFeature(feature Feature) []*AgentCard {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*AgentCard
	for _, card := range r.cards {
		for _, f := range card.Features {
			if f == feature {
				result = append(result, card)
				break
			}
		}
	}
	return result
}
