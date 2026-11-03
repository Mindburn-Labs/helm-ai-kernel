// Package a2a — agent_card.go
// Agent Card: discovery metadata for A2A agents.
//
// An AgentCard is the public identity document of an A2A agent. It contains
// the agent's capabilities, supported protocol versions, authentication
// requirements, and endpoint information. Cards are served at
// /.well-known/agent-card.json (see wellknown.go) and must be verifiable via
// signature.
//
// This is the HELM trust-protocol card. It borrows field names from the Linux
// Foundation / Agentic AI Foundation A2A specification (skills, capabilities,
// defaultInputModes, pushNotifications) but is not wire-compatible with the
// a2a-protocol.org AgentCard: HELM keys the card by agent_id, carries
// supported_versions/auth_methods/features and a content hash + signature,
// and does not emit the A2A url/version/protocolVersion/securitySchemes
// fields. Interoperating with an A2A v1.0 peer requires a separate,
// conformance-tested translation; do not present this card as one.
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
	"sync"
	"time"
)

// ── Agent Card ───────────────────────────────────────────────────

// AgentCard is the public identity and capability document for a HELM
// agent-to-agent trust peer. See the package comment above for how it differs
// from the a2a-protocol.org AgentCard.
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
	mu           sync.RWMutex
	cards        map[string]*AgentCard           // agentID -> card
	skillIndex   map[string]map[string]struct{}  // skillID -> agentIDs
	featureIndex map[Feature]map[string]struct{} // feature -> agentIDs
}
