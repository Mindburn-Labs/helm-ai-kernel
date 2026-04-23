// Package capgraph compiles Integration Manifests into a Capability Graph IR.
// The capability graph is the runtime-indexed lookup structure used by the
// Integration Gateway to resolve capability URNs to their runtime bindings,
// auth requirements, risk classes, and content hashes.
package capgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/integrations/manifest"
)

// CapabilityURN is the canonical identity of an action:
// cap://<provider_id>/<action_name>@<connector_version>
type CapabilityURN string

// ParseURN parses a capability URN string into its component parts.
func ParseURN(raw string) (CapabilityURN, error) {
	p, err := DecomposeURN(raw)
	if err != nil {
		return "", err
	}
	_ = p
	return CapabilityURN(raw), nil
}

// URNParts holds the decomposed parts of a capability URN.
type URNParts struct {
	Provider string
	Action   string
	Version  string
}

// DecomposeURN breaks a URN string into provider, action, and version.
func DecomposeURN(raw string) (*URNParts, error) {
	if !strings.HasPrefix(raw, "cap://") {
		return nil, fmt.Errorf("capability URN must start with cap://, got %q", raw)
	}
	body := strings.TrimPrefix(raw, "cap://")
	atIdx := strings.LastIndex(body, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("capability URN must contain @version, got %q", raw)
	}
	path := body[:atIdx]
	version := body[atIdx+1:]
	if version == "" {
		return nil, fmt.Errorf("capability URN version is empty in %q", raw)
	}
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("capability URN must have provider/action, got %q", raw)
	}
	return &URNParts{
		Provider: parts[0],
		Action:   parts[1],
		Version:  version,
	}, nil
}

// FormatURN constructs a CapabilityURN from its parts.
func FormatURN(provider, action, version string) CapabilityURN {
	return CapabilityURN(fmt.Sprintf("cap://%s/%s@%s", provider, action, version))
}

// String returns the URN as a string.
func (u CapabilityURN) String() string { return string(u) }

// CapabilityNode is a resolved capability in the graph.
type CapabilityNode struct {
	URN           CapabilityURN        `json:"urn"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	Action        string               `json:"action"`   // Decomposed action name from URN.
	Endpoint      string               `json:"endpoint"` // Base URL or endpoint for HTTP/MCP calls.
	ProviderID    string               `json:"provider_id"`
	ConnectorID   string               `json:"connector_id"`
	RuntimeKind   manifest.RuntimeKind `json:"runtime_kind"`
	RuntimeConfig json.RawMessage      `json:"runtime_config,omitempty"`
	AuthType      string               `json:"auth_type"` // Primary auth method type.
	RiskClass     string               `json:"risk_class"`
	Idempotent    bool                 `json:"idempotent"`
	Rollback      bool                 `json:"rollback"`
	InputSchema   json.RawMessage      `json:"input_schema,omitempty"`
	OutputSchema  json.RawMessage      `json:"output_schema,omitempty"`
	ContentHash   string               `json:"content_hash"` // SHA-256 of the capability spec.
}

// CapabilityGraph is the compiled, indexed lookup structure for capabilities.
type CapabilityGraph struct {
	nodes map[CapabilityURN]*CapabilityNode
}

// Compile builds a CapabilityGraph from a set of integration manifests.
func Compile(manifests []manifest.IntegrationManifest) (*CapabilityGraph, error) {
	g := &CapabilityGraph{
		nodes: make(map[CapabilityURN]*CapabilityNode),
	}
	for _, m := range manifests {
		if err := g.addManifest(&m); err != nil {
			return nil, fmt.Errorf("compile manifest %s: %w", m.Connector.ID, err)
		}
	}
	return g, nil
}

// addManifest adds all capabilities from a single manifest to the graph.
func (g *CapabilityGraph) addManifest(m *manifest.IntegrationManifest) error {
	primaryAuth := ""
	if len(m.Auth.Methods) > 0 {
		primaryAuth = m.Auth.Methods[0].Type
	}

	for _, cap := range m.Caps {
		urn := CapabilityURN(cap.URN)
		if _, exists := g.nodes[urn]; exists {
			return fmt.Errorf("duplicate capability URN: %s", urn)
		}

		hash, err := computeCapHash(&cap)
		if err != nil {
			return fmt.Errorf("hash capability %s: %w", cap.URN, err)
		}

		// Extract action name from URN.
		action := cap.Name
		if parts, parseErr := DecomposeURN(cap.URN); parseErr == nil {
			action = parts.Action
		}

		// Extract base endpoint from runtime config if present.
		endpoint := ""
		if len(m.Runtime.Config) > 0 {
			var rtCfg struct {
				BaseURL string `json:"base_url"`
			}
			if jsonErr := json.Unmarshal(m.Runtime.Config, &rtCfg); jsonErr == nil {
				endpoint = rtCfg.BaseURL
			}
		}

		g.nodes[urn] = &CapabilityNode{
			URN:           urn,
			Name:          cap.Name,
			Description:   cap.Description,
			Action:        action,
			Endpoint:      endpoint,
			ProviderID:    m.Provider.ID,
			ConnectorID:   m.Connector.ID,
			RuntimeKind:   m.Runtime.Kind,
			RuntimeConfig: m.Runtime.Config,
			AuthType:      primaryAuth,
			RiskClass:     cap.RiskClass,
			Idempotent:    cap.Idempotent,
			Rollback:      cap.Rollback,
			InputSchema:   cap.InputSchema,
			OutputSchema:  cap.OutputSchema,
			ContentHash:   hash,
		}
	}
	return nil
}

// Resolve looks up a capability by its URN.
func (g *CapabilityGraph) Resolve(urn CapabilityURN) (*CapabilityNode, error) {
	node, ok := g.nodes[urn]
	if !ok {
		return nil, fmt.Errorf("capability not found: %s", urn)
	}
	return node, nil
}

// All returns all capability nodes in the graph.
func (g *CapabilityGraph) All() []*CapabilityNode {
	result := make([]*CapabilityNode, 0, len(g.nodes))
	for _, n := range g.nodes {
		result = append(result, n)
	}
	return result
}

// Size returns the number of capabilities in the graph.
func (g *CapabilityGraph) Size() int {
	return len(g.nodes)
}

// computeCapHash computes a SHA-256 content hash for a capability spec.
func computeCapHash(cap *manifest.CapabilitySpec) (string, error) {
	data, err := json.Marshal(cap)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
