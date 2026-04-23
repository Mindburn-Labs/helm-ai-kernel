package manifest

import (
	"fmt"
	"strings"
)

// ManifestRegistry stores compiled manifests indexed by connector ID.
// It provides lookup by connector ID and provider, version pinning checks,
// and a full catalog for the Library UI.
type ManifestRegistry struct {
	manifests map[string]*IntegrationManifest // keyed by connector.id
}

// NewManifestRegistry creates an empty manifest registry.
func NewManifestRegistry() *ManifestRegistry {
	return &ManifestRegistry{
		manifests: make(map[string]*IntegrationManifest),
	}
}

// Register adds a validated manifest to the registry.
func (r *ManifestRegistry) Register(m *IntegrationManifest) error {
	if err := Validate(m); err != nil {
		return fmt.Errorf("invalid manifest %q: %w", m.Connector.ID, err)
	}
	if _, exists := r.manifests[m.Connector.ID]; exists {
		return fmt.Errorf("manifest %q already registered", m.Connector.ID)
	}
	r.manifests[m.Connector.ID] = m
	return nil
}

// Get retrieves a manifest by connector ID.
func (r *ManifestRegistry) Get(connectorID string) (*IntegrationManifest, bool) {
	m, ok := r.manifests[connectorID]
	return m, ok
}

// GetByProvider returns all manifests for a given provider ID.
func (r *ManifestRegistry) GetByProvider(providerID string) []*IntegrationManifest {
	var results []*IntegrationManifest
	for _, m := range r.manifests {
		if m.Provider.ID == providerID {
			results = append(results, m)
		}
	}
	return results
}

// All returns all registered manifests.
func (r *ManifestRegistry) All() []*IntegrationManifest {
	result := make([]*IntegrationManifest, 0, len(r.manifests))
	for _, m := range r.manifests {
		result = append(result, m)
	}
	return result
}

// Count returns the number of registered manifests.
func (r *ManifestRegistry) Count() int {
	return len(r.manifests)
}

// LoadDir loads all manifests from a directory and registers them.
// Manifests that fail validation are skipped and collected in the error.
func (r *ManifestRegistry) LoadDir(dir string) error {
	manifests, err := LoadFromDir(dir)
	if err != nil {
		// Even partial loads succeed — register what we got.
		for i := range manifests {
			_ = r.Register(&manifests[i])
		}
		return err
	}
	var regErrors []string
	for i := range manifests {
		if regErr := r.Register(&manifests[i]); regErr != nil {
			regErrors = append(regErrors, regErr.Error())
		}
	}
	if len(regErrors) > 0 {
		return fmt.Errorf("registration errors:\n  - %s", strings.Join(regErrors, "\n  - "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Version Pinning
// ---------------------------------------------------------------------------

// VersionPin represents a pinned connector version with upgrade metadata.
type VersionPin struct {
	ConnectorID    string `json:"connector_id"`
	CurrentVersion string `json:"current_version"`
	PinnedVersion  string `json:"pinned_version"`
	UpgradeAvail   bool   `json:"upgrade_available"`
	UpgradeVersion string `json:"upgrade_version,omitempty"`
	UpgradeReason  string `json:"upgrade_reason,omitempty"`
}

// CheckUpgrade compares a pinned version against the manifest's version.
func CheckUpgrade(pinned string, m *IntegrationManifest) VersionPin {
	pin := VersionPin{
		ConnectorID:    m.Connector.ID,
		CurrentVersion: m.Connector.Version,
		PinnedVersion:  pinned,
	}
	if pinned != m.Connector.Version {
		pin.UpgradeAvail = true
		pin.UpgradeVersion = m.Connector.Version
		pin.UpgradeReason = fmt.Sprintf("manifest v%s available, pinned at v%s", m.Connector.Version, pinned)
	}
	return pin
}

// ---------------------------------------------------------------------------
// Commercial Pack Descriptor
// ---------------------------------------------------------------------------

// PackDescriptor describes a commercial integration pack that can be
// installed into the fabric. It wraps one or more manifests with
// licensing and pricing metadata.
type PackDescriptor struct {
	ID           string   `json:"id"`            // e.g. "siem-pack"
	Name         string   `json:"name"`          // e.g. "SIEM Integration Pack"
	Version      string   `json:"version"`       // semver
	Description  string   `json:"description"`   // What the pack provides.
	Category     string   `json:"category"`      // "security", "compliance", "orchestration", etc.
	Connectors   []string `json:"connectors"`    // Connector IDs included in this pack.
	License      string   `json:"license"`       // "commercial", "open-core", "enterprise"
	RequiresTier string   `json:"requires_tier"` // "pro", "enterprise", etc.
}

// CommercialPacks returns descriptors for all known commercial packs.
// These map directly to commercial/integrations/{siem,federation,governance,orchestration}.
func CommercialPacks() []PackDescriptor {
	return []PackDescriptor{
		{
			ID:           "siem-pack",
			Name:         "SIEM Integration Pack",
			Version:      "1.0.0",
			Description:  "Forward audit events and incidents to SIEM platforms (Splunk, Datadog, Elastic).",
			Category:     "security",
			Connectors:   []string{"splunk-v1", "datadog-v1", "elastic-v1"},
			License:      "commercial",
			RequiresTier: "enterprise",
		},
		{
			ID:           "federation-pack",
			Name:         "Federation Integration Pack",
			Version:      "1.0.0",
			Description:  "Cross-organization trust federation, identity bridging, and mesh collaboration.",
			Category:     "governance",
			Connectors:   []string{"federation-bridge-v1"},
			License:      "commercial",
			RequiresTier: "enterprise",
		},
		{
			ID:           "governance-pack",
			Name:         "Governance Integration Pack",
			Version:      "1.0.0",
			Description:  "Policy frameworks, compliance attestation, and regulatory reporting connectors.",
			Category:     "compliance",
			Connectors:   []string{"compliance-reporter-v1", "policy-sync-v1"},
			License:      "commercial",
			RequiresTier: "pro",
		},
		{
			ID:           "orchestration-pack",
			Name:         "Orchestration Integration Pack",
			Version:      "1.0.0",
			Description:  "Multi-system workflow orchestration, saga coordination, and rollback management.",
			Category:     "orchestration",
			Connectors:   []string{"saga-coordinator-v1", "workflow-bridge-v1"},
			License:      "commercial",
			RequiresTier: "pro",
		},
	}
}
