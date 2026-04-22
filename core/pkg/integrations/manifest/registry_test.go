package manifest

import (
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Registry Tests
// ---------------------------------------------------------------------------

func TestManifestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewManifestRegistry()
	m := validGitHubManifest()

	if err := reg.Register(m); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}
	if reg.Count() != 1 {
		t.Errorf("expected count 1, got %d", reg.Count())
	}

	got, ok := reg.Get("github-v1")
	if !ok {
		t.Fatal("expected to find github-v1")
	}
	if got.Provider.Name != "GitHub" {
		t.Errorf("expected GitHub, got %s", got.Provider.Name)
	}
}

func TestManifestRegistry_DuplicateReject(t *testing.T) {
	reg := NewManifestRegistry()
	m := validGitHubManifest()
	_ = reg.Register(m)

	err := reg.Register(m)
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
}

func TestManifestRegistry_InvalidReject(t *testing.T) {
	reg := NewManifestRegistry()
	m := &IntegrationManifest{} // Empty — should fail validation.

	err := reg.Register(m)
	if err == nil {
		t.Fatal("expected error for invalid manifest")
	}
}

func TestManifestRegistry_GetByProvider(t *testing.T) {
	reg := NewManifestRegistry()
	gh := validGitHubManifest()
	_ = reg.Register(gh)

	// Create a second "github" connector.
	gh2 := validGitHubManifest()
	gh2.Connector.ID = "github-actions-v1"
	gh2.Connector.Version = "1.0.0"
	gh2.Caps[0].URN = "cap://github/run-action@1.0.0"
	_ = reg.Register(gh2)

	results := reg.GetByProvider("github")
	if len(results) != 2 {
		t.Errorf("expected 2 github manifests, got %d", len(results))
	}

	results = reg.GetByProvider("slack")
	if len(results) != 0 {
		t.Errorf("expected 0 slack manifests, got %d", len(results))
	}
}

func TestManifestRegistry_All(t *testing.T) {
	reg := NewManifestRegistry()
	gh := validGitHubManifest()
	_ = reg.Register(gh)

	all := reg.All()
	if len(all) != 1 {
		t.Errorf("expected 1 manifest, got %d", len(all))
	}
}

func TestManifestRegistry_LoadDir(t *testing.T) {
	reg := NewManifestRegistry()
	err := reg.LoadDir(filepath.Join("testdata"))
	if err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}
	if reg.Count() < 3 {
		t.Errorf("expected at least 3 manifests (github, slack, stripe), got %d", reg.Count())
	}

	// Verify each provider loaded
	for _, id := range []string{"github", "slack", "stripe"} {
		results := reg.GetByProvider(id)
		if len(results) == 0 {
			t.Errorf("expected manifest for provider %q", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Version Pinning Tests
// ---------------------------------------------------------------------------

func TestCheckUpgrade_NoUpgrade(t *testing.T) {
	m := validGitHubManifest()
	pin := CheckUpgrade("1.0.0", m)

	if pin.UpgradeAvail {
		t.Error("expected no upgrade when versions match")
	}
	if pin.ConnectorID != "github-v1" {
		t.Errorf("expected connector ID github-v1, got %s", pin.ConnectorID)
	}
}

func TestCheckUpgrade_UpgradeAvailable(t *testing.T) {
	m := validGitHubManifest()
	m.Connector.Version = "2.0.0"

	pin := CheckUpgrade("1.0.0", m)
	if !pin.UpgradeAvail {
		t.Error("expected upgrade available")
	}
	if pin.UpgradeVersion != "2.0.0" {
		t.Errorf("expected upgrade version 2.0.0, got %s", pin.UpgradeVersion)
	}
	if pin.UpgradeReason == "" {
		t.Error("expected non-empty upgrade reason")
	}
}

// ---------------------------------------------------------------------------
// Manifest Lint Tests (Slack & Stripe)
// ---------------------------------------------------------------------------

func TestManifestLint_Slack(t *testing.T) {
	m, err := LoadFromFile(filepath.Join("testdata", "slack.json"))
	if err != nil {
		t.Fatalf("failed to load slack manifest: %v", err)
	}
	if m.Provider.ID != "slack" {
		t.Errorf("expected provider.id=slack, got %s", m.Provider.ID)
	}
	if m.Connector.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", m.Connector.Version)
	}
	if len(m.Caps) != 3 {
		t.Errorf("expected 3 capabilities, got %d", len(m.Caps))
	}
	if m.Auth.Methods[0].Type != "oauth2" {
		t.Errorf("expected oauth2 auth, got %s", m.Auth.Methods[0].Type)
	}
	if len(m.UI.InstallSteps) != 2 {
		t.Errorf("expected 2 install steps, got %d", len(m.UI.InstallSteps))
	}
}

func TestManifestLint_Stripe(t *testing.T) {
	m, err := LoadFromFile(filepath.Join("testdata", "stripe.json"))
	if err != nil {
		t.Fatalf("failed to load stripe manifest: %v", err)
	}
	if m.Provider.ID != "stripe" {
		t.Errorf("expected provider.id=stripe, got %s", m.Provider.ID)
	}
	if m.Auth.Methods[0].Type != "apikey" {
		t.Errorf("expected apikey auth, got %s", m.Auth.Methods[0].Type)
	}
	if len(m.Caps) != 3 {
		t.Errorf("expected 3 capabilities, got %d", len(m.Caps))
	}

	// Verify high-risk capability
	var hasE3 bool
	for _, cap := range m.Caps {
		if cap.RiskClass == "E3" {
			hasE3 = true
			if !cap.Rollback {
				t.Error("expected E3 capability to support rollback")
			}
		}
	}
	if !hasE3 {
		t.Error("expected at least one E3 risk capability for Stripe")
	}

	// Verify financial data restrictions
	if len(m.Policies.DataClassRestriction) == 0 {
		t.Error("expected data class restrictions for Stripe")
	}
	if len(m.Evidence.RedactionRules) == 0 {
		t.Error("expected redaction rules for Stripe")
	}
}

// ---------------------------------------------------------------------------
// Commercial Packs Tests
// ---------------------------------------------------------------------------

func TestCommercialPacks_Count(t *testing.T) {
	packs := CommercialPacks()
	if len(packs) != 4 {
		t.Errorf("expected 4 commercial packs, got %d", len(packs))
	}
}

func TestCommercialPacks_IDs(t *testing.T) {
	packs := CommercialPacks()
	expected := map[string]bool{
		"siem-pack":          false,
		"federation-pack":    false,
		"governance-pack":    false,
		"orchestration-pack": false,
	}
	for _, p := range packs {
		if _, ok := expected[p.ID]; ok {
			expected[p.ID] = true
		} else {
			t.Errorf("unexpected pack ID: %s", p.ID)
		}
	}
	for id, found := range expected {
		if !found {
			t.Errorf("missing pack: %s", id)
		}
	}
}

func TestCommercialPacks_Metadata(t *testing.T) {
	for _, p := range CommercialPacks() {
		if p.Name == "" {
			t.Errorf("pack %s missing name", p.ID)
		}
		if p.Version == "" {
			t.Errorf("pack %s missing version", p.ID)
		}
		if p.License == "" {
			t.Errorf("pack %s missing license", p.ID)
		}
		if p.RequiresTier == "" {
			t.Errorf("pack %s missing requires_tier", p.ID)
		}
		if len(p.Connectors) == 0 {
			t.Errorf("pack %s has no connectors", p.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Contract Tests: manifest-defined providers have valid capabilities
// ---------------------------------------------------------------------------

func TestContractTest_AllManifestsHaveValidCaps(t *testing.T) {
	reg := NewManifestRegistry()
	if err := reg.LoadDir("testdata"); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	validRiskClasses := map[string]bool{
		"E0": true, "E1": true, "E2": true, "E3": true, "E4": true,
	}

	for _, m := range reg.All() {
		t.Run(m.Connector.ID, func(t *testing.T) {
			for _, cap := range m.Caps {
				if cap.URN == "" {
					t.Errorf("capability %q has empty URN", cap.Name)
				}
				if !validRiskClasses[cap.RiskClass] {
					t.Errorf("capability %q has invalid risk class %q", cap.URN, cap.RiskClass)
				}
			}
		})
	}
}
