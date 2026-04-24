package manifest

import (
	"encoding/json"
	"testing"
)

// ── Helpers ─────────────────────────────────────────────────────

func validManifest() *IntegrationManifest {
	return &IntegrationManifest{
		APIVersion: APIVersion,
		Provider:   ProviderMeta{ID: "github", Name: "GitHub", Category: "developer_tools"},
		Connector:  ConnectorMeta{ID: "github-v1", Version: "1.0.0", Packaging: "builtin"},
		Auth:       AuthSpec{Methods: []AuthMethod{{Type: "oauth2", OAuthConfig: &OAuthMethodSpec{AuthorizationURL: "https://a", TokenURL: "https://t"}}}},
		Caps: []CapabilitySpec{{
			URN: "cap://github/list-repos@v1", Name: "List Repos", RiskClass: "E0",
		}},
		Runtime: RuntimeBinding{Kind: RuntimeHTTP},
	}
}

// ── Validate ────────────────────────────────────────────────────

func TestValidate_ValidManifest(t *testing.T) {
	if err := Validate(validManifest()); err != nil {
		t.Errorf("valid manifest rejected: %v", err)
	}
}

func TestValidate_WrongAPIVersion(t *testing.T) {
	m := validManifest()
	m.APIVersion = "wrong/v99"
	if err := Validate(m); err == nil {
		t.Error("should reject wrong api_version")
	}
}

func TestValidate_MissingProviderID(t *testing.T) {
	m := validManifest()
	m.Provider.ID = ""
	if err := Validate(m); err == nil {
		t.Error("should reject missing provider.id")
	}
}

func TestValidate_InvalidSemver(t *testing.T) {
	m := validManifest()
	m.Connector.Version = "not-semver"
	if err := Validate(m); err == nil {
		t.Error("should reject invalid semver")
	}
}

func TestValidate_DuplicateCapabilityURN(t *testing.T) {
	m := validManifest()
	m.Caps = append(m.Caps, m.Caps[0])
	if err := Validate(m); err == nil {
		t.Error("should reject duplicate capability URN")
	}
}

func TestValidate_InvalidRiskClass(t *testing.T) {
	m := validManifest()
	m.Caps[0].RiskClass = "E99"
	if err := Validate(m); err == nil {
		t.Error("should reject invalid risk class")
	}
}

func TestValidate_InvalidRuntimeKind(t *testing.T) {
	m := validManifest()
	m.Runtime.Kind = "quantum"
	if err := Validate(m); err == nil {
		t.Error("should reject unknown runtime kind")
	}
}

func TestValidate_APIKeyWithoutConfig(t *testing.T) {
	m := validManifest()
	m.Auth.Methods = []AuthMethod{{Type: "apikey"}}
	if err := Validate(m); err == nil {
		t.Error("should reject apikey without apikey_config")
	}
}

// ── Registry ────────────────────────────────────────────────────

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewManifestRegistry()
	if err := reg.Register(validManifest()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	m, ok := reg.Get("github-v1")
	if !ok || m.Connector.ID != "github-v1" {
		t.Error("should retrieve registered manifest")
	}
}

func TestRegistry_RegisterDuplicate(t *testing.T) {
	reg := NewManifestRegistry()
	_ = reg.Register(validManifest())
	if err := reg.Register(validManifest()); err == nil {
		t.Error("should reject duplicate registration")
	}
}

func TestRegistry_GetByProvider(t *testing.T) {
	reg := NewManifestRegistry()
	_ = reg.Register(validManifest())
	results := reg.GetByProvider("github")
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestRegistry_AllAndCount(t *testing.T) {
	reg := NewManifestRegistry()
	_ = reg.Register(validManifest())
	if reg.Count() != 1 {
		t.Errorf("expected count 1, got %d", reg.Count())
	}
	if len(reg.All()) != 1 {
		t.Error("All() should return 1 manifest")
	}
}

func TestCheckUpgrade_SameVersion(t *testing.T) {
	m := validManifest()
	pin := CheckUpgrade("1.0.0", m)
	if pin.UpgradeAvail {
		t.Error("no upgrade should be available for same version")
	}
}

func TestCheckUpgrade_NewerAvailable(t *testing.T) {
	m := validManifest()
	pin := CheckUpgrade("0.9.0", m)
	if !pin.UpgradeAvail {
		t.Error("upgrade should be available")
	}
	if pin.UpgradeVersion != "1.0.0" {
		t.Errorf("expected upgrade to 1.0.0, got %s", pin.UpgradeVersion)
	}
}

func TestCommercialPacks_HasEntries(t *testing.T) {
	packs := CommercialPacks()
	if len(packs) < 4 {
		t.Errorf("expected at least 4 packs, got %d", len(packs))
	}
}

func TestParse_ValidJSON(t *testing.T) {
	data, _ := json.Marshal(validManifest())
	m, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Connector.ID != "github-v1" {
		t.Errorf("unexpected connector ID: %s", m.Connector.ID)
	}
}
