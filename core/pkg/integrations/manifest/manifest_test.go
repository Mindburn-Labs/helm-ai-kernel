package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestValidation_ValidGitHub(t *testing.T) {
	m := validGitHubManifest()
	if err := Validate(m); err != nil {
		t.Fatalf("expected valid manifest, got: %v", err)
	}
}

func TestManifestValidation_MissingAPIVersion(t *testing.T) {
	m := validGitHubManifest()
	m.APIVersion = "wrong/v99"
	err := Validate(m)
	if err == nil {
		t.Fatal("expected validation error for wrong api_version")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Errors) == 0 {
		t.Fatal("expected at least one error")
	}
}

func TestManifestValidation_BadSemver(t *testing.T) {
	m := validGitHubManifest()
	m.Connector.Version = "not-a-version"
	err := Validate(m)
	if err == nil {
		t.Fatal("expected validation error for bad semver")
	}
}

func TestManifestValidation_DuplicateURN(t *testing.T) {
	m := validGitHubManifest()
	m.Caps = append(m.Caps, m.Caps[0]) // Duplicate.
	err := Validate(m)
	if err == nil {
		t.Fatal("expected validation error for duplicate URN")
	}
}

func TestManifestValidation_BadURNFormat(t *testing.T) {
	cases := []struct {
		name string
		urn  string
	}{
		{"no_prefix", "github/list-repos@1.0.0"},
		{"no_version", "cap://github/list-repos"},
		{"no_action", "cap://github@1.0.0"},
		{"empty_provider", "cap:///list-repos@1.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validGitHubManifest()
			m.Caps[0].URN = tc.urn
			if err := Validate(m); err == nil {
				t.Fatalf("expected validation error for bad URN %q", tc.urn)
			}
		})
	}
}

func TestManifestValidation_BadRiskClass(t *testing.T) {
	m := validGitHubManifest()
	m.Caps[0].RiskClass = "E9"
	err := Validate(m)
	if err == nil {
		t.Fatal("expected validation error for bad risk class")
	}
}

func TestManifestValidation_MissingAuth(t *testing.T) {
	m := validGitHubManifest()
	m.Auth.Methods = nil
	err := Validate(m)
	if err == nil {
		t.Fatal("expected validation error for missing auth methods")
	}
}

func TestManifestValidation_OAuth2MissingConfig(t *testing.T) {
	m := validGitHubManifest()
	m.Auth.Methods[0].OAuthConfig = nil
	err := Validate(m)
	if err == nil {
		t.Fatal("expected validation error for oauth2 without config")
	}
}

func TestManifestValidation_BadRuntimeKind(t *testing.T) {
	m := validGitHubManifest()
	m.Runtime.Kind = "quantum"
	err := Validate(m)
	if err == nil {
		t.Fatal("expected validation error for unknown runtime kind")
	}
}

func TestManifestLoader_FromFile(t *testing.T) {
	path := filepath.Join("testdata", "github.json")
	m, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if m.Provider.ID != "github" {
		t.Errorf("expected provider.id=github, got %s", m.Provider.ID)
	}
	if m.Connector.Version != "1.0.0" {
		t.Errorf("expected connector.version=1.0.0, got %s", m.Connector.Version)
	}
	if len(m.Caps) != 3 {
		t.Errorf("expected 3 capabilities, got %d", len(m.Caps))
	}
	if m.Runtime.Kind != RuntimeHTTP {
		t.Errorf("expected runtime.kind=http, got %s", m.Runtime.Kind)
	}
	if len(m.UI.InstallSteps) != 2 {
		t.Errorf("expected 2 install steps, got %d", len(m.UI.InstallSteps))
	}
}

func TestManifestLoader_FromDir(t *testing.T) {
	dir := "testdata"
	manifests, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("expected at least one manifest loaded")
	}
}

func TestManifestLoader_InvalidJSON(t *testing.T) {
	_, err := Parse([]byte(`{not json}`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestManifestLoader_InvalidManifest(t *testing.T) {
	_, err := Parse([]byte(`{"api_version": "wrong"}`))
	if err == nil {
		t.Fatal("expected validation error for invalid manifest")
	}
}

func TestParse_RoundTrip(t *testing.T) {
	path := filepath.Join("testdata", "github.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	m, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Re-marshal and parse again.
	data2, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	m2, err := Parse(data2)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if m.Provider.ID != m2.Provider.ID {
		t.Errorf("round-trip provider.id mismatch: %s vs %s", m.Provider.ID, m2.Provider.ID)
	}
	if len(m.Caps) != len(m2.Caps) {
		t.Errorf("round-trip capabilities count mismatch: %d vs %d", len(m.Caps), len(m2.Caps))
	}
}

// validGitHubManifest returns a minimal valid IntegrationManifest for testing.
func validGitHubManifest() *IntegrationManifest {
	return &IntegrationManifest{
		APIVersion: APIVersion,
		Provider: ProviderMeta{
			ID:       "github",
			Name:     "GitHub",
			Category: "developer_tools",
		},
		Connector: ConnectorMeta{
			ID:        "github-v1",
			Version:   "1.0.0",
			Packaging: "builtin",
		},
		Auth: AuthSpec{
			Methods: []AuthMethod{
				{
					Type: "oauth2",
					OAuthConfig: &OAuthMethodSpec{
						AuthorizationURL: "https://github.com/login/oauth/authorize",
						TokenURL:         "https://github.com/login/oauth/access_token",
					},
				},
			},
		},
		Caps: []CapabilitySpec{
			{
				URN:       "cap://github/list-repos@1.0.0",
				Name:      "List Repositories",
				RiskClass: "E0",
			},
		},
		Runtime: RuntimeBinding{
			Kind: RuntimeHTTP,
		},
	}
}
