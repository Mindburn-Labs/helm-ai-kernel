package capgraph

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/integrations/manifest"
)

func TestCapabilityURNParse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		parts   *URNParts
	}{
		{
			name: "valid",
			raw:  "cap://github/list-repos@1.0.0",
			parts: &URNParts{
				Provider: "github",
				Action:   "list-repos",
				Version:  "1.0.0",
			},
		},
		{
			name: "valid_nested_action",
			raw:  "cap://github/repos/create@2.1.0",
			parts: &URNParts{
				Provider: "github",
				Action:   "repos/create",
				Version:  "2.1.0",
			},
		},
		{name: "missing_prefix", raw: "github/list-repos@1.0.0", wantErr: true},
		{name: "missing_version", raw: "cap://github/list-repos", wantErr: true},
		{name: "empty_version", raw: "cap://github/list-repos@", wantErr: true},
		{name: "missing_action", raw: "cap://github@1.0.0", wantErr: true},
		{name: "empty_provider", raw: "cap:///list-repos@1.0.0", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			urn, err := ParseURN(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(urn) != tc.raw {
				t.Errorf("URN mismatch: got %q, want %q", urn, tc.raw)
			}
			parts, err := DecomposeURN(tc.raw)
			if err != nil {
				t.Fatalf("DecomposeURN: %v", err)
			}
			if parts.Provider != tc.parts.Provider {
				t.Errorf("provider: got %q, want %q", parts.Provider, tc.parts.Provider)
			}
			if parts.Action != tc.parts.Action {
				t.Errorf("action: got %q, want %q", parts.Action, tc.parts.Action)
			}
			if parts.Version != tc.parts.Version {
				t.Errorf("version: got %q, want %q", parts.Version, tc.parts.Version)
			}
		})
	}
}

func TestFormatURN_RoundTrip(t *testing.T) {
	urn := FormatURN("github", "create-issue", "1.2.0")
	if urn.String() != "cap://github/create-issue@1.2.0" {
		t.Errorf("FormatURN: got %q", urn)
	}
	parts, err := DecomposeURN(urn.String())
	if err != nil {
		t.Fatalf("DecomposeURN: %v", err)
	}
	if parts.Provider != "github" || parts.Action != "create-issue" || parts.Version != "1.2.0" {
		t.Errorf("round-trip failed: %+v", parts)
	}
}

func TestCompileManifests(t *testing.T) {
	m := testGitHubManifest()
	graph, err := Compile([]manifest.IntegrationManifest{m})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if graph.Size() != 2 {
		t.Fatalf("expected 2 capabilities, got %d", graph.Size())
	}
}

func TestResolveCapability(t *testing.T) {
	m := testGitHubManifest()
	graph, err := Compile([]manifest.IntegrationManifest{m})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	node, err := graph.Resolve("cap://github/list-repos@1.0.0")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if node.ProviderID != "github" {
		t.Errorf("expected provider=github, got %s", node.ProviderID)
	}
	if node.RuntimeKind != manifest.RuntimeHTTP {
		t.Errorf("expected runtime=http, got %s", node.RuntimeKind)
	}
	if node.RiskClass != "E0" {
		t.Errorf("expected risk_class=E0, got %s", node.RiskClass)
	}
	if node.AuthType != "oauth2" {
		t.Errorf("expected auth_type=oauth2, got %s", node.AuthType)
	}
	if node.ContentHash == "" {
		t.Error("expected non-empty content hash")
	}
}

func TestResolveCapability_NotFound(t *testing.T) {
	graph, _ := Compile(nil)
	_, err := graph.Resolve("cap://nonexistent/action@1.0.0")
	if err == nil {
		t.Fatal("expected error for missing capability")
	}
}

func TestCompile_DuplicateURN(t *testing.T) {
	m := testGitHubManifest()
	// Pass the same manifest twice → duplicate URNs.
	_, err := Compile([]manifest.IntegrationManifest{m, m})
	if err == nil {
		t.Fatal("expected error for duplicate URNs across manifests")
	}
}

func testGitHubManifest() manifest.IntegrationManifest {
	return manifest.IntegrationManifest{
		APIVersion: manifest.APIVersion,
		Provider: manifest.ProviderMeta{
			ID:       "github",
			Name:     "GitHub",
			Category: "developer_tools",
		},
		Connector: manifest.ConnectorMeta{
			ID:        "github-v1",
			Version:   "1.0.0",
			Packaging: "builtin",
		},
		Auth: manifest.AuthSpec{
			Methods: []manifest.AuthMethod{
				{
					Type: "oauth2",
					OAuthConfig: &manifest.OAuthMethodSpec{
						AuthorizationURL: "https://github.com/login/oauth/authorize",
						TokenURL:         "https://github.com/login/oauth/access_token",
					},
				},
			},
		},
		Caps: []manifest.CapabilitySpec{
			{
				URN:       "cap://github/list-repos@1.0.0",
				Name:      "List Repositories",
				RiskClass: "E0",
			},
			{
				URN:       "cap://github/create-issue@1.0.0",
				Name:      "Create Issue",
				RiskClass: "E1",
			},
		},
		Runtime: manifest.RuntimeBinding{Kind: manifest.RuntimeHTTP},
	}
}
