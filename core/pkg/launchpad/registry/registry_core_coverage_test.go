package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const registryCoverageAppPolicy = `[app]
id = "test-app"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
`

const registryCoverageSubstratePolicy = `[substrate]
id = "local-container"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
isolation_mode = "docker-default"
hostile_agent_grade = false
`

func TestLoadCatalogDiscoverRootAndYAMLHelpers(t *testing.T) {
	root := t.TempDir()
	writeRegistryFile(t, root, "registry/launchpad/apps/b.yaml", "id: b\n")
	writeRegistryFile(t, root, "registry/launchpad/apps/a.yml", "id: a\n")
	writeRegistryFile(t, root, "registry/launchpad/apps/ignored.txt", "id: ignored\n")
	if err := os.MkdirAll(filepath.Join(root, "registry", "launchpad", "apps", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeRegistryFile(t, root, "registry/launchpad/substrates/local.yaml", "id: local\n")
	writeRegistryFile(t, root, "registry/launchpad/mcp/test.yaml", "id: manifest\napp_id: a\n")

	catalog, err := LoadCatalog(root)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	if got := appIDs(catalog.Apps); strings.Join(got, ",") != "a,b" {
		t.Fatalf("LoadCatalog app order = %v, want sorted a,b", got)
	}
	if len(catalog.Substrates) != 1 || catalog.Substrates[0].ID != "local" {
		t.Fatalf("LoadCatalog substrates = %#v, want local", catalog.Substrates)
	}
	if len(catalog.MCPManifests) != 1 || catalog.MCPManifests[0].ID != "manifest" {
		t.Fatalf("LoadCatalog manifests = %#v, want manifest", catalog.MCPManifests)
	}

	missing, err := loadOptionalYAMLDir[AppSpec](filepath.Join(root, "registry", "launchpad", "missing"))
	if err != nil {
		t.Fatalf("loadOptionalYAMLDir missing dir: %v", err)
	}
	if missing != nil {
		t.Fatalf("loadOptionalYAMLDir missing dir = %#v, want nil", missing)
	}
	if got := sortKey(42); got != "42" {
		t.Fatalf("sortKey fallback = %q, want 42", got)
	}
	if _, err := loadYAMLDir[AppSpec](filepath.Join(root, "does-not-exist")); err == nil {
		t.Fatal("loadYAMLDir missing dir error = nil, want error")
	}

	badYAMLRoot := t.TempDir()
	writeRegistryFile(t, badYAMLRoot, "bad.yaml", "id: [\n")
	_, err = loadYAMLDir[AppSpec](badYAMLRoot)
	requireErrorContains(t, err, "bad.yaml")

	missingAppsRoot := t.TempDir()
	_, err = LoadCatalog(missingAppsRoot)
	requireErrorContains(t, err, "registry/launchpad/apps")

	missingSubstratesRoot := t.TempDir()
	writeRegistryFile(t, missingSubstratesRoot, "registry/launchpad/apps/app.yaml", "id: app\n")
	_, err = LoadCatalog(missingSubstratesRoot)
	requireErrorContains(t, err, "registry/launchpad/substrates")

	invalidManifestRoot := t.TempDir()
	writeRegistryFile(t, invalidManifestRoot, "registry/launchpad/apps/app.yaml", "id: app\n")
	writeRegistryFile(t, invalidManifestRoot, "registry/launchpad/substrates/local.yaml", "id: local\n")
	writeRegistryFile(t, invalidManifestRoot, "registry/launchpad/mcp/bad.yaml", "id: [\n")
	_, err = LoadCatalog(invalidManifestRoot)
	requireErrorContains(t, err, "bad.yaml")

	envRoot := t.TempDir()
	writeRegistryFile(t, envRoot, "registry/launchpad/apps/app.yaml", "id: app\n")
	writeRegistryFile(t, envRoot, "registry/launchpad/substrates/local.yaml", "id: local\n")
	if err := os.MkdirAll(filepath.Join(envRoot, "policies", "launchpad"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_LAUNCHPAD_REGISTRY_ROOT", "  "+envRoot+"  ")
	catalog, err = LoadCatalog("")
	if err != nil {
		t.Fatalf("LoadCatalog discovered root: %v", err)
	}
	if catalog.Root != envRoot || len(catalog.MCPManifests) != 0 {
		t.Fatalf("LoadCatalog discovered catalog root=%q manifests=%d, want %q and 0", catalog.Root, len(catalog.MCPManifests), envRoot)
	}
}

func TestDiscoverRootRejectsInvalidExplicitRootAndFindsWorkingDirectoryRoot(t *testing.T) {
	t.Run("invalid env", func(t *testing.T) {
		t.Setenv("HELM_LAUNCHPAD_REGISTRY_ROOT", t.TempDir())
		_, err := DiscoverRoot()
		requireErrorContains(t, err, "does not contain registry/launchpad")
	})

	t.Run("root cwd", func(t *testing.T) {
		root := t.TempDir()
		writeLaunchpadRootMarkers(t, root)
		t.Setenv("HELM_LAUNCHPAD_REGISTRY_ROOT", "")
		withWorkingDir(t, root, func() {
			discovered, err := DiscoverRoot()
			if err != nil {
				t.Fatalf("DiscoverRoot: %v", err)
			}
			if canonicalPath(t, discovered) != canonicalPath(t, root) {
				t.Fatalf("DiscoverRoot = %s, want %s", discovered, root)
			}
		})
	})

	t.Run("core cwd", func(t *testing.T) {
		root := t.TempDir()
		writeLaunchpadRootMarkers(t, root)
		t.Setenv("HELM_LAUNCHPAD_REGISTRY_ROOT", "")
		withWorkingDir(t, filepath.Join(root, "core"), func() {
			discovered, err := DiscoverRoot()
			if err != nil {
				t.Fatalf("DiscoverRoot: %v", err)
			}
			if canonicalPath(t, discovered) != canonicalPath(t, root) {
				t.Fatalf("DiscoverRoot = %s, want %s", discovered, root)
			}
		})
	})
}

func TestMatrixAndCatalogLookups(t *testing.T) {
	catalog := registryCoverageCatalog(t)
	catalog.Apps = append(catalog.Apps,
		AppSpec{ID: "external", Availability: AvailabilityExternalProprietaryAdapter},
		AppSpec{ID: "blocked-license", Availability: AvailabilityBlockedLicense},
		AppSpec{ID: "candidate", Availability: AvailabilityOSSCandidate},
		AppSpec{ID: "blocked-conformance", Availability: AvailabilityBlockedConformance},
	)
	catalog.Substrates = append(catalog.Substrates, SubstrateSpec{ID: "preview", Availability: "preview"})

	cells := catalog.Matrix()
	if len(cells) != len(catalog.Apps)*len(catalog.Substrates) {
		t.Fatalf("Matrix returned %d cells, want %d", len(cells), len(catalog.Apps)*len(catalog.Substrates))
	}
	assertMatrixCell(t, cells, "test-app", "local-container", "ALLOW", "verified", true)
	assertMatrixCell(t, cells, "test-app", "preview", "ESCALATE", "blocked_conformance_not_verified", false)
	assertMatrixCell(t, cells, "external", "local-container", "ESCALATE", "external_byo_license_account_tool", false)
	assertMatrixCell(t, cells, "blocked-license", "local-container", "DENY", "blocked_license_or_redistribution", false)
	assertMatrixCell(t, cells, "candidate", "local-container", "ESCALATE", "experimental_candidate_requires_e2e", false)
	assertMatrixCell(t, cells, "blocked-conformance", "local-container", "ESCALATE", "blocked_conformance_not_verified", false)

	app, ok := catalog.App("test-app")
	if !ok || app.ID != "test-app" {
		t.Fatalf("App(test-app) = (%#v, %v), want test-app true", app, ok)
	}
	if _, ok := catalog.App("missing"); ok {
		t.Fatal("App(missing) ok = true, want false")
	}
	substrate, ok := catalog.Substrate("local-container")
	if !ok || substrate.ID != "local-container" {
		t.Fatalf("Substrate(local-container) = (%#v, %v), want local-container true", substrate, ok)
	}
	if _, ok := catalog.Substrate("missing"); ok {
		t.Fatal("Substrate(missing) ok = true, want false")
	}
}

func TestCatalogValidateRejectsCoreStructuralFailures(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Catalog)
		wantErr string
	}{
		{
			name:    "no apps",
			mutate:  func(c *Catalog) { c.Apps = nil },
			wantErr: "no launchpad apps registered",
		},
		{
			name:    "no substrates",
			mutate:  func(c *Catalog) { c.Substrates = nil },
			wantErr: "no launchpad substrates registered",
		},
		{
			name:    "blank manifest id",
			mutate:  func(c *Catalog) { c.MCPManifests[0].ID = "" },
			wantErr: "MCP manifest id is required",
		},
		{
			name: "duplicate manifest id",
			mutate: func(c *Catalog) {
				c.MCPManifests = append(c.MCPManifests, c.MCPManifests[0])
			},
			wantErr: `duplicate MCP manifest id "test-app.default"`,
		},
		{
			name:    "blank app id",
			mutate:  func(c *Catalog) { c.Apps[0].ID = "" },
			wantErr: "app id is required",
		},
		{
			name:    "duplicate app id",
			mutate:  func(c *Catalog) { c.Apps = append(c.Apps, c.Apps[0]) },
			wantErr: `duplicate app id "test-app"`,
		},
		{
			name:    "unknown availability",
			mutate:  func(c *Catalog) { c.Apps[0].Availability = Availability("space") },
			wantErr: `unknown availability "space"`,
		},
		{
			name:    "app network default",
			mutate:  func(c *Catalog) { c.Apps[0].NetworkPolicy.Default = "allow" },
			wantErr: "network default must be deny",
		},
		{
			name:    "mcp policy",
			mutate:  func(c *Catalog) { c.Apps[0].MCPPolicy.UnknownServerPolicy = "allow" },
			wantErr: "MCP policy must quarantine unknown servers",
		},
		{
			name:    "unknown evidence requirement",
			mutate:  func(c *Catalog) { c.Apps[0].EvidenceRequirements = append(c.Apps[0].EvidenceRequirements, "mystery") },
			wantErr: `unknown evidence requirement "mystery"`,
		},
		{
			name:    "missing policy ref",
			mutate:  func(c *Catalog) { c.Apps[0].FilesystemPolicy.PolicyRef = "" },
			wantErr: "policy_ref is required",
		},
		{
			name:    "unverified conformance",
			mutate:  func(c *Catalog) { c.Apps[0].Conformance.E2EPassing = false },
			wantErr: "cannot be oss_supported without full conformance",
		},
		{
			name:    "blank substrate id",
			mutate:  func(c *Catalog) { c.Substrates[0].ID = "" },
			wantErr: "substrate id is required",
		},
		{
			name:    "duplicate substrate id",
			mutate:  func(c *Catalog) { c.Substrates = append(c.Substrates, c.Substrates[0]) },
			wantErr: `duplicate substrate id "local-container"`,
		},
		{
			name:    "unknown substrate kind",
			mutate:  func(c *Catalog) { c.Substrates[0].Kind = "bare-metal" },
			wantErr: `unknown kind "bare-metal"`,
		},
		{
			name:    "substrate network default",
			mutate:  func(c *Catalog) { c.Substrates[0].Network.Default = "allow" },
			wantErr: "network default must be deny",
		},
		{
			name:    "unknown isolation",
			mutate:  func(c *Catalog) { c.Substrates[0].Isolation.Mode = "process" },
			wantErr: `unknown isolation mode "process"`,
		},
		{
			name:    "unknown supported isolation mode",
			mutate:  func(c *Catalog) { c.Substrates[0].Isolation.SupportedModes = []string{"docker-default", "process"} },
			wantErr: `unknown isolation mode "process"`,
		},
		{
			name:    "missing substrate policy pack",
			mutate:  func(c *Catalog) { c.Substrates[0].PolicyPack = "" },
			wantErr: "policy_pack is required",
		},
		{
			name:    "missing capability",
			mutate:  func(c *Catalog) { c.Substrates[0].Capabilities.SecretMode = "" },
			wantErr: "capabilities.secret_mode is required",
		},
		{
			name:    "missing lifecycle step",
			mutate:  func(c *Catalog) { c.Substrates[0].Capabilities.Lifecycle = []string{"plan"} },
			wantErr: "capabilities.lifecycle must include preflight",
		},
		{
			name:    "supported substrate non ga",
			mutate:  func(c *Catalog) { c.Substrates[0].Capabilities.Status = "beta" },
			wantErr: "cannot be supported unless capabilities.status is ga",
		},
		{
			name:    "supported substrate optional receipts",
			mutate:  func(c *Catalog) { c.Substrates[0].Capabilities.ReceiptSupport = "optional" },
			wantErr: "cannot be supported unless receipt_support is required",
		},
		{
			name:    "supported substrate optional teardown proof",
			mutate:  func(c *Catalog) { c.Substrates[0].Capabilities.TeardownProof = "optional" },
			wantErr: "cannot be supported unless teardown_proof is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalog := registryCoverageCatalog(t)
			tc.mutate(catalog)
			requireErrorContains(t, catalog.Validate(), tc.wantErr)
		})
	}
}

func TestCatalogValidateRejectsModelGatewayFailures(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*AppSpec)
		wantErr string
	}{
		{
			name: "missing logical secret",
			mutate: func(app *AppSpec) {
				configureGateway(app)
				app.ModelGateway.LogicalSecret = ""
			},
			wantErr: "model_gateway.logical_secret is required",
		},
		{
			name: "missing provider",
			mutate: func(app *AppSpec) {
				configureGateway(app)
				app.ModelGateway.Provider = ""
			},
			wantErr: "model_gateway.provider is required",
		},
		{
			name: "missing mode",
			mutate: func(app *AppSpec) {
				configureGateway(app)
				app.ModelGateway.Mode = ""
			},
			wantErr: "model_gateway.mode is required",
		},
		{
			name: "env projection requires raw key marker",
			mutate: func(app *AppSpec) {
				configureGateway(app)
				app.ModelGateway.Mode = "logical_binding_env_projection"
				app.ModelGateway.RawProviderKeyProjected = false
			},
			wantErr: "must mark raw_provider_key_projected",
		},
		{
			name: "token broker forbids raw provider key",
			mutate: func(app *AppSpec) {
				configureGateway(app)
				app.ModelGateway.Mode = "token_broker"
				app.ModelGateway.RawProviderKeyProjected = true
				app.ModelGatewayEnv = nil
			},
			wantErr: "token_broker mode cannot project raw provider keys",
		},
		{
			name: "unknown mode",
			mutate: func(app *AppSpec) {
				configureGateway(app)
				app.ModelGateway.Mode = "ambient"
			},
			wantErr: `unknown model_gateway.mode "ambient"`,
		},
		{
			name: "logical secret must match required secret",
			mutate: func(app *AppSpec) {
				configureGateway(app)
				app.ModelGateway.LogicalSecret = "provider_key"
				app.ModelGatewayEnv = nil
			},
			wantErr: "model_gateway.logical_secret must match required secret model_gateway",
		},
		{
			name: "oss app requires gateway broker evidence",
			mutate: func(app *AppSpec) {
				app.RequiredSecrets = nil
				app.ModelGatewayEnv = []string{"OPENAI_API_KEY"}
				app.ModelGateway = ModelGatewaySpec{
					LogicalSecret:           "model_gateway",
					Provider:                "byo",
					Mode:                    "external_byo",
					RawProviderKeyProjected: true,
				}
			},
			wantErr: "cannot be oss_supported without model_gateway_broker",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalog := registryCoverageCatalog(t)
			tc.mutate(&catalog.Apps[0])
			requireErrorContains(t, catalog.Validate(), tc.wantErr)
		})
	}

	catalog := registryCoverageCatalog(t)
	configureGateway(&catalog.Apps[0])
	catalog.Apps[0].ModelGateway.Mode = "token_broker"
	catalog.Apps[0].ModelGateway.RawProviderKeyProjected = false
	catalog.Apps[0].ModelGatewayEnv = nil
	if err := catalog.Validate(); err != nil {
		t.Fatalf("Validate() accepted token_broker gateway = %v, want nil", err)
	}
}

func TestCatalogValidateRejectsMCPReferenceAndManifestFailures(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Catalog)
		wantErr string
	}{
		{
			name:    "oss app requires mcp manifest refs",
			mutate:  func(c *Catalog) { c.Apps[0].MCPManifests = nil },
			wantErr: "without signed MCP manifest refs",
		},
		{
			name:    "missing manifest ref",
			mutate:  func(c *Catalog) { c.Apps[0].MCPManifests = []string{"missing.default"} },
			wantErr: `references missing MCP manifest "missing.default"`,
		},
		{
			name:    "manifest belongs to another app",
			mutate:  func(c *Catalog) { c.MCPManifests[0].AppID = "other-app" },
			wantErr: `for app "other-app"`,
		},
		{
			name: "missing mcp evidence requirement",
			mutate: func(c *Catalog) {
				c.Apps[0].EvidenceRequirements = withoutString(c.Apps[0].EvidenceRequirements, "mcp_manifest")
			},
			wantErr: "without mcp_manifest evidence requirement",
		},
		{
			name: "orphan manifest app id",
			mutate: func(c *Catalog) {
				orphan := c.MCPManifests[0]
				orphan.ID = "orphan.default"
				orphan.AppID = "orphan"
				c.MCPManifests = append(c.MCPManifests, orphan)
			},
			wantErr: `references unknown app "orphan"`,
		},
		{
			name:    "missing server id",
			mutate:  func(c *Catalog) { c.MCPManifests[0].ServerID = "" },
			wantErr: "server_id is required",
		},
		{
			name:    "unsupported transport",
			mutate:  func(c *Catalog) { c.MCPManifests[0].Transport = "grpc" },
			wantErr: `unsupported transport "grpc"`,
		},
		{
			name:    "stdio requires command",
			mutate:  func(c *Catalog) { c.MCPManifests[0].Command = nil },
			wantErr: "stdio transport requires pinned command",
		},
		{
			name:    "bad package digest",
			mutate:  func(c *Catalog) { c.MCPManifests[0].PackageDigest = "sha256:ABC" },
			wantErr: "package_digest must be sha256:<64 lowercase hex>",
		},
		{
			name:    "package digest drift from AppSpec artifact",
			mutate:  func(c *Catalog) { c.MCPManifests[0].PackageDigest = "sha256:" + strings.Repeat("d", 64) },
			wantErr: "package_digest must match install digest",
		},
		{
			name:    "missing signature ref",
			mutate:  func(c *Catalog) { c.MCPManifests[0].SignatureRef = "" },
			wantErr: "signature_ref is required",
		},
		{
			name:    "signature ref drift from AppSpec supply chain",
			mutate:  func(c *Catalog) { c.MCPManifests[0].SignatureRef = "cosign://registry.example/other:1.0.0.sig" },
			wantErr: "signature_ref must match supply-chain signature_ref",
		},
		{
			name:    "bad schema hash",
			mutate:  func(c *Catalog) { c.MCPManifests[0].SchemaHash = "sha256:123" },
			wantErr: "schema_hash must be sha256:<64 lowercase hex>",
		},
		{
			name:    "no tools",
			mutate:  func(c *Catalog) { c.MCPManifests[0].Tools = nil },
			wantErr: "must declare at least one tool",
		},
		{
			name:    "tool without name",
			mutate:  func(c *Catalog) { c.MCPManifests[0].Tools[0].Name = "" },
			wantErr: "has tool without name",
		},
		{
			name:    "bad tool schema",
			mutate:  func(c *Catalog) { c.MCPManifests[0].Tools[0].SchemaHash = "sha256:123" },
			wantErr: "tool test.read schema_hash must be sha256:<64 lowercase hex>",
		},
		{
			name:    "unsupported tool effect",
			mutate:  func(c *Catalog) { c.MCPManifests[0].Tools[0].Effect = "write" },
			wantErr: `unsupported effect "write"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalog := registryCoverageCatalog(t)
			tc.mutate(catalog)
			requireErrorContains(t, catalog.Validate(), tc.wantErr)
		})
	}

	catalog := registryCoverageCatalog(t)
	catalog.MCPManifests[0].Transport = "http_sse"
	catalog.MCPManifests[0].Command = nil
	if err := catalog.Validate(); err != nil {
		t.Fatalf("Validate() accepted http_sse manifest = %v, want nil", err)
	}
	catalog.MCPManifests[0].Transport = "websocket"
	if err := catalog.Validate(); err != nil {
		t.Fatalf("Validate() accepted websocket manifest = %v, want nil", err)
	}
}

func TestCatalogValidateRequiresLaunchKitParityWhenLaunchKitExists(t *testing.T) {
	catalog := registryCoverageCatalog(t)
	writeLaunchKitParityFixture(t, catalog)
	if err := catalog.Validate(); err != nil {
		t.Fatalf("Validate() rejected matching LaunchKit parity fixture: %v", err)
	}

	writeRegistryFile(t, catalog.Root, "registry/launchkit/apps/test-app/runtime.local.yaml", `mode: live
target: local-container
command:
  - other
healthcheck: test-app --version
mcp_registry_ref: mcp.registry.yaml
provider_host_groups: []
egress_proxy_required: false
`)
	requireErrorContains(t, catalog.Validate(), "LaunchKit local command must match Launchpad runtime.command")
}

func TestOSSSupportedSupplyChainAdditionalEvidenceFailures(t *testing.T) {
	base := registryCoverageCatalog(t).Apps[0]
	cases := []struct {
		name    string
		mutate  func(*AppSpec)
		wantErr string
	}{
		{
			name:    "missing artifact digest evidence",
			mutate:  func(app *AppSpec) { app.SupplyChainEvidence.ArtifactDigest = "" },
			wantErr: "without artifact_digest evidence",
		},
		{
			name:    "artifact digest mismatch",
			mutate:  func(app *AppSpec) { app.SupplyChainEvidence.ArtifactDigest = "sha256:" + strings.Repeat("d", 64) },
			wantErr: "artifact_digest must match install digest",
		},
		{
			name:    "missing vulnerability scan ref",
			mutate:  func(app *AppSpec) { app.SupplyChainEvidence.VulnerabilityScanRef = "" },
			wantErr: "without vulnerability scan evidence",
		},
		{
			name: "missing required evidence labels",
			mutate: func(app *AppSpec) {
				app.EvidenceRequirements = withoutString(app.EvidenceRequirements, "artifact_digest")
			},
			wantErr: "without artifact_digest, cosign_signature, syft_sbom",
		},
		{
			name:    "missing artifact verification promotion evidence",
			mutate:  func(app *AppSpec) { app.PromotionEvidence.ArtifactVerificationRef = "" },
			wantErr: "promotion artifact verification evidence",
		},
		{
			name:    "missing evidence pack promotion evidence",
			mutate:  func(app *AppSpec) { app.PromotionEvidence.EvidencePackRef = "" },
			wantErr: "promotion EvidencePack ref",
		},
		{
			name:    "missing teardown promotion evidence",
			mutate:  func(app *AppSpec) { app.PromotionEvidence.TeardownReceiptRef = "" },
			wantErr: "promotion teardown receipt ref",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := base
			tc.mutate(&app)
			requireErrorContains(t, validateOSSSupportedSupplyChain(app), tc.wantErr)
		})
	}
}

func TestPolicyPackValidationAdditionalBranches(t *testing.T) {
	catalog := registryCoverageCatalog(t)

	invalidToml := filepath.Join(t.TempDir(), "invalid.toml")
	if err := os.WriteFile(invalidToml, []byte("[app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	requireErrorContains(t, catalog.validatePolicyPack("app", invalidToml), "is invalid")

	emptyPack := filepath.Join(t.TempDir(), "empty.toml")
	if err := os.WriteFile(emptyPack, []byte("title = \"empty\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	requireErrorContains(t, catalog.validatePolicyPack("app", emptyPack), "must contain [app] or [substrate]")

	allowNetwork := filepath.Join(t.TempDir(), "allow.toml")
	if err := os.WriteFile(allowNetwork, []byte(`[app]
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "allow"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	requireErrorContains(t, catalog.validatePolicyPack("app", allowNetwork), "network_default must be deny")

	hostileDocker := filepath.Join(t.TempDir(), "hostile.toml")
	if err := os.WriteFile(hostileDocker, []byte(`[substrate]
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
isolation_mode = "docker-default"
hostile_agent_grade = true
`), 0o644); err != nil {
		t.Fatal(err)
	}
	requireErrorContains(t, catalog.validatePolicyPack("substrate", hostileDocker), "cannot mark docker-default as hostile_agent_grade")

	validAbsolute := filepath.Join(t.TempDir(), "valid.toml")
	if err := os.WriteFile(validAbsolute, []byte(registryCoverageAppPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := catalog.validatePolicyPack("app", validAbsolute); err != nil {
		t.Fatalf("validatePolicyPack valid absolute path: %v", err)
	}
}

func registryCoverageCatalog(t *testing.T) *Catalog {
	t.Helper()
	return testCatalog(t, registryCoverageAppPolicy, registryCoverageSubstratePolicy)
}

func writeLaunchKitParityFixture(t *testing.T, catalog *Catalog) {
	t.Helper()
	app := catalog.Apps[0]
	writeRegistryFile(t, catalog.Root, "registry/launchkit/apps/test-app/helm.app.yaml", `id: test-app
legacy_launchpad_ref: registry/launchpad/apps/test-app.yaml
availability: oss_supported
install:
  strategy: signed_oci
  image: `+app.Install.Image+`
  digest: `+app.Install.Digest+`
policy: policy.default.yaml
secrets: secrets.schema.yaml
mcp_registry: mcp.registry.yaml
runtimes:
  local: runtime.local.yaml
evidence_profile: evidence.profile.yaml
`)
	writeRegistryFile(t, catalog.Root, "registry/launchkit/apps/test-app/runtime.local.yaml", `mode: live
target: local-container
command:
  - test-app
  - run
healthcheck: test-app --version
mcp_registry_ref: mcp.registry.yaml
provider_host_groups: []
egress_proxy_required: false
`)
}

func configureGateway(app *AppSpec) {
	app.RequiredSecrets = []string{"model_gateway"}
	app.ModelGatewayEnv = []string{"OPENAI_API_KEY"}
	app.ModelGateway = ModelGatewaySpec{
		LogicalSecret:           "model_gateway",
		Provider:                "byo",
		Mode:                    "external_byo",
		RawProviderKeyProjected: true,
	}
	app.EvidenceRequirements = append(app.EvidenceRequirements, "model_gateway_broker")
	app.FrameworkContract.ProviderHostGroups = []string{"openai"}
	app.FrameworkContract.EgressProxy = EgressProxyContractSpec{
		Required:             true,
		Image:                "registry.example/egress-proxy@sha256:" + strings.Repeat("d", 64),
		Digest:               "sha256:" + strings.Repeat("d", 64),
		SignatureRef:         "cosign://registry.example/egress-proxy@sha256:" + strings.Repeat("d", 64),
		SBOMRef:              "artifact://sbom-egress-proxy.spdx.json",
		VulnerabilityScanRef: "artifact://grype-egress-proxy.json",
		ReceiptRef:           "receipts/launchpad-egress-proxy.json",
	}
}

func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want substring %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}

func assertMatrixCell(t *testing.T, cells []MatrixCell, appID, substrateID, verdict, reason string, launchable bool) {
	t.Helper()
	for _, cell := range cells {
		if cell.AppID != appID || cell.SubstrateID != substrateID {
			continue
		}
		if cell.Verdict != verdict || cell.Reason != reason || cell.Launchable != launchable {
			t.Fatalf("Matrix cell %s/%s = verdict=%s reason=%s launchable=%v, want %s/%s/%v",
				appID, substrateID, cell.Verdict, cell.Reason, cell.Launchable, verdict, reason, launchable)
		}
		return
	}
	t.Fatalf("Matrix missing cell %s/%s", appID, substrateID)
}

func appIDs(apps []AppSpec) []string {
	ids := make([]string, 0, len(apps))
	for _, app := range apps {
		ids = append(ids, app.ID)
	}
	return ids
}

func withoutString(values []string, target string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func writeRegistryFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeLaunchpadRootMarkers(t *testing.T, root string) {
	t.Helper()
	for _, dir := range []string{
		filepath.Join(root, "registry", "launchpad"),
		filepath.Join(root, "policies", "launchpad"),
		filepath.Join(root, "core"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "core", "go.mod"), []byte("module example.test/root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func withWorkingDir(t *testing.T, dir string, fn func()) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore working dir: %v", err)
		}
	})
	fn()
}

func canonicalPath(t *testing.T, path string) string {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
