package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOSSSupportedRequiresSignedArtifactSupplyChainEvidence(t *testing.T) {
	catalog := testCatalog(t, `[app]
id = "test-app"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
`, `[substrate]
id = "local-container"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
isolation_mode = "docker-default"
hostile_agent_grade = false
`)
	app := catalog.Apps[0]

	cases := []struct {
		name    string
		mutate  func(*AppSpec)
		wantErr string
	}{
		{
			name: "missing digest",
			mutate: func(app *AppSpec) {
				app.Install.Digest = ""
				app.SupplyChainEvidence.ArtifactDigest = ""
			},
			wantErr: "signed artifact digest",
		},
		{
			name: "short digest",
			mutate: func(app *AppSpec) {
				app.Install.Digest = "sha256:abc"
				app.SupplyChainEvidence.ArtifactDigest = "sha256:abc"
			},
			wantErr: "sha256:<64 lowercase hex>",
		},
		{
			name: "mutable OCI image tag",
			mutate: func(app *AppSpec) {
				app.Install.Strategy = "signed_oci"
				app.Install.Image = "registry.example/test-app:1.0.0"
			},
			wantErr: "image@sha256",
		},
		{
			name: "external install strategy",
			mutate: func(app *AppSpec) {
				app.Install.Strategy = "byo_tool"
			},
			wantErr: `install strategy "byo_tool"`,
		},
		{
			name: "source install strategy",
			mutate: func(app *AppSpec) {
				app.Install.Strategy = "pinned_source"
			},
			wantErr: `install strategy "pinned_source"`,
		},
		{
			name: "missing cosign",
			mutate: func(app *AppSpec) {
				app.SupplyChainEvidence.SignatureTool = ""
			},
			wantErr: "cosign signature",
		},
		{
			name: "missing syft",
			mutate: func(app *AppSpec) {
				app.SupplyChainEvidence.SBOMTool = "cyclonedx"
			},
			wantErr: "syft SBOM",
		},
		{
			name: "missing grype or trivy",
			mutate: func(app *AppSpec) {
				app.SupplyChainEvidence.VulnerabilityScanTool = "scanner"
			},
			wantErr: "grype or trivy",
		},
		{
			name: "missing evidence requirements",
			mutate: func(app *AppSpec) {
				app.EvidenceRequirements = []string{"cpi_output"}
			},
			wantErr: "mcp_manifest",
		},
		{
			name: "missing promotion evidence",
			mutate: func(app *AppSpec) {
				app.PromotionEvidence.LiveE2ERunID = ""
			},
			wantErr: "promotion live e2e",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalog.Apps[0] = app
			tc.mutate(&catalog.Apps[0])
			err := catalog.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, tc.wantErr)
			}
		})
	}

	catalog.Apps[0] = app
	if err := catalog.Validate(); err != nil {
		t.Fatalf("valid signed supply-chain evidence rejected: %v", err)
	}
}

func TestExternalProprietaryAdaptersMustRemainBYOTool(t *testing.T) {
	catalog := testCatalog(t, `[app]
id = "test-app"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
`, `[substrate]
id = "local-container"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
isolation_mode = "docker-default"
hostile_agent_grade = false
`)
	catalog.Apps[0].Availability = AvailabilityExternalProprietaryAdapter
	catalog.Apps[0].Install.Strategy = "signed_release_artifact"

	err := catalog.Validate()
	if err == nil || !strings.Contains(err.Error(), "must use byo_tool") {
		t.Fatalf("Validate() error = %v, want byo_tool rejection", err)
	}
}

func TestPolicyPackRejectsPermissionBypassAndRecursiveLaunchDefaults(t *testing.T) {
	catalog := testCatalog(t, `[app]
id = "test-app"
network_default = "deny"
`, `[substrate]
id = "local-container"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
isolation_mode = "docker-default"
hostile_agent_grade = false
`)
	catalog.Apps[0].Availability = AvailabilityOSSCandidate

	err := catalog.Validate()
	if err == nil || !strings.Contains(err.Error(), "permission_bypass_forbidden") {
		t.Fatalf("Validate() error = %v, want permission bypass rejection", err)
	}

	catalog = testCatalog(t, `[app]
id = "test-app"
permission_bypass_forbidden = true
network_default = "deny"
`, `[substrate]
id = "local-container"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
isolation_mode = "docker-default"
hostile_agent_grade = false
`)
	catalog.Apps[0].Availability = AvailabilityOSSCandidate

	err = catalog.Validate()
	if err == nil || !strings.Contains(err.Error(), "recursive_launch_forbidden") {
		t.Fatalf("Validate() error = %v, want recursive launch rejection", err)
	}
}

func TestSubstrateIsolationPolicyBlocksDockerDefaultHostileClaim(t *testing.T) {
	catalog := testCatalog(t, `[app]
id = "test-app"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
`, `[substrate]
id = "local-container"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
isolation_mode = "docker-default"
hostile_agent_grade = false
`)
	catalog.Substrates[0].Isolation.HostileAgentGrade = true

	err := catalog.Validate()
	if err == nil || !strings.Contains(err.Error(), "hostile_agent_grade") {
		t.Fatalf("Validate() error = %v, want hostile_agent_grade rejection", err)
	}
}

func TestSubstratePolicyPackRequiresIsolationMode(t *testing.T) {
	catalog := testCatalog(t, `[app]
id = "test-app"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
`, `[substrate]
id = "local-container"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
`)

	err := catalog.Validate()
	if err == nil || !strings.Contains(err.Error(), "isolation_mode") {
		t.Fatalf("Validate() error = %v, want isolation_mode rejection", err)
	}
}

func TestModelGatewayProviderIDsMustExistInCatalog(t *testing.T) {
	catalog := testCatalog(t, `[app]
id = "test-app"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
`, `[substrate]
id = "local-container"
permission_bypass_forbidden = true
recursive_launch_forbidden = true
network_default = "deny"
isolation_mode = "docker-default"
hostile_agent_grade = false
`)
	app := &catalog.Apps[0]
	app.RequiredSecrets = []string{"model_gateway"}
	app.ModelGateway = ModelGatewaySpec{
		LogicalSecret:           "model_gateway",
		Provider:                "byo",
		ProviderIDs:             []string{"openai", "missing-provider"},
		Mode:                    "external_byo",
		RawProviderKeyProjected: true,
	}
	app.ModelGatewayEnv = []string{"OPENAI_API_KEY"}
	app.EvidenceRequirements = append(app.EvidenceRequirements, "model_gateway_broker")

	err := catalog.Validate()
	if err == nil || !strings.Contains(err.Error(), `unknown model_gateway.provider_ids entry "missing-provider"`) {
		t.Fatalf("Validate() error = %v, want unknown provider_ids rejection", err)
	}
}

func TestDiscoverRootUsesExplicitLaunchpadRegistryRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "registry", "launchpad"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "policies", "launchpad"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_LAUNCHPAD_REGISTRY_ROOT", root)
	discovered, err := DiscoverRoot()
	if err != nil {
		t.Fatalf("DiscoverRoot: %v", err)
	}
	if discovered != root {
		t.Fatalf("DiscoverRoot = %s, want %s", discovered, root)
	}
}

func testCatalog(t *testing.T, appPolicy, substratePolicy string) *Catalog {
	t.Helper()
	root := t.TempDir()
	digest := "sha256:" + strings.Repeat("a", 64)
	writePolicy(t, root, "policies/launchpad/apps/test.toml", appPolicy)
	writePolicy(t, root, "policies/launchpad/substrates/local.toml", substratePolicy)
	return &Catalog{
		Root: root,
		Apps: []AppSpec{{
			ID:             "test-app",
			Name:           "Test App",
			Version:        "1.0.0",
			Availability:   AvailabilityOSSSupported,
			Redistribution: "oss",
			Install: InstallSpec{
				Strategy: "signed_oci",
				Image:    "registry.example/test-app@sha256:" + strings.Repeat("a", 64),
				Digest:   digest,
			},
			FilesystemPolicy: PolicyRef{PolicyRef: "policies/launchpad/apps/test.toml"},
			NetworkPolicy:    NetworkPolicy{Default: "deny"},
			MCPPolicy: MCPPolicy{
				UnknownServerPolicy: "quarantine",
				UnknownToolPolicy:   "ESCALATE",
				RequireSchemaPin:    true,
			},
			MCPManifests: []string{"test-app.default"},
			EvidenceRequirements: []string{
				"cpi_output",
				"kernel_verdict",
				"sandbox_grant",
				"launch_receipt",
				"install_receipt",
				"healthcheck_receipt",
				"teardown_receipt",
				"evidence_pack",
				"evidence_graph",
				"artifact_digest",
				"mcp_manifest",
				"cosign_signature",
				"syft_sbom",
				"grype_vulnerability_scan",
			},
			SupplyChainEvidence: SupplyChainEvidenceSpec{
				ArtifactDigest:        digest,
				SignatureTool:         "cosign",
				SignatureRef:          "oci://registry.example/test-app:1.0.0.sig",
				SBOMTool:              "syft",
				SBOMRef:               "oci://registry.example/test-app:1.0.0.sbom",
				VulnerabilityScanTool: "grype",
				VulnerabilityScanRef:  "oci://registry.example/test-app:1.0.0.grype",
			},
			PromotionEvidence: PromotionEvidenceSpec{
				ArtifactVerificationRef: "evidence://artifact-verification",
				LiveE2ERunID:            "launch-run-verified",
				EvidencePackRef:         "evidence://pack/openclaw-local-container",
				TeardownReceiptRef:      "receipt://teardown",
			},
			Conformance: ConformanceSpec{
				LicenseVerified:      true,
				ArtifactVerified:     true,
				PolicyPackPresent:    true,
				SandboxVerified:      true,
				HealthcheckPassing:   true,
				E2EPassing:           true,
				TeardownVerified:     true,
				ReceiptVerified:      true,
				EvidencePackVerified: true,
			},
		}},
		Substrates: []SubstrateSpec{{
			ID:           "local-container",
			Kind:         "local-container",
			PolicyPack:   "policies/launchpad/substrates/local.toml",
			Network:      NetworkPolicy{Default: "deny"},
			Filesystem:   PolicyRef{Mode: "deny_by_default"},
			Availability: "supported",
			Isolation: IsolationPolicy{
				Mode:              "docker-default",
				SupportedModes:    []string{"docker-default", "docker-rootless-userns", "docker-eci", "gvisor", "kata-firecracker", "dedicated-vm"},
				HardenedModes:     []string{"docker-rootless-userns", "docker-eci", "gvisor", "kata-firecracker", "dedicated-vm"},
				HostileAgentGrade: false,
			},
			Capabilities: SubstrateCapabilities{
				IsolationStrength:  "container_baseline",
				NetworkEnforcement: "launch_owned_egress_proxy",
				SecretMode:         "logical_binding_env_projection",
				ReceiptSupport:     "required",
				TeardownProof:      "required",
				Status:             "ga",
				Lifecycle:          []string{"plan", "preflight", "launch", "healthcheck", "execute", "evidence_export", "reconcile", "delete", "post_delete_verify"},
			},
		}},
		MCPManifests: []MCPServerManifest{{
			ID:            "test-app.default",
			AppID:         "test-app",
			ServerID:      "test-app-default",
			Transport:     "stdio",
			Command:       []string{"test-app", "mcp", "serve"},
			PackageDigest: digest,
			SignatureRef:  "oci://registry.example/test-app:1.0.0.sig",
			SchemaHash:    "sha256:" + strings.Repeat("b", 64),
			Tools: []MCPToolManifest{{
				Name:       "test.read",
				SchemaHash: "sha256:" + strings.Repeat("c", 64),
				Effect:     "read",
			}},
		}},
	}
}

func writePolicy(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
