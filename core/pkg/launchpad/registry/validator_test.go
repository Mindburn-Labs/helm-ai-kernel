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
			wantErr: "cosign_signature",
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
`)
	catalog.Apps[0].Availability = AvailabilityOSSCandidate

	err = catalog.Validate()
	if err == nil || !strings.Contains(err.Error(), "recursive_launch_forbidden") {
		t.Fatalf("Validate() error = %v, want recursive launch rejection", err)
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
			EvidenceRequirements: []string{
				"cpi_output",
				"kernel_verdict",
				"sandbox_grant",
				"launch_receipt",
				"install_receipt",
				"healthcheck_receipt",
				"teardown_receipt",
				"evidence_pack",
				"artifact_digest",
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
