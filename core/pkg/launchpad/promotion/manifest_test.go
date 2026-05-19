package promotion

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestPromoteRequiresCompleteSignedArtifactEvidence(t *testing.T) {
	app := candidateApp("openclaw")
	entry := validArtifact("openclaw")
	refs := validRefs()

	promoted, err := Promote(app, entry, refs)
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if promoted.Availability != registry.AvailabilityOSSSupported {
		t.Fatalf("availability = %s, want oss_supported", promoted.Availability)
	}
	if promoted.Install.Image != entry.Image || promoted.Install.Digest != entry.Digest {
		t.Fatalf("install evidence was not copied from manifest: %#v", promoted.Install)
	}
	if !promoted.Conformance.FullyVerified() {
		t.Fatalf("promoted app must have full conformance: %#v", promoted.Conformance)
	}
	if promoted.PromotionEvidence.LiveE2ERunID != refs.LiveE2ERunID {
		t.Fatalf("promotion evidence not recorded: %#v", promoted.PromotionEvidence)
	}
}

func TestPromoteRejectsMissingEvidenceRefs(t *testing.T) {
	_, err := Promote(candidateApp("openclaw"), validArtifact("openclaw"), EvidenceRefs{LiveE2ERunID: "run"})
	if err == nil || !strings.Contains(err.Error(), "promotion requires") {
		t.Fatalf("Promote() error = %v, want missing refs rejection", err)
	}
}

func TestManifestEvidenceRefsMustTieToWorkflowRun(t *testing.T) {
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, GitHubRunID: "123", Artifacts: []ArtifactEntry{validArtifact("openclaw")}}
	entry := manifest.Artifacts[0]
	entry.ArtifactVerificationRef = "github-actions://123/1/artifact-verification/openclaw"
	entry.LiveE2ERunID = "github-actions://123/1/live-e2e/openclaw"
	entry.EvidencePackRef = "github-actions://123/1/evidencepack/openclaw"
	entry.TeardownReceiptRef = "github-actions://123/1/teardown/openclaw"

	if _, err := manifest.EvidenceRefsFor(entry, EvidenceRefs{}); err != nil {
		t.Fatalf("EvidenceRefsFor: %v", err)
	}
	entry.LiveE2ERunID = "github-actions://999/1/live-e2e/openclaw"
	if _, err := manifest.EvidenceRefsFor(entry, EvidenceRefs{}); err == nil || !strings.Contains(err.Error(), "current workflow run") {
		t.Fatalf("EvidenceRefsFor error = %v, want run binding failure", err)
	}
}

func TestValidateArtifactRejectsUnsupportedOrIncompleteManifest(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ArtifactEntry)
		wantErr string
	}{
		{
			name: "unsupported app",
			mutate: func(entry *ArtifactEntry) {
				entry.AppID = "codex"
			},
			wantErr: "not eligible",
		},
		{
			name: "mutable image",
			mutate: func(entry *ArtifactEntry) {
				entry.Image = "ghcr.io/mindburn-labs/helm-launchpad/openclaw:v2026.5.12"
			},
			wantErr: "immutable",
		},
		{
			name: "bad digest",
			mutate: func(entry *ArtifactEntry) {
				entry.Digest = "sha256:abc"
			},
			wantErr: "sha256:<64",
		},
		{
			name: "missing sbom",
			mutate: func(entry *ArtifactEntry) {
				entry.SBOMRef = ""
			},
			wantErr: "syft SBOM",
		},
		{
			name: "failed scan",
			mutate: func(entry *ArtifactEntry) {
				entry.VulnerabilityScanStatus = "failed"
			},
			wantErr: "scan failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := validArtifact("openclaw")
			tc.mutate(&entry)
			err := ValidateArtifact(entry)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateArtifact() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func candidateApp(id string) registry.AppSpec {
	return registry.AppSpec{
		ID:             id,
		Name:           "Candidate",
		Version:        "v0.0.0",
		Availability:   registry.AvailabilityOSSCandidate,
		Redistribution: "allowed_by_mit_pending_helm_signed_artifact",
		License: registry.LicenseSpec{
			Status: "verified",
			SPDX:   "MIT",
		},
		Install: registry.InstallSpec{
			Strategy: "signed_oci",
			Image:    "ghcr.io/mindburn-labs/helm-launchpad/" + id + ":candidate",
		},
		EvidenceRequirements: []string{"cpi_output"},
		Conformance: registry.ConformanceSpec{
			LicenseVerified:   true,
			PolicyPackPresent: true,
		},
		Metadata: map[string]string{"blocker": "pending signed artifact"},
	}
}

func validArtifact(appID string) ArtifactEntry {
	digest := "sha256:" + strings.Repeat("a", 64)
	return ArtifactEntry{
		AppID:                   appID,
		AppVersion:              "v2026.5.12",
		UpstreamRepo:            "https://github.com/openclaw/openclaw",
		UpstreamRef:             "v2026.5.12",
		UpstreamCommit:          strings.Repeat("b", 40),
		LicenseSPDX:             "MIT",
		LicenseRef:              "https://github.com/openclaw/openclaw/blob/v2026.5.12/LICENSE",
		Redistribution:          "allowed_by_MIT_with_upstream_notice",
		Image:                   "ghcr.io/mindburn-labs/helm-launchpad/" + appID + "@" + digest,
		Digest:                  digest,
		SignatureTool:           "cosign",
		SignatureRef:            "cosign://ghcr.io/mindburn-labs/helm-launchpad/" + appID + "@" + digest,
		SBOMTool:                "syft",
		SBOMRef:                 "artifact://sbom-" + appID + ".spdx.json",
		VulnerabilityScanTool:   "grype",
		VulnerabilityScanRef:    "artifact://grype-" + appID + ".json",
		VulnerabilityScanStatus: "completed",
		ProvenanceRef:           "github-actions://123/1",
	}
}

func validRefs() EvidenceRefs {
	return EvidenceRefs{
		ArtifactVerificationRef: "evidence://artifact-verification/openclaw",
		LiveE2ERunID:            "launch-run-openclaw",
		EvidencePackRef:         "evidence://pack/openclaw-local-container",
		TeardownReceiptRef:      "receipt://teardown/openclaw",
	}
}
