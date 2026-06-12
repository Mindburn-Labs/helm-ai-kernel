package promotion

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestManifestEntryCarriesTopLevelEgressProxyArtifact(t *testing.T) {
	proxy := validEgressProxyArtifact()
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		EgressProxy:   &proxy,
		Artifacts:     []ArtifactEntry{validArtifact("openclaw")},
	}

	entry, ok := manifest.Entry("openclaw")
	if !ok {
		t.Fatal("manifest entry not found")
	}
	if entry.EgressProxy == nil || entry.EgressProxy.Digest != manifest.EgressProxy.Digest {
		t.Fatalf("entry did not inherit top-level egress proxy artifact: %#v", entry.EgressProxy)
	}
}

func TestManifestHashIgnoresEmbeddedManifestHash(t *testing.T) {
	manifest := Manifest{
		SchemaVersion:    ManifestSchemaVersion,
		GeneratedAt:      "2026-06-12T00:00:00Z",
		GitHubRunID:      "123",
		GitHubRunAttempt: "1",
		SourceSHA:        strings.Repeat("d", 40),
		SourceTreeSHA256: "sha256:" + strings.Repeat("e", 64),
		WorkflowRef:      "Mindburn-Labs/helm-ai-kernel/.github/workflows/launchpad-artifacts.yml@refs/heads/main",
		Artifacts:        []ArtifactEntry{validArtifact("openclaw")},
		EgressProxy:      ptr(validEgressProxyArtifact()),
	}
	hash, err := manifest.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	manifest.ManifestHash = hash
	hashWithEmbeddedValue, err := manifest.Hash()
	if err != nil {
		t.Fatalf("Hash with embedded value: %v", err)
	}
	if hash != hashWithEmbeddedValue {
		t.Fatalf("manifest hash changed after embedding hash: %s != %s", hash, hashWithEmbeddedValue)
	}
}

func TestPromoteBindsRunBuiltEgressProxyArtifact(t *testing.T) {
	app := candidateApp("openclaw")
	app.FrameworkContract.EgressProxy = registry.EgressProxyContractSpec{
		Required:   true,
		Image:      "ghcr.io/mindburn-labs/helm-launchpad/egress-proxy@sha256:" + strings.Repeat("d", 64),
		Digest:     "sha256:" + strings.Repeat("d", 64),
		ReceiptRef: "receipts/launchpad-egress-proxy.json",
	}
	entry := validArtifact("openclaw")
	proxy := validEgressProxyArtifact()
	entry.EgressProxy = &proxy

	promoted, err := Promote(app, entry, validRefs())
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if promoted.FrameworkContract.EgressProxy.Image != proxy.Image {
		t.Fatalf("egress proxy image = %q, want %q", promoted.FrameworkContract.EgressProxy.Image, proxy.Image)
	}
	if promoted.FrameworkContract.EgressProxy.Digest != proxy.Digest {
		t.Fatalf("egress proxy digest = %q, want %q", promoted.FrameworkContract.EgressProxy.Digest, proxy.Digest)
	}
	if promoted.FrameworkContract.EgressProxy.SignatureRef != proxy.SignatureRef {
		t.Fatalf("egress proxy signature ref not bound from manifest: %#v", promoted.FrameworkContract.EgressProxy)
	}
}

func TestSyncDerivedWritesImageLockAndHelmValues(t *testing.T) {
	root := t.TempDir()
	apps := []registry.AppSpec{
		promotedAppForDerived(t, "openclaw"),
		promotedAppForDerived(t, "hermes"),
	}
	writeDerivedFixture(t, root, "sha256:"+strings.Repeat("0", 64), false)

	if err := SyncDerived(root, apps); err != nil {
		t.Fatalf("SyncDerived: %v", err)
	}
	if drifts := CheckDerived(root, apps); len(drifts) != 0 {
		t.Fatalf("CheckDerived drifts after sync: %v", drifts)
	}
	data, err := os.ReadFile(filepath.Join(root, "registry", "launchpad", "image-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock ImageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatalf("image lock json: %v", err)
	}
	if lock.SchemaVersion != ImageLockSchemaVersion || len(lock.Images) != 3 {
		t.Fatalf("unexpected image lock: %#v", lock)
	}
	values, err := os.ReadFile(filepath.Join(root, "deploy", "helm-chart", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range apps {
		if !strings.Contains(string(values), app.Install.Digest) {
			t.Fatalf("values.yaml missing digest for %s: %s", app.ID, values)
		}
	}
}

func TestCheckDerivedDetectsImageLockValuesAndSmokeDrift(t *testing.T) {
	root := t.TempDir()
	apps := []registry.AppSpec{
		promotedAppForDerived(t, "openclaw"),
		promotedAppForDerived(t, "hermes"),
	}
	writeDerivedFixture(t, root, "sha256:"+strings.Repeat("0", 64), true)
	if err := os.MkdirAll(filepath.Join(root, "registry", "launchpad"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "registry", "launchpad", "image-lock.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	drifts := CheckDerived(root, apps)
	if len(drifts) < 3 {
		t.Fatalf("CheckDerived drifts = %v, want image-lock, values, and smoke drift", drifts)
	}
	joined := strings.Join(drifts, "\n")
	for _, want := range []string{"image-lock.json drift", "helm values drift", "hard-coded launchpad image digest"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("CheckDerived missing %q in %v", want, drifts)
		}
	}
}

func TestPromoteRequiresEgressProxyArtifactWhenContractRequiresIt(t *testing.T) {
	app := candidateApp("openclaw")
	app.FrameworkContract.EgressProxy = registry.EgressProxyContractSpec{Required: true}

	_, err := Promote(app, validArtifact("openclaw"), validRefs())
	if err == nil || !strings.Contains(err.Error(), "signed egress proxy artifact") {
		t.Fatalf("Promote() error = %v, want egress proxy artifact requirement", err)
	}
}

func TestOpenCodeAndKiloCodeAreEligibleOnlyWithCompleteEvidence(t *testing.T) {
	for _, appID := range []string{"opencode", "kilocode"} {
		t.Run(appID, func(t *testing.T) {
			promoted, err := Promote(candidateApp(appID), validArtifact(appID), validRefsFor(appID))
			if err != nil {
				t.Fatalf("Promote(%s): %v", appID, err)
			}
			if promoted.Availability != registry.AvailabilityOSSSupported || !promoted.Conformance.FullyVerified() {
				t.Fatalf("promotion did not produce supported fully verified app: %#v", promoted)
			}
		})
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
		SourceSHA:               strings.Repeat("b", 40),
		SourceTreeSHA256:        "sha256:" + strings.Repeat("d", 64),
		WorkflowRef:             "Mindburn-Labs/helm-ai-kernel/.github/workflows/launchpad-artifacts.yml@refs/heads/main",
		SubjectName:             "ghcr.io/mindburn-labs/helm-launchpad/" + appID,
		SubjectDigest:           digest,
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

func validEgressProxyArtifact() EgressProxy {
	digest := "sha256:" + strings.Repeat("c", 64)
	return EgressProxy{
		Component:               "egress-proxy",
		SourceSHA:               strings.Repeat("e", 40),
		SourceTreeSHA256:        "sha256:" + strings.Repeat("f", 64),
		WorkflowRef:             "Mindburn-Labs/helm-ai-kernel/.github/workflows/launchpad-artifacts.yml@refs/heads/main",
		SubjectName:             "ghcr.io/mindburn-labs/helm-launchpad/egress-proxy",
		SubjectDigest:           digest,
		Image:                   "ghcr.io/mindburn-labs/helm-launchpad/egress-proxy@" + digest,
		Digest:                  digest,
		SignatureTool:           "cosign",
		SignatureRef:            "cosign://ghcr.io/mindburn-labs/helm-launchpad/egress-proxy@" + digest,
		SBOMTool:                "syft",
		SBOMRef:                 "artifact://sbom-egress-proxy.spdx.json",
		VulnerabilityScanTool:   "grype",
		VulnerabilityScanRef:    "artifact://grype-egress-proxy.json",
		VulnerabilityScanStatus: "completed",
		ProvenanceRef:           "github-actions://123/1",
	}
}

func promotedAppForDerived(t *testing.T, appID string) registry.AppSpec {
	t.Helper()
	app := candidateApp(appID)
	app.FrameworkContract.EgressProxy = registry.EgressProxyContractSpec{Required: true}
	entry := validArtifact(appID)
	proxy := validEgressProxyArtifact()
	entry.EgressProxy = &proxy
	promoted, err := Promote(app, entry, validRefsFor(appID))
	if err != nil {
		t.Fatalf("Promote(%s): %v", appID, err)
	}
	return promoted
}

func writeDerivedFixture(t *testing.T, root, digest string, hardCodedSmoke bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "deploy", "helm-chart"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "scripts", "ci"), 0o755); err != nil {
		t.Fatal(err)
	}
	values := `launchpadApps:
  openclaw:
    image:
      repository: "ghcr.io/mindburn-labs/helm-launchpad/openclaw"
      digest: "` + digest + `"
    egressSidecar:
      image:
        repository: "ghcr.io/mindburn-labs/helm-launchpad/egress-proxy"
        digest: "` + digest + `"
  hermes:
    image:
      repository: "ghcr.io/mindburn-labs/helm-launchpad/hermes"
      digest: "` + digest + `"
    egressSidecar:
      image:
        repository: "ghcr.io/mindburn-labs/helm-launchpad/egress-proxy"
        digest: "` + digest + `"
`
	if err := os.WriteFile(filepath.Join(root, "deploy", "helm-chart", "values.yaml"), []byte(values), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/usr/bin/env bash\nIMAGE_LOCK=\"${ROOT}/registry/launchpad/image-lock.json\"\n"
	if hardCodedSmoke {
		script = "#!/usr/bin/env bash\ndocker pull ghcr.io/mindburn-labs/helm-launchpad/openclaw@" + digest + "\n"
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "ci", "launchpad_k8s_smoke.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func ptr[T any](value T) *T {
	return &value
}

func validRefs() EvidenceRefs {
	return validRefsFor("openclaw")
}

func validRefsFor(appID string) EvidenceRefs {
	return EvidenceRefs{
		ArtifactVerificationRef: "evidence://artifact-verification/" + appID,
		LiveE2ERunID:            "launch-run-" + appID,
		EvidencePackRef:         "evidence://pack/" + appID + "-local-container",
		TeardownReceiptRef:      "receipt://teardown/" + appID,
	}
}
