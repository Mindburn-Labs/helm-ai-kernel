package promotionpermit

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestInputCanonicalHashBindsEveryPromotionField(t *testing.T) {
	input := validInput()
	canonical, err := input.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}
	want := `{"apps_empty_intent":false,"apps_overlay_hash":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","apps_overlay_ref":"gitops-apps@sha256:ccc","platform_overlay_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform_overlay_ref":"gitops-platform@sha256:bbb","protected_environment":"production","release_manifest_generation":23,"release_manifest_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_manifest_ref":"integration-mindburn-platform@sha256:aaa","release_manifest_status":"production_candidate","schema":"helm.production-promotion-input/v1","target_environment":"production"}`
	if string(canonical) != want {
		t.Fatalf("CanonicalBytes() = %s\nwant = %s", canonical, want)
	}
	hash, err := input.Hash()
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if wantHash := canonicalize.ComputeArtifactHash([]byte(want)); hash != wantHash {
		t.Fatalf("Hash() = %s, want %s", hash, wantHash)
	}
}

func TestInputRejectsInvalidPromotionClaims(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Input)
		want   string
	}{
		{name: "wrong environment", mutate: func(input *Input) { input.TargetEnvironment = "staging" }, want: "target_environment"},
		{name: "zero generation", mutate: func(input *Input) { input.ReleaseManifestGeneration = 0 }, want: "generation"},
		{name: "unsafe generation", mutate: func(input *Input) { input.ReleaseManifestGeneration = maxJCSSafeInteger + 1 }, want: "JCS-safe"},
		{name: "unknown status", mutate: func(input *Input) { input.ReleaseManifestStatus = "readiness_freeze" }, want: "status"},
		{name: "uppercase hash", mutate: func(input *Input) { input.AppsOverlayHash = "sha256:" + strings.Repeat("A", 64) }, want: "apps_overlay_hash"},
		{name: "noncanonical protected environment", mutate: func(input *Input) { input.ProtectedEnvironment = "Production Env" }, want: "protected_environment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validInput()
			test.mutate(&input)
			if err := input.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestInputVerifiesExactArtifactBytes(t *testing.T) {
	release := []byte("metadata:\n  generation: 23\nspec:\n  status: production_candidate\n  promotion:\n    target_environment: production\n")
	platform := []byte("spec:\n  production_promotion:\n    release_manifest_generation: 23\n    protected_environment: production\n")
	apps := []byte("spec:\n  production_promotion:\n    release_manifest_generation: 23\n    protected_environment: production\n  applications:\n    - name: control-plane\n")
	input := validInput()
	input.ReleaseManifestHash = canonicalize.ComputeArtifactHash(release)
	input.PlatformOverlayHash = canonicalize.ComputeArtifactHash(platform)
	input.AppsOverlayHash = canonicalize.ComputeArtifactHash(apps)
	if err := input.VerifyArtifactBytes(release, platform, apps); err != nil {
		t.Fatalf("VerifyArtifactBytes() error = %v", err)
	}
	if err := input.VerifyArtifactBytes(release, platform, append(apps, '!')); err == nil || !strings.Contains(err.Error(), "apps overlay") {
		t.Fatalf("VerifyArtifactBytes() error = %v, want apps overlay mismatch", err)
	}
}

func TestInputRequiresExplicitAppsEmptyIntent(t *testing.T) {
	release := []byte("metadata:\n  generation: 23\nspec:\n  status: production_candidate\n  promotion:\n    target_environment: production\n")
	platform := []byte("spec:\n  production_promotion:\n    release_manifest_generation: 23\n    protected_environment: production\n")
	apps := []byte("spec:\n  production_promotion:\n    release_manifest_generation: 23\n    protected_environment: production\n  applications: []\n")
	input := validInput()
	input.ReleaseManifestHash = canonicalize.ComputeArtifactHash(release)
	input.PlatformOverlayHash = canonicalize.ComputeArtifactHash(platform)
	input.AppsOverlayHash = canonicalize.ComputeArtifactHash(apps)
	if err := input.VerifyArtifactBytes(release, platform, apps); err == nil || !strings.Contains(err.Error(), "apps_empty_intent") {
		t.Fatalf("VerifyArtifactBytes() error = %v, want explicit intent mismatch", err)
	}
	input.AppsEmptyIntent = true
	if err := input.VerifyArtifactBytes(release, platform, apps); err != nil {
		t.Fatalf("VerifyArtifactBytes() with explicit empty intent error = %v", err)
	}
}

func TestInputBindsExistingLaunchPromotionFields(t *testing.T) {
	input := validInput()
	hash, err := input.Hash()
	if err != nil {
		t.Fatal(err)
	}
	envelope := contracts.LaunchEffectAuthorizationEnvelope{
		EffectID: contracts.EffectTypeDeployProductionActivate,
		Input: map[string]any{
			"promotion_permit_ref":  "promotion-input:23",
			"promotion_permit_hash": hash,
			"release_manifest_ref":  input.ReleaseManifestRef,
			"release_manifest_hash": input.ReleaseManifestHash,
		},
	}
	if err := input.VerifyEnvelopeBinding(envelope, "promotion-input:23"); err != nil {
		t.Fatalf("VerifyEnvelopeBinding() error = %v", err)
	}
	envelope.Input["promotion_permit_hash"] = "sha256:" + strings.Repeat("f", 64)
	if err := input.VerifyEnvelopeBinding(envelope, "promotion-input:23"); err == nil || !strings.Contains(err.Error(), "promotion_permit_hash") {
		t.Fatalf("VerifyEnvelopeBinding() error = %v, want promotion hash mismatch", err)
	}
}

func validInput() Input {
	return Input{
		Schema:                    InputSchemaV1,
		TargetEnvironment:         "production",
		ReleaseManifestRef:        "integration-mindburn-platform@sha256:aaa",
		ReleaseManifestGeneration: 23,
		ReleaseManifestHash:       "sha256:" + strings.Repeat("a", 64),
		ReleaseManifestStatus:     ReleaseManifestStatusProductionCandidate,
		PlatformOverlayRef:        "gitops-platform@sha256:bbb",
		PlatformOverlayHash:       "sha256:" + strings.Repeat("b", 64),
		AppsOverlayRef:            "gitops-apps@sha256:ccc",
		AppsOverlayHash:           "sha256:" + strings.Repeat("c", 64),
		ProtectedEnvironment:      "production",
		AppsEmptyIntent:           false,
	}
}
