package skillpacks

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// Submit the shipped bytes, not a reserialized LoadDir manifest: the latter
// fills defaults and changes the artifact that the first-party manifest pins.
func TestProjectionLifecycleAcceptsShippedFirstPartyBytes(t *testing.T) {
	repo := firstPartyRepoRoot(t)
	for _, pin := range loadKernelFirstPartyTrust().manifest.Packs {
		t.Run(pin.ID, func(t *testing.T) {
			dir := filepath.Join(repo, "registry", "skills", filepath.FromSlash(pin.ID))
			pack, err := LoadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			manifestBytes, err := os.ReadFile(filepath.Join(dir, "skillpack.json"))
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(10000, 0).UTC()
			fixture := newProjectionFixtureWithManifest(t, pack.Manifest.Version, pack.SkillMD, 1, "codex", now, func(manifest *Manifest) {
				*manifest = pack.Manifest
			})
			fixture.artifact.Files["skillpack.json"] = manifestBytes
			fixture.effect.ManifestHash = HashBytes(manifestBytes)
			fixture.effect.ArtifactHash, err = contracts.ComputeSkillProjectionArtifactHash(fixture.effect.ManifestHash, fixture.effect.ContentHash)
			if err != nil {
				t.Fatal(err)
			}
			fixture.effect.PolicyHash = loadKernelFirstPartyTrust().manifest.Policy.SHA256
			fixture.effect.CanonicalRequestHash = ""
			fixture.effect, err = fixture.effect.Seal()
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			verifierCalls := 0
			lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
				verifierCalls++
				if !bytes.Equal(request.ManifestBytes, manifestBytes) || request.Manifest.Status != StatusVerified {
					t.Fatal("configured verifier did not receive the exact shipped manifest")
				}
				return allowProjectionTrust(request)
			}), testProjectionTrustVerifierKey())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lifecycle.Close() })
			lifecycle.clock = func() time.Time { return now }
			result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
			if err != nil {
				t.Fatalf("shipped first-party artifact could not be projected: %v", err)
			}
			if result.Status != "installed" || result.ObservedManifestHash != HashBytes(manifestBytes) ||
				result.ObservedContentHash != fixture.effect.ContentHash || verifierCalls != 1 {
				t.Fatalf("install result=%+v verifier_calls=%d", result, verifierCalls)
			}
			live, err := os.ReadFile(projectionLivePath(root, fixture.effect))
			if err != nil || string(live) != pack.SkillMD {
				t.Fatalf("live projection differs from the shipped instructions: %v", err)
			}
			readEffect := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, "shipped-readback", "shipped-readback-attempt", testHash("6"))
			readback, err := lifecycle.Apply(readEffect, nil, readEffect.ConsumedPermitRef, nil)
			if err != nil || readback.Status != projectionStatusActive || readback.ObservedArtifactHash != fixture.effect.ArtifactHash {
				t.Fatalf("readback result=%+v error=%v", readback, err)
			}
		})
	}
}
