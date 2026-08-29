package skillpacks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestProjectionLifecycleInstallReadbackReplayAndPermitMismatch(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "governed prompt v1", 1, now)

	if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, testHash("f"), nil); err == nil || !strings.Contains(err.Error(), "consumed permit") {
		t.Fatalf("permit mismatch error = %v", err)
	}
	result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "installed" || result.NewArtifactHash != fixture.effect.ArtifactHash ||
		result.ObservedContentHash != fixture.effect.ContentHash || result.ResultHash == "" {
		t.Fatalf("install result = %+v", result)
	}
	live := projectionLivePath(root, fixture.effect)
	data, err := os.ReadFile(live)
	if err != nil || string(data) != "governed prompt v1" {
		t.Fatalf("live projection = %q err=%v", data, err)
	}

	marker := now.Add(-time.Hour)
	if err := os.Chtimes(live, marker, marker); err != nil {
		t.Fatal(err)
	}
	replay, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replay, result) {
		t.Fatalf("replay differs:\nfirst=%+v\nreplay=%+v", result, replay)
	}
	info, err := os.Stat(live)
	if err != nil || !info.ModTime().Equal(marker) {
		t.Fatalf("replay mutated projection: modtime=%v err=%v", info.ModTime(), err)
	}

	readbackEffect := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, "readback-1", "attempt-readback-1", testHash("6"))
	readback, err := lifecycle.Apply(readbackEffect, nil, readbackEffect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if readback.Status != projectionStatusActive || readback.ObservedArtifactHash != fixture.effect.ArtifactHash ||
		readback.ObservedManifestHash != fixture.effect.ManifestHash {
		t.Fatalf("readback result = %+v", readback)
	}
	conflict := readbackEffect
	conflict.AttemptID = "changed-attempt"
	conflict.CanonicalRequestHash = ""
	conflict, err = conflict.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Apply(conflict, nil, conflict.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionReplayConflict) {
		t.Fatalf("idempotency conflict error = %v", err)
	}
}

func TestProjectionLifecycleUpgradeRollbackAndRevoke(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	v1 := newProjectionFixture(t, "1.0.0", "governed prompt v1", 1, now)
	v2 := newProjectionFixture(t, "2.0.0", "governed prompt v2", 2, now)

	if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
		t.Fatal(err)
	}
	upgrade, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if upgrade.Status != "upgraded" || upgrade.PreviousArtifactHash != v1.effect.ArtifactHash ||
		upgrade.NewArtifactHash != v2.effect.ArtifactHash || upgrade.PreviousGeneration != 1 || upgrade.NewGeneration != 2 {
		t.Fatalf("upgrade result = %+v", upgrade)
	}

	rollback := actionEffect(t, v1.effect, contracts.SkillProjectionActionRollback, 3, "rollback-3", "attempt-rollback-3", testHash("7"))
	permit := contracts.SkillProjectionRollbackPermit{
		SchemaVersion:      contracts.SkillProjectionRollbackPermitSchemaV1,
		ContractVersion:    contracts.SkillProjectionRollbackPermitContractV1,
		PermitRef:          testHash("8"),
		Action:             contracts.SkillProjectionActionRollback,
		TenantID:           rollback.TenantID,
		WorkspaceID:        rollback.WorkspaceID,
		SkillID:            rollback.SkillID,
		AgentTarget:        rollback.AgentTarget,
		FromGeneration:     2,
		TargetGeneration:   1,
		TargetSkillVersion: rollback.SkillVersion,
		TargetArtifactHash: rollback.ArtifactHash,
		TargetPolicyHash:   rollback.PolicyHash,
		IssuedAt:           now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Minute),
		Nonce:              strings.Repeat("8", 64),
	}
	permit, err = permit.Seal()
	if err != nil {
		t.Fatal(err)
	}
	rollback.RollbackPermitHash = permit.PermitHash
	rollback.CanonicalRequestHash = ""
	rollback, err = rollback.Seal()
	if err != nil {
		t.Fatal(err)
	}
	tamperedPermit := permit
	tamperedPermit.TargetGeneration = 2
	if _, err := lifecycle.Apply(rollback, nil, rollback.ConsumedPermitRef, &tamperedPermit); err == nil {
		t.Fatal("expected tampered rollback permit to fail")
	}
	rolledBack, err := lifecycle.Apply(rollback, nil, rollback.ConsumedPermitRef, &permit)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Status != "rolled_back" || rolledBack.RestoredFromGeneration != 1 ||
		rolledBack.PreviousArtifactHash != v2.effect.ArtifactHash || rolledBack.NewArtifactHash != v1.effect.ArtifactHash {
		t.Fatalf("rollback result = %+v", rolledBack)
	}
	live := projectionLivePath(root, rollback)
	data, err := os.ReadFile(live)
	if err != nil || !reflect.DeepEqual(data, v1.artifact.Files["SKILL.md"]) {
		t.Fatalf("rollback bytes = %q err=%v", data, err)
	}
	state, err := lifecycle.readState(rollback, rolledBack.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	restored, ok := findProjectionGeneration(state.Generations, 3)
	if !ok {
		t.Fatal("restored generation 3 missing")
	}
	manifestBytes, contentBytes, err := lifecycle.readGeneration(rollback, restored)
	if err != nil || !reflect.DeepEqual(manifestBytes, v1.artifact.Files["skillpack.json"]) ||
		!reflect.DeepEqual(contentBytes, v1.artifact.Files["SKILL.md"]) {
		t.Fatalf("archived rollback is not byte-identical: err=%v", err)
	}

	revoke := actionEffect(t, v1.effect, contracts.SkillProjectionActionRevoke, 4, "revoke-4", "attempt-revoke-4", testHash("9"))
	revoked, err := lifecycle.Apply(revoke, nil, revoke.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != projectionStatusRevoked || revoked.PreviousArtifactHash != v1.effect.ArtifactHash || revoked.NewArtifactHash != "" {
		t.Fatalf("revoke result = %+v", revoked)
	}
	if _, err := os.Stat(live); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked projection still exists: %v", err)
	}
}

func TestProjectionLifecycleFailsClosedOnPathsArtifactsAndDrift(t *testing.T) {
	now := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)

	t.Run("traversal", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		fixture := newProjectionFixture(t, "1.0.0", "safe", 1, now)
		fixture.effect.WorkspaceID = "../escape"
		fixture.effect.CanonicalRequestHash = ""
		if _, err := fixture.effect.Seal(); err == nil {
			t.Fatal("expected traversal identity to fail sealing")
		}
		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); err == nil {
			t.Fatal("expected traversal request to fail")
		}
	})

	t.Run("unsupported artifact", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		fixture := newProjectionFixture(t, "1.0.0", "safe", 1, now)
		fixture.artifact.Files["script.sh"] = []byte("echo no")
		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); err == nil {
			t.Fatal("expected extra artifact file to fail")
		}
		delete(fixture.artifact.Files, "script.sh")
		fixture.artifact.Files["SKILL.md"] = []byte("safe\x00binary")
		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); err == nil {
			t.Fatal("expected binary artifact content to fail")
		}
	})

	t.Run("hash mismatch", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		fixture := newProjectionFixture(t, "1.0.0", "safe", 1, now)
		fixture.artifact.Files["SKILL.md"] = []byte("different")
		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
			t.Fatalf("hash mismatch error = %v", err)
		}
	})

	t.Run("symlink escape", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		fixture := newProjectionFixture(t, "1.0.0", "safe", 1, now)
		workspace := filepath.Join(root, "tenants", fixture.effect.TenantID, "workspaces", fixture.effect.WorkspaceID)
		if err := os.MkdirAll(workspace, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(workspace, ".agents")); err != nil {
			t.Skipf("symlinks unsupported: %v", err)
		}
		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionPathUnsafe) {
			t.Fatalf("symlink error = %v", err)
		}
		if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
			t.Fatalf("outside path mutated: entries=%v err=%v", entries, err)
		}
	})

	t.Run("unmanaged projection", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		fixture := newProjectionFixture(t, "1.0.0", "safe", 1, now)
		live := projectionLivePath(root, fixture.effect)
		if err := os.MkdirAll(filepath.Dir(live), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(live, []byte("operator owned"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrUnmanagedProjection) {
			t.Fatalf("unmanaged error = %v", err)
		}
	})

	t.Run("managed drift", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		v1 := newProjectionFixture(t, "1.0.0", "safe v1", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "safe v2", 2, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		live := projectionLivePath(root, v1.effect)
		if err := os.WriteFile(live, []byte("operator drift"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) {
			t.Fatalf("drift error = %v", err)
		}
		data, err := os.ReadFile(live)
		if err != nil || string(data) != "operator drift" {
			t.Fatalf("drift was overwritten: %q err=%v", data, err)
		}
	})
}

func TestProjectionLifecycleConcurrentReplayIsSingleMutation(t *testing.T) {
	now := time.Date(2026, 8, 30, 15, 0, 0, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "safe concurrent prompt", 1, now)

	const callers = 16
	results := make([]ProjectionLifecycleResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index], errs[index] = lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if !reflect.DeepEqual(results[0], results[i]) {
			t.Fatalf("caller %d result differs", i)
		}
	}
	state, err := lifecycle.readState(fixture.effect, results[0].RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Generations) != 1 || len(state.Replays) != 1 || len(state.Attempts) != 1 {
		t.Fatalf("concurrent replay mutated state more than once: %+v", state)
	}
}

type projectionFixture struct {
	effect   contracts.SkillProjectionEffect
	artifact SkillProjectionArtifact
}

func newProjectionFixture(t *testing.T, version, content string, generation uint64, now time.Time) projectionFixture {
	t.Helper()
	contentBytes := []byte(content)
	manifest := Manifest{
		SchemaVersion: "helm.skillpack.v1", ID: "helm/repo-auditor", Name: "Repo Auditor",
		Version: version, Description: "governed repository auditing prompt", Publisher: "test",
		Status: StatusExperimental, ScopeDefault: ScopeRepo, Risk: "LOW", LicenseSPDX: "MIT",
		SignatureRef:  "signature://repo-auditor/" + version,
		ProvenanceRef: "provenance://repo-auditor/" + version,
		PolicyRef:     "policy://safe/" + version,
		AgentTargets:  []string{"codex"}, PermissionsDoNotGrantTools: true,
		ContentHash: HashBytes(contentBytes),
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestHash := HashBytes(manifestBytes)
	artifactHash, err := contracts.ComputeSkillProjectionArtifactHash(manifestHash, manifest.ContentHash)
	if err != nil {
		t.Fatal(err)
	}
	effect := contracts.SkillProjectionEffect{
		SchemaVersion: contracts.SkillProjectionEffectSchemaV1, ContractVersion: contracts.SkillProjectionEffectContractV1,
		Action:   contracts.SkillProjectionActionInstall,
		TenantID: "tenant-1", WorkspaceID: "workspace-1", SkillID: manifest.ID,
		SkillVersion: version, AgentTarget: "codex",
		ArtifactHash: artifactHash, ContentHash: manifest.ContentHash, ManifestHash: manifestHash,
		PolicyHash: HashBytes([]byte(manifest.PolicyRef)), SchemaHash: contracts.SkillProjectionArtifactSchemaHashV1,
		CertificationRefs: []string{manifest.ProvenanceRef, manifest.SignatureRef},
		ConsumedPermitRef: testHash(string(rune('a' + generation))),
		IdempotencyKey:    "install-" + version, AttemptID: "attempt-install-" + version, Generation: generation,
		ExpiresAt: now.Add(time.Hour), Nonce: strings.Repeat(string(rune('0'+generation)), 64),
		SandboxProfile: contracts.SkillProjectionSandboxProfileV1,
	}
	effect, err = effect.Seal()
	if err != nil {
		t.Fatal(err)
	}
	return projectionFixture{
		effect: effect,
		artifact: SkillProjectionArtifact{Files: map[string][]byte{
			"skillpack.json": manifestBytes,
			"SKILL.md":       contentBytes,
		}},
	}
}

func actionEffect(
	t *testing.T,
	base contracts.SkillProjectionEffect,
	action string,
	generation uint64,
	key, attempt, permit string,
) contracts.SkillProjectionEffect {
	t.Helper()
	base.Action = action
	base.Generation = generation
	base.IdempotencyKey = key
	base.AttemptID = attempt
	base.ConsumedPermitRef = permit
	base.RollbackPermitHash = ""
	base.CanonicalRequestHash = ""
	sealed, err := base.Seal()
	if action == contracts.SkillProjectionActionRollback {
		if err == nil {
			t.Fatal("rollback effect without rollback permit hash unexpectedly sealed")
		}
		return base
	}
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func newProjectionLifecycleForTest(t *testing.T, root string, now time.Time) *ProjectionLifecycle {
	t.Helper()
	lifecycle, err := NewProjectionLifecycle(root)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.clock = func() time.Time { return now }
	return lifecycle
}

func projectionLivePath(root string, effect contracts.SkillProjectionEffect) string {
	return filepath.Join(root, "tenants", effect.TenantID, "workspaces", effect.WorkspaceID,
		".agents", "skills", "helm", "repo-auditor", "SKILL.md")
}

func testHash(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
