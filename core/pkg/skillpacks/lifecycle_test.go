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

func TestProjectionLifecycleRejectsRetainedArtifactInstallWithoutRollbackPermit(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 30, 0, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	v1 := newProjectionFixture(t, "1.0.0", "retained prompt v1", 1, now)
	v2 := newProjectionFixture(t, "2.0.0", "active prompt v2", 2, now)
	if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
		t.Fatal(err)
	}
	upgrade, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}

	reinstall := actionEffect(t, v1.effect, contracts.SkillProjectionActionInstall, 3, "reinstall-v1", "attempt-reinstall-v1", testHash("d"))
	livePath := projectionLivePath(root, v2.effect)
	statePath := filepath.Join(root, lifecycle.stateRel(v2.effect))
	liveBefore, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := lifecycle.Apply(reinstall, &v1.artifact, reinstall.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRollbackRequired) {
		t.Fatalf("retained artifact reinstall error = %v", err)
	}
	liveAfter, err := os.ReadFile(livePath)
	if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
		t.Fatalf("retained artifact reinstall changed live projection: %q err=%v", liveAfter, err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("retained artifact reinstall changed state: %q err=%v", stateAfter, err)
	}
	state, err := lifecycle.readState(v2.effect, upgrade.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Generations) != 2 {
		t.Fatalf("retained artifact reinstall appended generation: %+v", state.Generations)
	}
}

func TestProjectionLifecycleRequiresConfiguredTrustVerifier(t *testing.T) {
	root := filepath.Join(t.TempDir(), "projection-root")
	if _, err := NewProjectionLifecycle(root, nil); !errors.Is(err, ErrProjectionTrustRejected) {
		t.Fatalf("missing verifier error = %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing verifier created projection root: %v", err)
	}
}

func TestProjectionLifecycleRejectsInvalidTrustWithoutMutation(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 45, 0, 0, time.UTC)
	tests := []struct {
		name   string
		verify projectionTrustVerifierFunc
	}{
		{
			name: "policy binding mismatch",
			verify: func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
				decision, err := allowProjectionTrust(request)
				if err != nil {
					return ProjectionTrustDecision{}, err
				}
				decision.PolicyHash = testHash("c")
				return SealProjectionTrustDecision(decision)
			},
		},
		{
			name: "certification binding mismatch",
			verify: func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
				decision, err := allowProjectionTrust(request)
				if err != nil {
					return ProjectionTrustDecision{}, err
				}
				decision.CertificationRefs = []string{"certification://different"}
				return SealProjectionTrustDecision(decision)
			},
		},
		{
			name: "expired trusted evidence",
			verify: func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
				decision, err := allowProjectionTrust(request)
				if err != nil {
					return ProjectionTrustDecision{}, err
				}
				decision.ExpiresAt = request.EvaluationTime
				return SealProjectionTrustDecision(decision)
			},
		},
		{
			name: "verifier rejects current evidence",
			verify: func(ProjectionTrustRequest) (ProjectionTrustDecision, error) {
				return ProjectionTrustDecision{}, errors.New("signature or policy proof rejected")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			lifecycle, err := NewProjectionLifecycle(root, tt.verify)
			if err != nil {
				t.Fatal(err)
			}
			lifecycle.clock = func() time.Time { return now }
			fixture := newProjectionFixture(t, "1.0.0", "untrusted prompt", 1, now)

			if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) {
				t.Fatalf("invalid trust error = %v", err)
			}
			if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid trust mutated live projection: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, lifecycle.stateRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid trust mutated state: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, lifecycle.generationParentRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid trust retained a generation: %v", err)
			}
		})
	}
}

func TestProjectionLifecycleRejectsBlockedManifestBeforeVerifier(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 50, 0, 0, time.UTC)
	root := t.TempDir()
	verifierCalls := 0
	lifecycle, err := NewProjectionLifecycle(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		verifierCalls++
		return allowProjectionTrust(request)
	}))
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.clock = func() time.Time { return now }
	fixture := newProjectionFixture(t, "1.0.0", "blocked prompt", 1, now)
	var manifest Manifest
	if err := json.Unmarshal(fixture.artifact.Files["skillpack.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Status = StatusBlocked
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.artifact.Files["skillpack.json"] = manifestBytes
	fixture.effect.ManifestHash = HashBytes(manifestBytes)
	fixture.effect.ArtifactHash, err = contracts.ComputeSkillProjectionArtifactHash(fixture.effect.ManifestHash, fixture.effect.ContentHash)
	if err != nil {
		t.Fatal(err)
	}
	fixture.effect.CanonicalRequestHash = ""
	fixture.effect, err = fixture.effect.Seal()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) {
		t.Fatalf("blocked manifest error = %v", err)
	}
	if verifierCalls != 0 {
		t.Fatalf("blocked manifest reached verifier %d times", verifierCalls)
	}
	if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocked manifest mutated live projection: %v", err)
	}
}

func TestProjectionLifecycleReplayRequiresCurrentTrustWithoutMutation(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 55, 0, 0, time.UTC)
	root := t.TempDir()
	verifierCalls := 0
	lifecycle, err := NewProjectionLifecycle(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		verifierCalls++
		if verifierCalls > 1 {
			return ProjectionTrustDecision{}, errors.New("certification was revoked")
		}
		return allowProjectionTrust(request)
	}))
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.clock = func() time.Time { return now }
	fixture := newProjectionFixture(t, "1.0.0", "trust-sensitive replay", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	livePath := projectionLivePath(root, fixture.effect)
	statePath := filepath.Join(root, lifecycle.stateRel(fixture.effect))
	liveBefore, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if replay, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) || replay != (ProjectionLifecycleResult{}) {
		t.Fatalf("untrusted replay result=%+v err=%v", replay, err)
	}
	if installed.TrustVerificationRef == "" || installed.TrustDecisionHash == "" || verifierCalls != 2 {
		t.Fatalf("trust evidence/calls = %+v calls=%d", installed, verifierCalls)
	}
	liveAfter, err := os.ReadFile(livePath)
	if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
		t.Fatalf("untrusted replay mutated live projection: %q err=%v", liveAfter, err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("untrusted replay mutated state: %q err=%v", stateAfter, err)
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

	t.Run("retained generation drift", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		v1 := newProjectionFixture(t, "1.0.0", "safe retained v1", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "safe retained v2", 2, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		upgrade, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil)
		if err != nil {
			t.Fatal(err)
		}
		state, err := lifecycle.readState(v2.effect, upgrade.RelativePath)
		if err != nil {
			t.Fatal(err)
		}
		retained, ok := findProjectionGeneration(state.Generations, 1)
		if !ok {
			t.Fatal("retained generation 1 is missing")
		}
		retainedPath := filepath.Join(root, lifecycle.generationParentRel(v1.effect), projectionGenerationDirName(retained), "SKILL.md")
		if err := os.WriteFile(retainedPath, []byte("tampered retained bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) {
			t.Fatalf("retained drift error = %v", err)
		}
		live, err := os.ReadFile(projectionLivePath(root, v2.effect))
		if err != nil || !reflect.DeepEqual(live, v2.artifact.Files["SKILL.md"]) {
			t.Fatalf("retained drift changed live projection: %q err=%v", live, err)
		}
	})
}

func TestProjectionLifecycleRejectsOversizedManagedReadsWithoutMutation(t *testing.T) {
	now := time.Date(2026, 8, 30, 14, 30, 0, 0, time.UTC)

	t.Run("state", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		v1 := newProjectionFixture(t, "1.0.0", "bounded state v1", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "bounded state v2", 2, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}

		livePath := projectionLivePath(root, v1.effect)
		liveBefore, err := os.ReadFile(livePath)
		if err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(root, lifecycle.stateRel(v1.effect))
		if err := os.Truncate(statePath, maxProjectionLifecycleStateBytes+1); err != nil {
			t.Fatal(err)
		}
		stateBefore, err := os.Stat(statePath)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) || !errors.Is(err, ErrProjectionFileTooLarge) {
			t.Fatalf("oversized state error = %v", err)
		}
		liveAfter, err := os.ReadFile(livePath)
		if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
			t.Fatalf("oversized state changed live projection: %q err=%v", liveAfter, err)
		}
		stateAfter, err := os.Stat(statePath)
		if err != nil || stateAfter.Size() != stateBefore.Size() || !stateAfter.ModTime().Equal(stateBefore.ModTime()) {
			t.Fatalf("oversized state was mutated: before=%+v after=%+v err=%v", stateBefore, stateAfter, err)
		}
	})

	t.Run("retained generation", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		v1 := newProjectionFixture(t, "1.0.0", "bounded retained v1", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "bounded retained v2", 2, now)
		v3 := newProjectionFixture(t, "3.0.0", "bounded retained v3", 3, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		upgrade, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil)
		if err != nil {
			t.Fatal(err)
		}

		state, err := lifecycle.readState(v2.effect, upgrade.RelativePath)
		if err != nil {
			t.Fatal(err)
		}
		retained, ok := findProjectionGeneration(state.Generations, 1)
		if !ok {
			t.Fatal("retained generation 1 is missing")
		}
		statePath := filepath.Join(root, lifecycle.stateRel(v2.effect))
		stateBefore, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		livePath := projectionLivePath(root, v2.effect)
		liveBefore, err := os.ReadFile(livePath)
		if err != nil {
			t.Fatal(err)
		}
		retainedPath := filepath.Join(root, lifecycle.generationParentRel(v1.effect), projectionGenerationDirName(retained), "SKILL.md")
		if err := os.Truncate(retainedPath, maxProjectionArtifactBytes+1); err != nil {
			t.Fatal(err)
		}
		retainedBefore, err := os.Stat(retainedPath)
		if err != nil {
			t.Fatal(err)
		}

		_, err = lifecycle.Apply(v3.effect, &v3.artifact, v3.effect.ConsumedPermitRef, nil)
		if !errors.Is(err, ErrProjectionDrift) || !errors.Is(err, ErrProjectionFileTooLarge) {
			t.Fatalf("oversized retained generation error = %v", err)
		}
		stateAfter, err := os.ReadFile(statePath)
		if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
			t.Fatalf("oversized retained generation changed state: %q err=%v", stateAfter, err)
		}
		liveAfter, err := os.ReadFile(livePath)
		if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
			t.Fatalf("oversized retained generation changed live projection: %q err=%v", liveAfter, err)
		}
		retainedAfter, err := os.Stat(retainedPath)
		if err != nil || retainedAfter.Size() != retainedBefore.Size() || !retainedAfter.ModTime().Equal(retainedBefore.ModTime()) {
			t.Fatalf("oversized retained generation was mutated: before=%+v after=%+v err=%v", retainedBefore, retainedAfter, err)
		}
	})

	t.Run("live artifact", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		v1 := newProjectionFixture(t, "1.0.0", "bounded live v1", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "bounded live v2", 2, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}

		statePath := filepath.Join(root, lifecycle.stateRel(v1.effect))
		stateBefore, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		livePath := projectionLivePath(root, v1.effect)
		if err := os.Truncate(livePath, maxProjectionArtifactBytes+1); err != nil {
			t.Fatal(err)
		}
		liveBefore, err := os.Stat(livePath)
		if err != nil {
			t.Fatal(err)
		}

		_, err = lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil)
		if !errors.Is(err, ErrProjectionDrift) || !errors.Is(err, ErrProjectionFileTooLarge) {
			t.Fatalf("oversized live artifact error = %v", err)
		}
		stateAfter, err := os.ReadFile(statePath)
		if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
			t.Fatalf("oversized live artifact changed state: %q err=%v", stateAfter, err)
		}
		liveAfter, err := os.Stat(livePath)
		if err != nil || liveAfter.Size() != liveBefore.Size() || !liveAfter.ModTime().Equal(liveBefore.ModTime()) {
			t.Fatalf("oversized live artifact was mutated: before=%+v after=%+v err=%v", liveBefore, liveAfter, err)
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

func TestProjectionLifecycleCrossInstanceLockFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	root := t.TempDir()
	first := newProjectionLifecycleForTest(t, root, now)
	second := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "single writer prompt", 1, now)

	release, err := first.acquireRootLock()
	if errors.Is(err, ErrProjectionLockUnsupported) {
		t.Skip("platform has no supported cross-process projection lock")
	}
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			_ = release()
		}
	})

	if _, err := second.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionLockContended) {
		t.Fatalf("contended lifecycle error = %v", err)
	}
	lockPath := filepath.Join(root, filepath.FromSlash(projectionLifecycleLockRel))
	info, err := os.Lstat(lockPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("root-bounded lock = %+v err=%v", info, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	released = true
	if _, err := second.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); err != nil {
		t.Fatalf("apply after lock release: %v", err)
	}
}

func TestProjectionLifecycleRevalidatesAuthorityAfterLock(t *testing.T) {
	now := time.Date(2026, 8, 30, 16, 30, 0, 0, time.UTC)

	t.Run("effect expires while waiting", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		fixture := newProjectionFixture(t, "1.0.0", "expiring prompt", 1, now)
		calls := 0
		lifecycle.clock = func() time.Time {
			calls++
			if calls == 1 {
				return now
			}
			return fixture.effect.ExpiresAt
		}

		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, contracts.ErrSkillProjectionEffectInactive) {
			t.Fatalf("post-lock effect expiry error = %v", err)
		}
		if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired effect mutated live projection: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.stateRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired effect mutated state: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.generationParentRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired effect retained a generation: %v", err)
		}
	})

	t.Run("rollback permit expires while waiting", func(t *testing.T) {
		root := t.TempDir()
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		v1 := newProjectionFixture(t, "1.0.0", "rollback expiry v1", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "rollback expiry v2", 2, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}

		rollback := actionEffect(t, v1.effect, contracts.SkillProjectionActionRollback, 3, "rollback-expiry", "attempt-rollback-expiry", testHash("7"))
		permit := contracts.SkillProjectionRollbackPermit{
			SchemaVersion: contracts.SkillProjectionRollbackPermitSchemaV1, ContractVersion: contracts.SkillProjectionRollbackPermitContractV1,
			PermitRef: testHash("8"), Action: contracts.SkillProjectionActionRollback,
			TenantID: rollback.TenantID, WorkspaceID: rollback.WorkspaceID,
			SkillID: rollback.SkillID, AgentTarget: rollback.AgentTarget,
			FromGeneration: 2, TargetGeneration: 1,
			TargetSkillVersion: rollback.SkillVersion, TargetArtifactHash: rollback.ArtifactHash, TargetPolicyHash: rollback.PolicyHash,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Nonce: strings.Repeat("8", 64),
		}
		var err error
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
		livePath := projectionLivePath(root, v2.effect)
		statePath := filepath.Join(root, lifecycle.stateRel(v2.effect))
		liveBefore, err := os.ReadFile(livePath)
		if err != nil {
			t.Fatal(err)
		}
		stateBefore, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		lifecycle.clock = func() time.Time {
			calls++
			if calls == 1 {
				return now
			}
			return permit.ExpiresAt
		}

		if _, err := lifecycle.Apply(rollback, nil, rollback.ConsumedPermitRef, &permit); !errors.Is(err, contracts.ErrSkillProjectionEffectInactive) {
			t.Fatalf("post-lock rollback expiry error = %v", err)
		}
		liveAfter, err := os.ReadFile(livePath)
		if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
			t.Fatalf("expired rollback mutated live projection: %q err=%v", liveAfter, err)
		}
		stateAfter, err := os.ReadFile(statePath)
		if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
			t.Fatalf("expired rollback mutated state: %q err=%v", stateAfter, err)
		}
	})
}

func TestProjectionDurabilityHelpers(t *testing.T) {
	root := t.TempDir()
	managed, err := ensureManagedDir(root, filepath.Join("tenant", "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if err := syncProjectionDirectory(managed); err != nil {
		t.Fatalf("sync managed directory: %v", err)
	}
	if err := atomicReplaceManaged(root, filepath.Join("tenant", "workspace", "state.json"), []byte("durable")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(managed, "state.json"))
	if err != nil || string(data) != "durable" {
		t.Fatalf("durable publish = %q err=%v", data, err)
	}
	if err := syncProjectionDirectory(filepath.Join(managed, "state.json")); !errors.Is(err, ErrProjectionPathUnsafe) {
		t.Fatalf("non-directory sync error = %v", err)
	}
}

func TestManagedRootRejectsAncestorSwap(t *testing.T) {
	rootPath := t.TempDir()
	outside := t.TempDir()
	managed, err := openManagedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = managed.Close() })

	ancestorRel := filepath.Join("tenant", "workspace")
	if err := ensureManagedDirAt(managed, ancestorRel); err != nil {
		t.Fatal(err)
	}
	ancestorPath := filepath.Join(rootPath, ancestorRel)
	movedPath := filepath.Join(rootPath, "tenant", "workspace-moved")
	if err := os.Rename(ancestorPath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, ancestorPath); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	managedRel := filepath.Join(ancestorRel, "projection.md")
	if err := atomicReplaceManagedAt(managed, managedRel, []byte("must not escape")); !errors.Is(err, ErrProjectionPathUnsafe) {
		t.Fatalf("ancestor-swap write error = %v", err)
	}
	if _, err := readManagedFileAt(managed, managedRel, maxProjectionArtifactBytes); !errors.Is(err, ErrProjectionPathUnsafe) {
		t.Fatalf("ancestor-swap read error = %v", err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("ancestor swap mutated outside path: entries=%v err=%v", entries, err)
	}
	if entries, err := os.ReadDir(movedPath); err != nil || len(entries) != 0 {
		t.Fatalf("ancestor swap mutated original directory: entries=%v err=%v", entries, err)
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
	lifecycle, err := NewProjectionLifecycle(root, projectionTrustVerifierFunc(allowProjectionTrust))
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

type projectionTrustVerifierFunc func(ProjectionTrustRequest) (ProjectionTrustDecision, error)

func (verify projectionTrustVerifierFunc) VerifyProjectionTrust(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
	return verify(request)
}

func allowProjectionTrust(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
	if request.SchemaVersion != ProjectionTrustRequestSchemaV1 ||
		HashBytes(request.ManifestBytes) != request.Effect.ManifestHash ||
		HashBytes(request.ContentBytes) != request.Effect.ContentHash ||
		request.Manifest.ID != request.Effect.SkillID || request.Manifest.Version != request.Effect.SkillVersion ||
		request.Manifest.PolicyRef == "" {
		return ProjectionTrustDecision{}, errors.New("test verifier input mismatch")
	}
	decision := ProjectionTrustDecision{
		SchemaVersion: ProjectionTrustDecisionSchemaV1,
		Verdict:       VerdictAllow,
		Action:        request.Effect.Action,
		TenantID:      request.Effect.TenantID,
		WorkspaceID:   request.Effect.WorkspaceID,
		SkillID:       request.Effect.SkillID,
		SkillVersion:  request.Effect.SkillVersion,
		AgentTarget:   request.Effect.AgentTarget,

		CanonicalRequestHash: request.Effect.CanonicalRequestHash,
		ArtifactHash:         request.Effect.ArtifactHash,
		ContentHash:          request.Effect.ContentHash,
		ManifestHash:         request.Effect.ManifestHash,
		PolicyHash:           request.Effect.PolicyHash,
		SchemaHash:           request.Effect.SchemaHash,

		Publisher:         request.Manifest.Publisher,
		ManifestStatus:    request.Manifest.Status,
		PolicyRef:         request.Manifest.PolicyRef,
		CertificationRefs: append([]string(nil), request.Effect.CertificationRefs...),

		VerifiedAt:      request.EvaluationTime,
		ExpiresAt:       request.EvaluationTime.Add(time.Minute),
		VerificationRef: testHash("e"),
	}
	return SealProjectionTrustDecision(decision)
}
