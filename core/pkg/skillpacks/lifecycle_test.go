package skillpacks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if revoked.TrustDecisionAction != contracts.SkillProjectionActionRollback ||
		revoked.TrustDecisionCanonical != rollback.CanonicalRequestHash ||
		revoked.TrustDecisionHash != rolledBack.TrustDecisionHash {
		t.Fatalf("revoke did not cite current rollback receipt: revoked=%+v rollback=%+v", revoked, rolledBack)
	}
	replayedRevoke, err := lifecycle.Apply(revoke, nil, revoke.ConsumedPermitRef, nil)
	if err != nil || !reflect.DeepEqual(replayedRevoke, revoked) {
		t.Fatalf("rollback-backed revoke replay=%+v err=%v", replayedRevoke, err)
	}
	if _, err := os.Stat(live); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked projection still exists: %v", err)
	}
}

func TestProjectionLifecycleRevokeUsesAuthenticatedStoredTrustAfterWithdrawal(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 20, 0, 0, time.UTC)
	root := t.TempDir()
	verifierCalls := 0
	lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		verifierCalls++
		if verifierCalls > 1 {
			return ProjectionTrustDecision{}, errors.New("publisher trust withdrawn")
		}
		return allowProjectionTrust(request)
	}), testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lifecycle.Close() })
	lifecycle.clock = func() time.Time { return now }
	fixture := newProjectionFixture(t, "1.0.0", "withdrawn prompt", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	revoke := actionEffect(t, fixture.effect, contracts.SkillProjectionActionRevoke, 2, "withdrawn-revoke", "attempt-withdrawn-revoke", testHash("9"))
	revoked, err := lifecycle.Apply(revoke, nil, revoke.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if verifierCalls != 1 || revoked.Action != contracts.SkillProjectionActionRevoke ||
		revoked.TrustDecisionAction != contracts.SkillProjectionActionInstall ||
		revoked.TrustDecisionCanonical != fixture.effect.CanonicalRequestHash ||
		revoked.TrustDecisionHash != installed.TrustDecisionHash ||
		revoked.TrustDecisionSignature != installed.TrustDecisionSignature {
		t.Fatalf("stored revoke trust result=%+v verifier_calls=%d installed=%+v", revoked, verifierCalls, installed)
	}
	replay, err := lifecycle.Apply(revoke, nil, revoke.ConsumedPermitRef, nil)
	if err != nil || !reflect.DeepEqual(replay, revoked) || verifierCalls != 1 {
		t.Fatalf("stored revoke replay=%+v err=%v verifier_calls=%d", replay, err, verifierCalls)
	}
	if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("withdrawn revoke retained live projection: %v", err)
	}
	readback := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 2, "withdrawn-readback", "attempt-withdrawn-readback", testHash("8"))
	if result, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) || result != (ProjectionLifecycleResult{}) || verifierCalls != 2 {
		t.Fatalf("withdrawn readback result=%+v err=%v verifier_calls=%d", result, err, verifierCalls)
	}
}

func TestProjectionLifecycleExpiredRevocationAuthorityRestoresLiveState(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 25, 0, 0, time.UTC)
	currentTime := now
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	lifecycle.clock = func() time.Time { return currentTime }
	fixture := newProjectionFixture(t, "1.0.0", "expiry revoke prompt", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, lifecycle.stateRel(fixture.effect))
	stateBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	liveBefore, err := os.ReadFile(projectionLivePath(root, fixture.effect))
	if err != nil {
		t.Fatal(err)
	}
	revoke := actionEffect(t, fixture.effect, contracts.SkillProjectionActionRevoke, 2, "expiry-revoke", "attempt-expiry-revoke", testHash("9"))
	lifecycle.mutationHook = func(stage string) error {
		if stage == projectionMutationAfterLive {
			currentTime = revoke.ExpiresAt
		}
		return nil
	}
	if result, err := lifecycle.Apply(revoke, nil, revoke.ConsumedPermitRef, nil); err == nil || result != (ProjectionLifecycleResult{}) {
		t.Fatalf("expired revoke result=%+v err=%v", result, err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("expired revoke changed state: err=%v", err)
	}
	liveAfter, err := os.ReadFile(projectionLivePath(root, fixture.effect))
	if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
		t.Fatalf("expired revoke did not restore live bytes: %q err=%v", liveAfter, err)
	}
	if _, err := os.Stat(filepath.Join(root, lifecycle.journalRel(revoke))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired revoke retained journal: %v", err)
	}
	state, err := lifecycle.readState(fixture.effect, installed.RelativePath)
	if err != nil || state.Status != projectionStatusActive || state.Generation != installed.NewGeneration {
		t.Fatalf("expired revoke restored state=%+v err=%v", state, err)
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
	if _, err := NewProjectionLifecycleWithVerifierKey(root, nil, testProjectionTrustVerifierKey()); !errors.Is(err, ErrProjectionTrustRejected) {
		t.Fatalf("missing verifier error = %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing verifier created projection root: %v", err)
	}
}

func TestProjectionLifecycleLegacyConstructorFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "projection-root")
	if _, err := NewProjectionLifecycle(root, projectionTrustVerifierFunc(allowProjectionTrust)); !errors.Is(err, ErrProjectionTrustRejected) {
		t.Fatalf("legacy constructor error = %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy constructor created projection root: %v", err)
	}
}

func TestProjectionLifecycleRequiresPinnedTrustVerifierKey(t *testing.T) {
	tests := []struct {
		name string
		key  ProjectionTrustVerifierKey
	}{
		{name: "missing verifier identity", key: ProjectionTrustVerifierKey{KeyID: "key-v1", HMACKey: []byte(strings.Repeat("k", 32))}},
		{name: "missing key identity", key: ProjectionTrustVerifierKey{VerifierID: "verifier", HMACKey: []byte(strings.Repeat("k", 32))}},
		{name: "short key", key: ProjectionTrustVerifierKey{VerifierID: "verifier", KeyID: "key-v1", HMACKey: []byte("too-short")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "projection-root")
			if _, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(allowProjectionTrust), tt.key); !errors.Is(err, ErrProjectionTrustRejected) {
				t.Fatalf("invalid pinned verifier key error = %v", err)
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid pinned verifier key created projection root: %v", err)
			}
		})
	}
}

func TestProjectionLifecycleVerifierKeyRotationIsExplicit(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 44, 0, 0, time.UTC)
	root := t.TempDir()
	oldLifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "key-rotation prompt", 1, now)
	if _, err := oldLifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); err != nil {
		t.Fatal(err)
	}
	if err := oldLifecycle.Close(); err != nil {
		t.Fatal(err)
	}

	currentKey := rotatedProjectionTrustVerifierKey()
	currentVerifier := projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		return allowProjectionTrustWithKey(request, currentKey)
	})
	rotated, err := NewProjectionLifecycleWithVerifierKeyring(root, currentVerifier, ProjectionTrustVerifierKeyring{
		Current: currentKey, Historical: []ProjectionTrustVerifierKey{testProjectionTrustVerifierKey()},
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated.clock = func() time.Time { return now }
	readback := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, "read-after-key-rotation", "attempt-read-after-key-rotation", testHash("7"))
	result, err := rotated.Apply(readback, nil, readback.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.TrustKeyID != currentKey.KeyID {
		t.Fatalf("rotated result key = %q", result.TrustKeyID)
	}
	state, err := rotated.readState(readback, result.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.StateKeyID != currentKey.KeyID || state.Generations[0].TrustKeyID != testProjectionTrustVerifierKey().KeyID {
		t.Fatalf("rotated state keys = state:%q generation:%q", state.StateKeyID, state.Generations[0].TrustKeyID)
	}
	if err := rotated.Close(); err != nil {
		t.Fatal(err)
	}

	revokedHistory, err := NewProjectionLifecycleWithVerifierKey(root, currentVerifier, currentKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = revokedHistory.Close() })
	revokedHistory.clock = func() time.Time { return now }
	secondReadback := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, "read-with-revoked-history", "attempt-read-with-revoked-history", testHash("8"))
	if result, err := revokedHistory.Apply(secondReadback, nil, secondReadback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) || result != (ProjectionLifecycleResult{}) {
		t.Fatalf("revoked historical key result=%+v err=%v", result, err)
	}
}

func TestProjectionLifecycleRecoveryJournalSurvivesExplicitKeyRotation(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 44, 30, 0, time.UTC)
	root := t.TempDir()
	oldLifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "key-rotated recovery journal", 1, now)
	oldLifecycle.mutationHook = func(stage string) error {
		if stage == projectionMutationAfterJournal {
			return errors.New("retain old-key journal")
		}
		return nil
	}
	if _, err := oldLifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) {
		t.Fatalf("prepare old-key journal: %v", err)
	}
	if err := oldLifecycle.Close(); err != nil {
		t.Fatal(err)
	}

	currentKey := rotatedProjectionTrustVerifierKey()
	verifierCalls := 0
	rotated, err := NewProjectionLifecycleWithVerifierKeyring(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		verifierCalls++
		return allowProjectionTrustWithKey(request, currentKey)
	}), ProjectionTrustVerifierKeyring{
		Current: currentKey, Historical: []ProjectionTrustVerifierKey{testProjectionTrustVerifierKey()},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rotated.Close() })
	rotated.clock = func() time.Time { return now }
	result, err := rotated.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "installed" || result.TrustKeyID != testProjectionTrustVerifierKey().KeyID || verifierCalls == 0 {
		t.Fatalf("rotated recovery exact result=%+v verifier_calls=%d", result, verifierCalls)
	}
	if _, err := os.Stat(filepath.Join(root, rotated.journalRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rotated recovery retained journal: %v", err)
	}
	state, err := rotated.readState(fixture.effect, result.RelativePath)
	if err != nil || state.StateKeyID != testProjectionTrustVerifierKey().KeyID {
		t.Fatalf("rotated recovery state=%+v err=%v", state, err)
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
				return SignProjectionTrustDecision(decision, testProjectionTrustVerifierKey())
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
				return SignProjectionTrustDecision(decision, testProjectionTrustVerifierKey())
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
				return SignProjectionTrustDecision(decision, testProjectionTrustVerifierKey())
			},
		},
		{
			name: "tampered verifier signature",
			verify: func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
				decision, err := allowProjectionTrust(request)
				if err != nil {
					return ProjectionTrustDecision{}, err
				}
				decision.Signature = tamperProjectionTrustSignature(decision.Signature)
				return decision, nil
			},
		},
		{
			name: "wrong verifier key",
			verify: func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
				decision, err := allowProjectionTrust(request)
				if err != nil {
					return ProjectionTrustDecision{}, err
				}
				return SignProjectionTrustDecision(decision, otherProjectionTrustVerifierKey())
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
			lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, tt.verify, testProjectionTrustVerifierKey())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lifecycle.Close() })
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
	lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		verifierCalls++
		return allowProjectionTrust(request)
	}), testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lifecycle.Close() })
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
	lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		verifierCalls++
		if verifierCalls > 1 {
			return ProjectionTrustDecision{}, errors.New("certification was revoked")
		}
		return allowProjectionTrust(request)
	}), testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lifecycle.Close() })
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

func TestProjectionLifecycleBoundsVerifierAndKeepsEmergencyRevokeAvailable(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 55, 15, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "bounded verifier prompt", 1, now)
	if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); err != nil {
		t.Fatal(err)
	}
	lifecycle.verifierTimeout = 20 * time.Millisecond
	started := make(chan struct{})
	release := make(chan struct{})
	callbackDone := make(chan struct{})
	verifierCalls := 0
	lifecycle.verifier = projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		verifierCalls++
		close(started)
		defer close(callbackDone)
		<-release
		return allowProjectionTrust(request)
	})
	readback := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, "bounded-readback", "attempt-bounded-readback", testHash("7"))
	type applyOutcome struct {
		result ProjectionLifecycleResult
		err    error
	}
	firstDone := make(chan applyOutcome, 1)
	go func() {
		result, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil)
		firstDone <- applyOutcome{result: result, err: err}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("legacy verifier did not start")
	}
	select {
	case outcome := <-firstDone:
		if !errors.Is(outcome.err, ErrProjectionTrustRejected) || !errors.Is(outcome.err, context.DeadlineExceeded) ||
			outcome.result != (ProjectionLifecycleResult{}) {
			t.Fatalf("bounded verifier outcome=%+v", outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy verifier retained lifecycle lock past deadline")
	}
	secondReadback := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, "busy-readback", "attempt-busy-readback", testHash("6"))
	if result, err := lifecycle.Apply(secondReadback, nil, secondReadback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) || result != (ProjectionLifecycleResult{}) || verifierCalls != 1 {
		t.Fatalf("busy verifier result=%+v err=%v calls=%d", result, err, verifierCalls)
	}
	revoke := actionEffect(t, fixture.effect, contracts.SkillProjectionActionRevoke, 2, "bounded-revoke", "attempt-bounded-revoke", testHash("5"))
	if result, err := lifecycle.Apply(revoke, nil, revoke.ConsumedPermitRef, nil); err != nil || result.Status != projectionStatusRevoked || verifierCalls != 1 {
		t.Fatalf("emergency revoke result=%+v err=%v calls=%d", result, err, verifierCalls)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- lifecycle.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited for abandoned legacy verifier")
	}
	close(release)
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("released legacy verifier did not exit")
	}
	if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("emergency revoke retained live projection: %v", err)
	}
}

func TestProjectionLifecycleCloseCancelsContextVerifier(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 55, 30, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "cancel verifier prompt", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, lifecycle.stateRel(fixture.effect))
	stateBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.verifierTimeout = time.Minute
	started := make(chan struct{})
	observedCancellation := make(chan error, 1)
	lifecycle.verifier = projectionTrustContextVerifierFunc(func(ctx context.Context, _ ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		close(started)
		<-ctx.Done()
		observedCancellation <- ctx.Err()
		return ProjectionTrustDecision{}, ctx.Err()
	})
	readback := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, installed.NewGeneration, "cancel-readback", "attempt-cancel-readback", testHash("4"))
	applyDone := make(chan error, 1)
	go func() {
		_, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil)
		applyDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("context verifier did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- lifecycle.Close() }()
	select {
	case err := <-applyDone:
		if !errors.Is(err, ErrProjectionTrustRejected) || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled verifier apply error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context verifier Apply did not observe Close cancellation")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not return after context cancellation")
	}
	select {
	case err := <-observedCancellation:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("context verifier cancellation=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context verifier did not report cancellation")
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("canceled verifier mutated state: err=%v", err)
	}
}

func TestProjectionLifecycleReplayRejectsUnauthenticatedReceiptWithoutMutation(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 56, 0, 0, time.UTC)
	tests := []struct {
		name   string
		tamper func(ProjectionTrustRequest, ProjectionTrustDecision) (ProjectionTrustDecision, error)
	}{
		{
			name: "tampered signature",
			tamper: func(_ ProjectionTrustRequest, decision ProjectionTrustDecision) (ProjectionTrustDecision, error) {
				decision.Signature = tamperProjectionTrustSignature(decision.Signature)
				return decision, nil
			},
		},
		{
			name: "wrong key",
			tamper: func(_ ProjectionTrustRequest, decision ProjectionTrustDecision) (ProjectionTrustDecision, error) {
				return SignProjectionTrustDecision(decision, otherProjectionTrustVerifierKey())
			},
		},
		{
			name: "expired",
			tamper: func(request ProjectionTrustRequest, decision ProjectionTrustDecision) (ProjectionTrustDecision, error) {
				decision.ExpiresAt = request.EvaluationTime
				return SignProjectionTrustDecision(decision, testProjectionTrustVerifierKey())
			},
		},
		{
			name: "binding mismatch",
			tamper: func(_ ProjectionTrustRequest, decision ProjectionTrustDecision) (ProjectionTrustDecision, error) {
				decision.PolicyHash = testHash("c")
				return SignProjectionTrustDecision(decision, testProjectionTrustVerifierKey())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			verifierCalls := 0
			lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
				verifierCalls++
				decision, err := allowProjectionTrust(request)
				if err != nil || verifierCalls == 1 {
					return decision, err
				}
				return tt.tamper(request, decision)
			}), testProjectionTrustVerifierKey())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lifecycle.Close() })
			lifecycle.clock = func() time.Time { return now }
			fixture := newProjectionFixture(t, "1.0.0", "authenticated replay", 1, now)
			if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); err != nil {
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

			if result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) || result != (ProjectionLifecycleResult{}) {
				t.Fatalf("unauthenticated replay result=%+v err=%v", result, err)
			}
			if verifierCalls != 2 {
				t.Fatalf("verifier calls = %d want 2", verifierCalls)
			}
			liveAfter, err := os.ReadFile(livePath)
			if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
				t.Fatalf("unauthenticated replay changed live projection: %q err=%v", liveAfter, err)
			}
			stateAfter, err := os.ReadFile(statePath)
			if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
				t.Fatalf("unauthenticated replay changed state: %q err=%v", stateAfter, err)
			}
		})
	}
}

func TestProjectionLifecycleRejectsResealedStateWithTamperedTrustReceipt(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 56, 30, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "authenticated managed state", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, lifecycle.stateRel(fixture.effect))
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state projectionLifecycleState
	if err := decodeStrictProjectionJSON(stateBytes, &state); err != nil {
		t.Fatal(err)
	}
	state.Generations[0].TrustDecisionSignature = tamperProjectionTrustSignature(state.Generations[0].TrustDecisionSignature)
	state, err = sealProjectionLifecycleState(state, testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	stateBefore = append(stateBefore, '\n')
	if err := os.WriteFile(statePath, stateBefore, 0o644); err != nil {
		t.Fatal(err)
	}
	livePath := projectionLivePath(root, fixture.effect)
	liveBefore, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}
	readback := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, "read-tampered-state", "attempt-read-tampered-state", testHash("7"))

	if result, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) || result != (ProjectionLifecycleResult{}) {
		t.Fatalf("resealed state trust tamper result=%+v err=%v", result, err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("resealed state trust tamper changed state: %q err=%v", stateAfter, err)
	}
	liveAfter, err := os.ReadFile(livePath)
	if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
		t.Fatalf("resealed state trust tamper changed live projection: %q err=%v", liveAfter, err)
	}
	if installed.TrustDecisionSignature == state.Generations[0].TrustDecisionSignature {
		t.Fatal("test did not tamper the stored trust receipt")
	}
}

func TestProjectionLifecycleRejectsPubliclyRehashedGenerationSelection(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 56, 40, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	v1 := newProjectionFixture(t, "1.0.0", "authenticated selection v1", 1, now)
	v2 := newProjectionFixture(t, "2.0.0", "authenticated selection v2", 2, now)
	if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
		t.Fatal(err)
	}
	installed, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(root, lifecycle.stateRel(v2.effect))
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state projectionLifecycleState
	if err := decodeStrictProjectionJSON(stateBytes, &state); err != nil {
		t.Fatal(err)
	}
	state.ArchiveGeneration = 1
	state.StateHash, err = hashProjectionLifecycleState(state)
	if err != nil {
		t.Fatal(err)
	}
	forgedState, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, forgedState, 0o644); err != nil {
		t.Fatal(err)
	}
	livePath := projectionLivePath(root, v2.effect)
	if err := os.WriteFile(livePath, v1.artifact.Files["SKILL.md"], 0o644); err != nil {
		t.Fatal(err)
	}
	liveBefore, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	readback := actionEffect(t, v1.effect, contracts.SkillProjectionActionReadback, 2, "read-forged-selection", "attempt-read-forged-selection", testHash("9"))

	if result, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) || result != (ProjectionLifecycleResult{}) {
		t.Fatalf("forged generation selection result=%+v err=%v", result, err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("forged selection changed state: %q err=%v", stateAfter, err)
	}
	liveAfter, err := os.ReadFile(livePath)
	if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
		t.Fatalf("forged selection changed live: %q err=%v", liveAfter, err)
	}
	if installed.NewArtifactHash == state.Generations[0].ArtifactHash {
		t.Fatal("test did not select an older retained generation")
	}
}

func TestProjectionLifecycleRejectsCrossWorkspaceTrustReceiptTransplant(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 56, 45, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	victim := newProjectionFixture(t, "1.0.0", "workspace-bound receipt", 1, now)
	victimResult, err := lifecycle.Apply(victim.effect, &victim.artifact, victim.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := victim
	other.effect.WorkspaceID = "workspace-other"
	other.effect.IdempotencyKey = "install-other-workspace"
	other.effect.AttemptID = "attempt-other-workspace"
	other.effect.Nonce = strings.Repeat("9", 64)
	other.effect.CanonicalRequestHash = ""
	other.effect, err = other.effect.Seal()
	if err != nil {
		t.Fatal(err)
	}
	otherResult, err := lifecycle.Apply(other.effect, &other.artifact, other.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	victimState, err := lifecycle.readState(victim.effect, victimResult.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	otherState, err := lifecycle.readState(other.effect, otherResult.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	transplanted := otherState.Generations[0]
	victimState.Generations[0].TrustVerificationRef = transplanted.TrustVerificationRef
	victimState.Generations[0].TrustDecisionHash = transplanted.TrustDecisionHash
	victimState.Generations[0].TrustVerifierID = transplanted.TrustVerifierID
	victimState.Generations[0].TrustKeyID = transplanted.TrustKeyID
	victimState.Generations[0].TrustAction = transplanted.TrustAction
	victimState.Generations[0].TrustCanonicalHash = transplanted.TrustCanonicalHash
	victimState.Generations[0].TrustBindingHash = transplanted.TrustBindingHash
	victimState.Generations[0].TrustDecisionSignature = transplanted.TrustDecisionSignature
	sealedVictimState, err := sealProjectionLifecycleState(*victimState, testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := json.MarshalIndent(sealedVictimState, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	stateBefore = append(stateBefore, '\n')
	statePath := filepath.Join(root, lifecycle.stateRel(victim.effect))
	if err := os.WriteFile(statePath, stateBefore, 0o644); err != nil {
		t.Fatal(err)
	}
	livePath := projectionLivePath(root, victim.effect)
	liveBefore, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}
	readback := actionEffect(t, victim.effect, contracts.SkillProjectionActionReadback, 1, "read-transplanted-state", "attempt-read-transplanted-state", testHash("6"))

	if result, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) || result != (ProjectionLifecycleResult{}) {
		t.Fatalf("cross-workspace receipt transplant result=%+v err=%v", result, err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("cross-workspace receipt transplant changed state: %q err=%v", stateAfter, err)
	}
	liveAfter, err := os.ReadFile(livePath)
	if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
		t.Fatalf("cross-workspace receipt transplant changed live projection: %q err=%v", liveAfter, err)
	}
}

func TestProjectionLifecycleRejectsResealedCertificationRefBoundaryCollision(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 56, 50, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "certification-bound receipt", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, lifecycle.stateRel(fixture.effect))
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state projectionLifecycleState
	if err := decodeStrictProjectionJSON(stateBytes, &state); err != nil {
		t.Fatal(err)
	}
	originalRefs := append([]string(nil), state.Generations[0].CertificationRefs...)
	state.Generations[0].CertificationRefs = []string{strings.Join(originalRefs, "\x00")}
	state, err = sealProjectionLifecycleState(state, testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	stateBefore = append(stateBefore, '\n')
	if err := os.WriteFile(statePath, stateBefore, 0o644); err != nil {
		t.Fatal(err)
	}
	livePath := projectionLivePath(root, fixture.effect)
	liveBefore, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}
	readback := actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, "read-cert-collision", "attempt-read-cert-collision", testHash("5"))

	if result, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) || result != (ProjectionLifecycleResult{}) {
		t.Fatalf("certification ref boundary collision result=%+v err=%v", result, err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
		t.Fatalf("certification ref boundary collision changed state: %q err=%v", stateAfter, err)
	}
	liveAfter, err := os.ReadFile(livePath)
	if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
		t.Fatalf("certification ref boundary collision changed live projection: %q err=%v", liveAfter, err)
	}
	if projectionCertificationRefsHash(originalRefs) == projectionCertificationRefsHash(state.Generations[0].CertificationRefs) {
		t.Fatal("certification ref hash retained a delimiter collision")
	}
	if installed.TrustCertificationHash != projectionCertificationRefsHash(originalRefs) {
		t.Fatal("installed result omitted the exact certification-set binding")
	}
}

func TestProjectionLifecycleRecoversFsyncedJournalAtEveryPublishBoundary(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 57, 0, 0, time.UTC)
	for _, crashStage := range []string{
		projectionMutationAfterJournal,
		projectionMutationAfterLive,
		projectionMutationAfterState,
	} {
		t.Run(crashStage, func(t *testing.T) {
			root := t.TempDir()
			lifecycle := newProjectionLifecycleForTest(t, root, now)
			fixture := newProjectionFixture(t, "1.0.0", "journal recovery prompt", 1, now)
			simulatedCrash := errors.New("simulated process crash")
			lifecycle.mutationHook = func(stage string) error {
				if stage == crashStage {
					return simulatedCrash
				}
				return nil
			}

			if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) || !errors.Is(err, simulatedCrash) {
				t.Fatalf("crash-stage apply error = %v", err)
			}
			journalPath := filepath.Join(root, lifecycle.journalRel(fixture.effect))
			journalBytes, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			var journal projectionRecoveryJournal
			if err := json.Unmarshal(journalBytes, &journal); err != nil {
				t.Fatal(err)
			}
			projection, err := projectionRelativePath(fixture.effect.SkillID, fixture.effect.AgentTarget)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := lifecycle.validateProjectionRecoveryJournal(journal, fixture.effect, filepath.ToSlash(projection.Path)); err != nil {
				t.Fatalf("persisted journal is not valid: %v", err)
			}

			lifecycle.mutationHook = nil
			recovered, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.Status != "installed" || recovered.ResultHash != journal.ResultHash ||
				recovered.TrustDecisionHash != journal.TrustDecisionHash {
				t.Fatalf("recovered result = %+v journal=%+v", recovered, journal)
			}
			if _, err := os.Stat(journalPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recovered journal still exists: %v", err)
			}
			live, err := os.ReadFile(projectionLivePath(root, fixture.effect))
			if err != nil || !reflect.DeepEqual(live, fixture.artifact.Files["SKILL.md"]) {
				t.Fatalf("recovered live projection = %q err=%v", live, err)
			}
			state, err := lifecycle.readState(fixture.effect, recovered.RelativePath)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.Generations) != 1 || len(state.Replays) != 1 || len(state.Attempts) != 1 {
				t.Fatalf("recovery duplicated state: %+v", state)
			}
		})
	}
}

func TestProjectionLifecycleRecoveryRevalidatesTrustBeforePublication(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 57, 30, 0, time.UTC)
	t.Run("revoked initial install after live publish", func(t *testing.T) {
		root := t.TempDir()
		trustRevoked := errors.New("certification revoked")
		revoked := false
		lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
			if revoked {
				return ProjectionTrustDecision{}, trustRevoked
			}
			return allowProjectionTrust(request)
		}), testProjectionTrustVerifierKey())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lifecycle.Close() })
		lifecycle.clock = func() time.Time { return now }
		fixture := newProjectionFixture(t, "1.0.0", "revoked recovery prompt", 1, now)
		lifecycle.mutationHook = func(stage string) error {
			if stage == projectionMutationAfterLive {
				return errors.New("stop after live publish")
			}
			return nil
		}
		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) {
			t.Fatalf("prepare recovery journal: %v", err)
		}
		revoked = true
		lifecycle.mutationHook = nil
		if result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) || !strings.Contains(err.Error(), trustRevoked.Error()) || result != (ProjectionLifecycleResult{}) {
			t.Fatalf("revoked recovery result=%+v err=%v", result, err)
		}
		if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("revoked recovery retained live projection: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.stateRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("revoked recovery retained state: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.journalRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("revoked recovery retained journal: %v", err)
		}
	})

	t.Run("expired upgrade after state publish", func(t *testing.T) {
		root := t.TempDir()
		expired := false
		lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
			decision, err := allowProjectionTrust(request)
			if err != nil || !expired {
				return decision, err
			}
			decision.ExpiresAt = request.EvaluationTime
			return SignProjectionTrustDecision(decision, testProjectionTrustVerifierKey())
		}), testProjectionTrustVerifierKey())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lifecycle.Close() })
		lifecycle.clock = func() time.Time { return now }
		v1 := newProjectionFixture(t, "1.0.0", "previous authenticated prompt", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "expired recovery prompt", 2, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(root, lifecycle.stateRel(v1.effect))
		previousState, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		previousLive, err := os.ReadFile(projectionLivePath(root, v1.effect))
		if err != nil {
			t.Fatal(err)
		}
		lifecycle.mutationHook = func(stage string) error {
			if stage == projectionMutationAfterState {
				return errors.New("stop after state publish")
			}
			return nil
		}
		if _, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) {
			t.Fatalf("prepare upgrade recovery journal: %v", err)
		}
		expired = true
		lifecycle.mutationHook = nil
		if result, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) || result != (ProjectionLifecycleResult{}) {
			t.Fatalf("expired recovery result=%+v err=%v", result, err)
		}
		stateAfter, err := os.ReadFile(statePath)
		if err != nil || !reflect.DeepEqual(stateAfter, previousState) {
			t.Fatalf("expired recovery state = %q err=%v", stateAfter, err)
		}
		liveAfter, err := os.ReadFile(projectionLivePath(root, v1.effect))
		if err != nil || !reflect.DeepEqual(liveAfter, previousLive) {
			t.Fatalf("expired recovery live = %q err=%v", liveAfter, err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.journalRel(v2.effect))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired recovery retained journal: %v", err)
		}
	})
}

func TestProjectionLifecycleExpiredAuthorityRestoresPendingJournal(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 57, 45, 0, time.UTC)
	t.Run("expired install effect", func(t *testing.T) {
		root := t.TempDir()
		currentTime := now
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		lifecycle.clock = func() time.Time { return currentTime }
		fixture := newProjectionFixture(t, "1.0.0", "expired pending install", 1, now)
		lifecycle.mutationHook = func(stage string) error {
			if stage == projectionMutationAfterLive {
				return errors.New("stop pending install after live")
			}
			return nil
		}
		if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) {
			t.Fatalf("prepare expired install journal: %v", err)
		}
		abortedRecord := projectionGeneration{Generation: 1, ArtifactHash: fixture.effect.ArtifactHash}
		partialGeneration := filepath.Join(root, lifecycle.generationParentRel(fixture.effect), projectionGenerationDirName(abortedRecord))
		if err := os.Remove(filepath.Join(partialGeneration, "skillpack.json")); err != nil {
			t.Fatalf("prepare partial generation cleanup: %v", err)
		}
		currentTime = fixture.effect.ExpiresAt
		lifecycle.mutationHook = nil
		if result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, contracts.ErrSkillProjectionEffectInactive) || result != (ProjectionLifecycleResult{}) {
			t.Fatalf("expired pending install result=%+v err=%v", result, err)
		}
		for name, path := range map[string]string{
			"live":    projectionLivePath(root, fixture.effect),
			"state":   filepath.Join(root, lifecycle.stateRel(fixture.effect)),
			"journal": filepath.Join(root, lifecycle.journalRel(fixture.effect)),
		} {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expired pending install retained %s: %v", name, err)
			}
		}
		generationParent := filepath.Join(root, lifecycle.generationParentRel(fixture.effect))
		if entries, err := os.ReadDir(generationParent); err != nil || len(entries) != 0 {
			t.Fatalf("expired pending install retained generation entries=%v err=%v", entries, err)
		}
	})

	t.Run("expired rollback permit", func(t *testing.T) {
		root := t.TempDir()
		currentTime := now
		lifecycle := newProjectionLifecycleForTest(t, root, now)
		lifecycle.clock = func() time.Time { return currentTime }
		v1 := newProjectionFixture(t, "1.0.0", "rollback restore v1", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "rollback restore v2", 2, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		rollback := actionEffect(t, v1.effect, contracts.SkillProjectionActionRollback, 3, "rollback-expired-journal", "attempt-rollback-expired-journal", testHash("7"))
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
		statePath := filepath.Join(root, lifecycle.stateRel(v2.effect))
		stateBefore, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		liveBefore, err := os.ReadFile(projectionLivePath(root, v2.effect))
		if err != nil {
			t.Fatal(err)
		}
		lifecycle.mutationHook = func(stage string) error {
			if stage == projectionMutationAfterState {
				return errors.New("stop pending rollback after state")
			}
			return nil
		}
		if _, err := lifecycle.Apply(rollback, nil, rollback.ConsumedPermitRef, &permit); !errors.Is(err, ErrProjectionRecoveryPending) {
			t.Fatalf("prepare expired rollback journal: %v", err)
		}
		currentTime = permit.ExpiresAt
		lifecycle.mutationHook = nil
		if result, err := lifecycle.Apply(rollback, nil, rollback.ConsumedPermitRef, &permit); !errors.Is(err, contracts.ErrSkillProjectionEffectInactive) || result != (ProjectionLifecycleResult{}) {
			t.Fatalf("expired pending rollback result=%+v err=%v", result, err)
		}
		stateAfter, err := os.ReadFile(statePath)
		if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
			t.Fatalf("expired rollback state=%q err=%v", stateAfter, err)
		}
		liveAfter, err := os.ReadFile(projectionLivePath(root, v2.effect))
		if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
			t.Fatalf("expired rollback live=%q err=%v", liveAfter, err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.journalRel(rollback))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired rollback retained journal: %v", err)
		}
		abortedRecord := projectionGeneration{Generation: 3, ArtifactHash: v1.effect.ArtifactHash}
		if _, err := os.Stat(filepath.Join(root, lifecycle.generationParentRel(rollback), projectionGenerationDirName(abortedRecord))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired rollback retained forward generation: %v", err)
		}
	})
}

func TestProjectionLifecycleRejectsCapturedJournalStateSplice(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 57, 55, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	v1 := newProjectionFixture(t, "1.0.0", "journal splice v1", 1, now)
	v2 := newProjectionFixture(t, "2.0.0", "journal splice v2", 2, now)
	if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
		t.Fatal(err)
	}
	readback := actionEffect(t, v1.effect, contracts.SkillProjectionActionReadback, 1, "captured-readback", "attempt-captured-readback", testHash("6"))
	lifecycle.mutationHook = func(stage string) error {
		if stage == projectionMutationAfterJournal {
			return errors.New("capture authentic journal")
		}
		return nil
	}
	if _, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) {
		t.Fatalf("capture journal: %v", err)
	}
	journalPath := filepath.Join(root, lifecycle.journalRel(readback))
	capturedBytes, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var captured projectionRecoveryJournal
	if err := decodeStrictProjectionJSON(capturedBytes, &captured); err != nil {
		t.Fatal(err)
	}
	lifecycle.mutationHook = nil
	if _, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil); err != nil {
		t.Fatal(err)
	}
	currentStateBytes, err := os.ReadFile(filepath.Join(root, lifecycle.stateRel(v2.effect)))
	if err != nil {
		t.Fatal(err)
	}
	currentLiveBytes, err := os.ReadFile(projectionLivePath(root, v2.effect))
	if err != nil {
		t.Fatal(err)
	}
	splice := captured
	splice.PreviousStateBytes = append([]byte(nil), currentStateBytes...)
	splice.PreviousStateHash = HashBytes(currentStateBytes)
	splice.PreviousLiveBytes = append([]byte(nil), currentLiveBytes...)
	splice.PreviousLiveHash = HashBytes(currentLiveBytes)
	splice.JournalHash, err = hashProjectionRecoveryJournal(splice)
	if err != nil {
		t.Fatal(err)
	}
	publicSpliceBytes, err := json.MarshalIndent(splice, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, publicSpliceBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if result, err := lifecycle.Apply(readback, nil, readback.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) || result != (ProjectionLifecycleResult{}) {
		t.Fatalf("public journal splice result=%+v err=%v", result, err)
	}
	stateAfter, err := os.ReadFile(filepath.Join(root, lifecycle.stateRel(v2.effect)))
	if err != nil || !reflect.DeepEqual(stateAfter, currentStateBytes) {
		t.Fatalf("journal splice changed current state: %q err=%v", stateAfter, err)
	}
	liveAfter, err := os.ReadFile(projectionLivePath(root, v2.effect))
	if err != nil || !reflect.DeepEqual(liveAfter, currentLiveBytes) {
		t.Fatalf("journal splice changed current live: %q err=%v", liveAfter, err)
	}
	authenticatedSplice, err := sealProjectionRecoveryJournal(splice, testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := projectionRelativePath(readback.SkillID, readback.AgentTarget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.validateProjectionRecoveryJournal(authenticatedSplice, readback, filepath.ToSlash(projection.Path)); !errors.Is(err, ErrProjectionDrift) {
		t.Fatalf("authenticated illegal transition error=%v", err)
	}
}

func TestProjectionLifecycleRecoversRevocationJournal(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 58, 0, 0, time.UTC)
	root := t.TempDir()
	verifierCalls := 0
	lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
		verifierCalls++
		if verifierCalls > 1 {
			return ProjectionTrustDecision{}, errors.New("revocation evidence withdrawn")
		}
		return allowProjectionTrust(request)
	}), testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lifecycle.Close() })
	lifecycle.clock = func() time.Time { return now }
	fixture := newProjectionFixture(t, "1.0.0", "revoke recovery prompt", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	revoke := actionEffect(t, fixture.effect, contracts.SkillProjectionActionRevoke, 2, "revoke-recovery", "attempt-revoke-recovery", testHash("9"))
	simulatedCrash := errors.New("simulated revoke crash")
	lifecycle.mutationHook = func(stage string) error {
		if stage == projectionMutationAfterLive {
			return simulatedCrash
		}
		return nil
	}
	if _, err := lifecycle.Apply(revoke, nil, revoke.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) || !errors.Is(err, simulatedCrash) {
		t.Fatalf("revoke crash error = %v", err)
	}
	if verifierCalls != 1 {
		t.Fatalf("revoke crash rechecked withdrawn trust %d times", verifierCalls)
	}
	if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoke crash did not publish live absence: %v", err)
	}
	stateBeforeRecovery, err := lifecycle.readState(fixture.effect, installed.RelativePath)
	if err != nil || stateBeforeRecovery.Status != projectionStatusActive {
		t.Fatalf("revoke crash unexpectedly published state: %+v err=%v", stateBeforeRecovery, err)
	}

	lifecycle.mutationHook = nil
	recovered, err := lifecycle.Apply(revoke, nil, revoke.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != projectionStatusRevoked {
		t.Fatalf("recovered revoke = %+v", recovered)
	}
	if verifierCalls != 1 || recovered.TrustDecisionAction != contracts.SkillProjectionActionInstall ||
		recovered.TrustDecisionCanonical != fixture.effect.CanonicalRequestHash {
		t.Fatalf("recovered revoke trust=%+v verifier_calls=%d", recovered, verifierCalls)
	}
	state, err := lifecycle.readState(revoke, recovered.RelativePath)
	if err != nil || state.Status != projectionStatusRevoked || state.Generation != 2 {
		t.Fatalf("recovered revoke state = %+v err=%v", state, err)
	}
	if _, err := os.Stat(filepath.Join(root, lifecycle.journalRel(revoke))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoke recovery journal still exists: %v", err)
	}
}

func TestProjectionLifecyclePersistsOnlyTrustReceiptNotVerifierSecret(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 58, 30, 0, time.UTC)
	root := t.TempDir()
	key := testProjectionTrustVerifierKey()
	lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(allowProjectionTrust), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lifecycle.Close() })
	lifecycle.clock = func() time.Time { return now }
	fixture := newProjectionFixture(t, "1.0.0", "receipt without verifier secret", 1, now)
	lifecycle.mutationHook = func(stage string) error {
		if stage == projectionMutationAfterJournal {
			return errors.New("inspect durable journal")
		}
		return nil
	}
	if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) {
		t.Fatalf("prepare recovery journal: %v", err)
	}
	journalBytes, err := os.ReadFile(filepath.Join(root, lifecycle.journalRel(fixture.effect)))
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.mutationHook = nil
	result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	stateBytes, err := os.ReadFile(filepath.Join(root, lifecycle.stateRel(fixture.effect)))
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{"result": resultBytes, "state": stateBytes, "journal": journalBytes} {
		if bytes.Contains(payload, key.HMACKey) {
			t.Fatalf("%s serialized the verifier secret", name)
		}
		if !bytes.Contains(payload, []byte(key.VerifierID)) || !bytes.Contains(payload, []byte(key.KeyID)) ||
			!bytes.Contains(payload, []byte(projectionTrustSignaturePrefix)) {
			t.Fatalf("%s omitted the authenticated receipt identity/MAC: %s", name, payload)
		}
	}
}

func TestProjectionLifecycleRejectsTamperedRecoveryJournalWithoutMutation(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 59, 0, 0, time.UTC)
	tests := []struct {
		name         string
		tamper       func(t *testing.T, path string)
		wantTooLarge bool
	}{
		{
			name: "hash mismatch",
			tamper: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var journal projectionRecoveryJournal
				if err := json.Unmarshal(data, &journal); err != nil {
					t.Fatal(err)
				}
				journal.NextLiveBytes[0] ^= 0xff
				mutated, err := json.MarshalIndent(journal, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, mutated, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "resealed trust signature mismatch",
			tamper: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var journal projectionRecoveryJournal
				if err := json.Unmarshal(data, &journal); err != nil {
					t.Fatal(err)
				}
				journal.TrustDecisionSignature = tamperProjectionTrustSignature(journal.TrustDecisionSignature)
				journal, err = sealProjectionRecoveryJournal(journal, testProjectionTrustVerifierKey())
				if err != nil {
					t.Fatal(err)
				}
				mutated, err := json.MarshalIndent(journal, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				mutated = append(mutated, '\n')
				if err := os.WriteFile(path, mutated, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversized",
			tamper: func(t *testing.T, path string) {
				if err := os.Truncate(path, maxProjectionRecoveryJournalBytes+1); err != nil {
					t.Fatal(err)
				}
			},
			wantTooLarge: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			lifecycle := newProjectionLifecycleForTest(t, root, now)
			fixture := newProjectionFixture(t, "1.0.0", "tamper-resistant recovery", 1, now)
			lifecycle.mutationHook = func(stage string) error {
				if stage == projectionMutationAfterJournal {
					return errors.New("stop after journal")
				}
				return nil
			}
			if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) {
				t.Fatalf("prepare recovery journal: %v", err)
			}
			journalPath := filepath.Join(root, lifecycle.journalRel(fixture.effect))
			tt.tamper(t, journalPath)
			journalBefore, err := os.Stat(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			lifecycle.mutationHook = nil
			_, err = lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
			if !errors.Is(err, ErrProjectionDrift) || (tt.wantTooLarge && !errors.Is(err, ErrProjectionFileTooLarge)) {
				t.Fatalf("tampered recovery error = %v", err)
			}
			if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("tampered recovery mutated live projection: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, lifecycle.stateRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("tampered recovery mutated state: %v", err)
			}
			journalAfter, err := os.Stat(journalPath)
			if err != nil || journalAfter.Size() != journalBefore.Size() || !journalAfter.ModTime().Equal(journalBefore.ModTime()) {
				t.Fatalf("tampered journal was changed: before=%+v after=%+v err=%v", journalBefore, journalAfter, err)
			}
		})
	}
}

func TestProjectionLifecycleRecoveryRefusesUnjournaledLiveDrift(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 59, 30, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "journal-authorized live bytes", 1, now)
	lifecycle.mutationHook = func(stage string) error {
		if stage == projectionMutationAfterJournal {
			return errors.New("stop after journal")
		}
		return nil
	}
	if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRecoveryPending) {
		t.Fatalf("prepare recovery journal: %v", err)
	}
	livePath := projectionLivePath(root, fixture.effect)
	if err := os.MkdirAll(filepath.Dir(livePath), 0o755); err != nil {
		t.Fatal(err)
	}
	intruder := []byte("operator-owned unjournaled bytes")
	if err := os.WriteFile(livePath, intruder, 0o644); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(root, lifecycle.journalRel(fixture.effect))
	journalBefore, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}

	lifecycle.mutationHook = nil
	if _, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionDrift) {
		t.Fatalf("unjournaled live drift error = %v", err)
	}
	liveAfter, err := os.ReadFile(livePath)
	if err != nil || !reflect.DeepEqual(liveAfter, intruder) {
		t.Fatalf("recovery overwrote live drift: %q err=%v", liveAfter, err)
	}
	if _, err := os.Stat(filepath.Join(root, lifecycle.stateRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery published state over live drift: %v", err)
	}
	journalAfter, err := os.ReadFile(journalPath)
	if err != nil || !reflect.DeepEqual(journalAfter, journalBefore) {
		t.Fatalf("recovery changed valid journal after drift: err=%v", err)
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

func TestProjectionLifecycleCompactsReplayWindowBeforeStateLimit(t *testing.T) {
	now := time.Date(2026, 8, 30, 15, 30, 0, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "bounded replay window", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := lifecycle.readState(fixture.effect, installed.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	record := state.Generations[0]
	state.Replays = nil
	state.Attempts = nil

	var lastEffect contracts.SkillProjectionEffect
	var lastResult ProjectionLifecycleResult
	for i := 0; i < maxProjectionReplayEntries+8; i++ {
		key := fmt.Sprintf("bounded-readback-%03d", i)
		attempt := fmt.Sprintf("bounded-attempt-%03d", i)
		lastEffect = actionEffect(t, fixture.effect, contracts.SkillProjectionActionReadback, 1, key, attempt, testHash("6"))
		decision, err := lifecycle.verifyProjectionTrust(lastEffect, record, fixture.artifact.Files["skillpack.json"], fixture.artifact.Files["SKILL.md"], nil)
		if err != nil {
			t.Fatalf("trust readback %d: %v", i, err)
		}
		lastResult = newProjectionResult(lastEffect, installed.RelativePath, projectionStatusActive, 1, record, record)
		lastResult.ObservedArtifactHash = record.ArtifactHash
		lastResult.ObservedContentHash = record.ContentHash
		lastResult.ObservedManifestHash = record.ManifestHash
		bindProjectionResultTrust(&lastResult, decision, lastEffect)
		lastResult, err = sealProjectionLifecycleResult(lastResult)
		if err != nil {
			t.Fatal(err)
		}
		appendProjectionReplay(state, lastEffect, lastResult)
	}
	if len(state.Replays) != maxProjectionReplayEntries || len(state.Attempts) != maxProjectionReplayEntries {
		t.Fatalf("compacted replay window = replays:%d attempts:%d", len(state.Replays), len(state.Attempts))
	}
	wantFirst := fmt.Sprintf("bounded-readback-%03d", 8)
	if state.Replays[0].IdempotencyKey != wantFirst || state.Attempts[0].IdempotencyKey != wantFirst {
		t.Fatalf("oldest retained replay = %+v attempt=%+v", state.Replays[0], state.Attempts[0])
	}
	if replay, ok := findProjectionReplay(state.Replays, lastEffect.IdempotencyKey); !ok || !reflect.DeepEqual(replay.Result, lastResult) {
		t.Fatalf("newest exact replay = %+v found=%v", replay, ok)
	}
	if err := validateProjectionStateIdentity(*state, lastEffect, installed.RelativePath); err != nil {
		t.Fatalf("compacted state identity: %v", err)
	}
	if err := lifecycle.verifyProjectionStateTrustReceipts(*state); err != nil {
		t.Fatalf("compacted state trust: %v", err)
	}
	if _, data, err := lifecycle.marshalProjectionLifecycleState(*state); err != nil || len(data) >= maxProjectionLifecycleStateBytes {
		t.Fatalf("compacted state size = %d err=%v", len(data), err)
	}
}

func TestProjectionLifecycleCompactsGenerationRollbackWindowBeforeStateLimit(t *testing.T) {
	now := time.Date(2026, 8, 30, 15, 45, 0, 0, time.UTC)
	root := t.TempDir()
	lifecycle := newProjectionLifecycleForTest(t, root, now)
	fixture := newProjectionFixture(t, "1.0.0", "bounded generation window", 1, now)
	installed, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := lifecycle.readState(fixture.effect, installed.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	baseRecord := state.Generations[0]
	generationParent := filepath.Join(root, lifecycle.generationParentRel(fixture.effect))
	for generation := uint64(2); generation <= maxProjectionGenerationEntries; generation++ {
		record := baseRecord
		record.Generation = generation
		state.Generations = append(state.Generations, record)
		dir := filepath.Join(generationParent, projectionGenerationDirName(record))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "skillpack.json"), fixture.artifact.Files["skillpack.json"], 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), fixture.artifact.Files["SKILL.md"], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	state.Generation = maxProjectionGenerationEntries
	state.ArchiveGeneration = maxProjectionGenerationEntries
	sealedState, stateBytes, err := lifecycle.marshalProjectionLifecycleState(*state)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealedState.Generations) != maxProjectionGenerationEntries || len(stateBytes) >= maxProjectionLifecycleStateBytes {
		t.Fatalf("seeded generation state count=%d size=%d", len(sealedState.Generations), len(stateBytes))
	}
	if err := lifecycle.writeStateBytes(fixture.effect, stateBytes); err != nil {
		t.Fatal(err)
	}

	upgrade := newProjectionFixture(t, "257.0.0", "generation window upgrade", 2, now)
	upgrade.effect.Generation = maxProjectionGenerationEntries + 1
	upgrade.effect.IdempotencyKey = "install-generation-257"
	upgrade.effect.AttemptID = "attempt-install-generation-257"
	upgrade.effect.ConsumedPermitRef = testHash("f")
	upgrade.effect.Nonce = strings.Repeat("f", 64)
	upgrade.effect.CanonicalRequestHash = ""
	upgrade.effect, err = upgrade.effect.Seal()
	if err != nil {
		t.Fatal(err)
	}
	result, err := lifecycle.Apply(upgrade.effect, &upgrade.artifact, upgrade.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "upgraded" || result.NewGeneration != maxProjectionGenerationEntries+1 {
		t.Fatalf("generation-window upgrade result=%+v", result)
	}
	compacted, err := lifecycle.readState(upgrade.effect, result.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(compacted.Generations) != maxProjectionGenerationEntries || compacted.Generations[0].Generation != 2 ||
		compacted.Generations[len(compacted.Generations)-1].Generation != maxProjectionGenerationEntries+1 {
		t.Fatalf("compacted generation window first=%d last=%d count=%d", compacted.Generations[0].Generation, compacted.Generations[len(compacted.Generations)-1].Generation, len(compacted.Generations))
	}
	if _, data, err := lifecycle.marshalProjectionLifecycleState(*compacted); err != nil || len(data) >= maxProjectionLifecycleStateBytes {
		t.Fatalf("compacted generation state size=%d err=%v", len(data), err)
	}
	if _, err := os.Stat(filepath.Join(generationParent, projectionGenerationDirName(baseRecord))); err != nil {
		t.Fatalf("old immutable generation bytes were not retained: %v", err)
	}
	stateBeforeReinstall, err := os.ReadFile(filepath.Join(root, lifecycle.stateRel(upgrade.effect)))
	if err != nil {
		t.Fatal(err)
	}
	reinstall := actionEffect(t, fixture.effect, contracts.SkillProjectionActionInstall, maxProjectionGenerationEntries+2, "reinstall-evicted-generation", "attempt-reinstall-evicted-generation", testHash("d"))
	if _, err := lifecycle.Apply(reinstall, &fixture.artifact, reinstall.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionRollbackRequired) {
		t.Fatalf("evicted-generation artifact reinstall error=%v", err)
	}
	stateAfterReinstall, err := os.ReadFile(filepath.Join(root, lifecycle.stateRel(upgrade.effect)))
	if err != nil || !reflect.DeepEqual(stateAfterReinstall, stateBeforeReinstall) {
		t.Fatalf("evicted-generation reinstall changed state: %q err=%v", stateAfterReinstall, err)
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
	// Replacing the former sidecar path cannot split the lock because the
	// authoritative lock is the already-opened physical root directory.
	legacyLockPath := filepath.Join(root, ".helm", "skillpacks", "projection-lifecycle.lock")
	if err := os.MkdirAll(filepath.Dir(legacyLockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyLockPath, []byte("first inode"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(legacyLockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyLockPath, []byte("replacement inode"), 0o600); err != nil {
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

func TestProjectionLifecycleRefreshesAuthorityAndDecisionAfterVerifier(t *testing.T) {
	now := time.Date(2026, 8, 30, 16, 45, 0, 0, time.UTC)
	t.Run("effect expires during verifier", func(t *testing.T) {
		root := t.TempDir()
		currentTime := now
		lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
			decision, err := allowProjectionTrust(request)
			currentTime = request.Effect.ExpiresAt
			return decision, err
		}), testProjectionTrustVerifierKey())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lifecycle.Close() })
		lifecycle.clock = func() time.Time { return currentTime }
		fixture := newProjectionFixture(t, "1.0.0", "verifier-expired effect", 1, now)

		if result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, contracts.ErrSkillProjectionEffectInactive) || result != (ProjectionLifecycleResult{}) {
			t.Fatalf("verifier-expired effect result=%+v err=%v", result, err)
		}
		if _, err := os.Stat(projectionLivePath(root, fixture.effect)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("verifier-expired effect mutated live: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.stateRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("verifier-expired effect mutated state: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.generationParentRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("verifier-expired effect retained generation: %v", err)
		}
	})

	t.Run("decision expires during verifier", func(t *testing.T) {
		root := t.TempDir()
		currentTime := now
		lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
			decision, err := allowProjectionTrust(request)
			if err != nil {
				return ProjectionTrustDecision{}, err
			}
			decision.ExpiresAt = request.EvaluationTime.Add(time.Second)
			decision, err = SignProjectionTrustDecision(decision, testProjectionTrustVerifierKey())
			currentTime = decision.ExpiresAt
			return decision, err
		}), testProjectionTrustVerifierKey())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lifecycle.Close() })
		lifecycle.clock = func() time.Time { return currentTime }
		fixture := newProjectionFixture(t, "1.0.0", "verifier-expired decision", 1, now)

		if result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil); !errors.Is(err, ErrProjectionTrustRejected) || result != (ProjectionLifecycleResult{}) {
			t.Fatalf("expired trust decision result=%+v err=%v", result, err)
		}
		if _, err := os.Stat(filepath.Join(root, lifecycle.generationParentRel(fixture.effect))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired trust decision retained generation: %v", err)
		}
	})

	t.Run("rollback permit expires during verifier", func(t *testing.T) {
		root := t.TempDir()
		currentTime := now
		expireRollback := false
		var permit contracts.SkillProjectionRollbackPermit
		lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(func(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
			decision, err := allowProjectionTrust(request)
			if expireRollback {
				currentTime = permit.ExpiresAt
			}
			return decision, err
		}), testProjectionTrustVerifierKey())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lifecycle.Close() })
		lifecycle.clock = func() time.Time { return currentTime }
		v1 := newProjectionFixture(t, "1.0.0", "verifier rollback v1", 1, now)
		v2 := newProjectionFixture(t, "2.0.0", "verifier rollback v2", 2, now)
		if _, err := lifecycle.Apply(v1.effect, &v1.artifact, v1.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := lifecycle.Apply(v2.effect, &v2.artifact, v2.effect.ConsumedPermitRef, nil); err != nil {
			t.Fatal(err)
		}
		rollback := actionEffect(t, v1.effect, contracts.SkillProjectionActionRollback, 3, "rollback-verifier-expiry", "attempt-rollback-verifier-expiry", testHash("7"))
		permit = contracts.SkillProjectionRollbackPermit{
			SchemaVersion: contracts.SkillProjectionRollbackPermitSchemaV1, ContractVersion: contracts.SkillProjectionRollbackPermitContractV1,
			PermitRef: testHash("8"), Action: contracts.SkillProjectionActionRollback,
			TenantID: rollback.TenantID, WorkspaceID: rollback.WorkspaceID,
			SkillID: rollback.SkillID, AgentTarget: rollback.AgentTarget,
			FromGeneration: 2, TargetGeneration: 1,
			TargetSkillVersion: rollback.SkillVersion, TargetArtifactHash: rollback.ArtifactHash, TargetPolicyHash: rollback.PolicyHash,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Nonce: strings.Repeat("8", 64),
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
		statePath := filepath.Join(root, lifecycle.stateRel(v2.effect))
		stateBefore, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		liveBefore, err := os.ReadFile(projectionLivePath(root, v2.effect))
		if err != nil {
			t.Fatal(err)
		}
		expireRollback = true

		if result, err := lifecycle.Apply(rollback, nil, rollback.ConsumedPermitRef, &permit); !errors.Is(err, contracts.ErrSkillProjectionEffectInactive) || result != (ProjectionLifecycleResult{}) {
			t.Fatalf("verifier-expired rollback result=%+v err=%v", result, err)
		}
		stateAfter, err := os.ReadFile(statePath)
		if err != nil || !reflect.DeepEqual(stateAfter, stateBefore) {
			t.Fatalf("verifier-expired rollback changed state: %q err=%v", stateAfter, err)
		}
		liveAfter, err := os.ReadFile(projectionLivePath(root, v2.effect))
		if err != nil || !reflect.DeepEqual(liveAfter, liveBefore) {
			t.Fatalf("verifier-expired rollback changed live: %q err=%v", liveAfter, err)
		}
		abortedRecord := projectionGeneration{Generation: 3, ArtifactHash: v1.effect.ArtifactHash}
		if _, err := os.Stat(filepath.Join(root, lifecycle.generationParentRel(rollback), projectionGenerationDirName(abortedRecord))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("verifier-expired rollback retained generation: %v", err)
		}
	})
}

func TestProjectionDurabilityHelpers(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openManagedRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	managedRel := filepath.Join("tenant", "workspace")
	if err := ensureManagedDirAt(root, managedRel); err != nil {
		t.Fatal(err)
	}
	if err := syncManagedDirectoryAt(root, managedRel); err != nil {
		t.Fatalf("sync managed directory: %v", err)
	}
	stateRel := filepath.Join(managedRel, "state.json")
	if err := atomicReplaceManagedAt(root, stateRel, []byte("durable")); err != nil {
		t.Fatal(err)
	}
	data, err := readManagedFileAt(root, stateRel, maxProjectionLifecycleStateBytes)
	if err != nil || string(data) != "durable" {
		t.Fatalf("durable publish = %q err=%v", data, err)
	}
	if err := syncManagedDirectoryAt(root, stateRel); !errors.Is(err, ErrProjectionPathUnsafe) {
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

func TestProjectionLifecycleRemainsAnchoredWhenConfiguredRootIsReplaced(t *testing.T) {
	now := time.Date(2026, 8, 30, 17, 0, 0, 0, time.UTC)
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "projection-root")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	lifecycle := newProjectionLifecycleForTest(t, rootPath, now)
	outside := t.TempDir()
	movedPath := filepath.Join(parent, "projection-root-original")
	if err := os.Rename(rootPath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, rootPath); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	fixture := newProjectionFixture(t, "1.0.0", "root-anchored prompt", 1, now)
	result, err := lifecycle.Apply(fixture.effect, &fixture.artifact, fixture.effect.ConsumedPermitRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("replaced root redirected writes outside: entries=%v err=%v", entries, err)
	}
	live, err := os.ReadFile(projectionLivePath(movedPath, fixture.effect))
	if err != nil || !reflect.DeepEqual(live, fixture.artifact.Files["SKILL.md"]) {
		t.Fatalf("anchored root live projection = %q err=%v", live, err)
	}
	if _, err := os.Stat(filepath.Join(movedPath, lifecycle.stateRel(fixture.effect))); err != nil {
		t.Fatalf("anchored root state for %s: %v", result.RelativePath, err)
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
	lifecycle, err := NewProjectionLifecycleWithVerifierKey(root, projectionTrustVerifierFunc(allowProjectionTrust), testProjectionTrustVerifierKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lifecycle.Close() })
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

type projectionTrustContextVerifierFunc func(context.Context, ProjectionTrustRequest) (ProjectionTrustDecision, error)

func (verify projectionTrustContextVerifierFunc) VerifyProjectionTrust(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
	return verify(context.Background(), request)
}

func (verify projectionTrustContextVerifierFunc) VerifyProjectionTrustContext(
	ctx context.Context,
	request ProjectionTrustRequest,
) (ProjectionTrustDecision, error) {
	return verify(ctx, request)
}

func allowProjectionTrust(request ProjectionTrustRequest) (ProjectionTrustDecision, error) {
	return allowProjectionTrustWithKey(request, testProjectionTrustVerifierKey())
}

func allowProjectionTrustWithKey(request ProjectionTrustRequest, key ProjectionTrustVerifierKey) (ProjectionTrustDecision, error) {
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
		SandboxProfile:       request.Effect.SandboxProfile,

		Publisher:         request.Manifest.Publisher,
		ManifestStatus:    request.Manifest.Status,
		PolicyRef:         request.Manifest.PolicyRef,
		CertificationRefs: append([]string(nil), request.Effect.CertificationRefs...),

		VerifiedAt:      request.EvaluationTime,
		ExpiresAt:       request.EvaluationTime.Add(time.Minute),
		VerificationRef: testHash("e"),
	}
	return SignProjectionTrustDecision(decision, key)
}

func testProjectionTrustVerifierKey() ProjectionTrustVerifierKey {
	return ProjectionTrustVerifierKey{
		VerifierID: "test-verifier",
		KeyID:      "test-key-v1",
		HMACKey:    []byte(strings.Repeat("k", 32)),
	}
}

func rotatedProjectionTrustVerifierKey() ProjectionTrustVerifierKey {
	return ProjectionTrustVerifierKey{
		VerifierID: "test-verifier",
		KeyID:      "test-key-v2",
		HMACKey:    []byte(strings.Repeat("r", 32)),
	}
}

func otherProjectionTrustVerifierKey() ProjectionTrustVerifierKey {
	return ProjectionTrustVerifierKey{
		VerifierID: "other-verifier",
		KeyID:      "other-key-v1",
		HMACKey:    []byte(strings.Repeat("z", 32)),
	}
}

func tamperProjectionTrustSignature(signature string) string {
	replacement := "0"
	if strings.HasSuffix(signature, "0") {
		replacement = "1"
	}
	return signature[:len(signature)-1] + replacement
}
