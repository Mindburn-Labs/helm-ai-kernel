package reconcile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistentSnapshotStoreRejectsReplayAcrossRestart(t *testing.T) {
	scope := PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	path := filepath.Join(t.TempDir(), "policy-replay-watermarks.json")
	store, err := NewPersistentSnapshotStore(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("policy-v2")
	head := PolicyHead{Scope: scope, PolicyEpoch: 2, PolicyHash: HashBytes(bundle)}
	headMaterial, err := PolicyHeadSignatureMaterial(head)
	if err != nil {
		t.Fatal(err)
	}
	epochTwo := replayTestSnapshot(scope, 2, "policy-v2", "head-v2")
	epochTwo.PolicyHeadHash = HashBytes(headMaterial)
	if err := store.Swap(scope, epochTwo); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("watermark mode=%v", info.Mode().Perm())
	}

	restarted, err := NewPersistentSnapshotStore(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, ok := restarted.Get(scope)
	if !ok || persisted.PolicyEpoch != 2 || persisted.PolicyHash != epochTwo.PolicyHash ||
		persisted.PolicyHeadHash != epochTwo.PolicyHeadHash || persisted.Validation.Status != StatusInvalid {
		t.Fatalf("persisted watermark=%+v", persisted)
	}
	if err := restarted.Swap(scope, replayTestSnapshot(scope, 1, "policy-v1", "head-v1")); !errors.Is(err, ErrPolicyEpochRollback) {
		t.Fatalf("rollback error=%v", err)
	}
	if err := restarted.Swap(scope, replayTestSnapshot(scope, 2, "policy-v2-mutated", "head-v2")); !errors.Is(err, ErrPolicyEpochEquivocation) {
		t.Fatalf("policy equivocation error=%v", err)
	}
	if err := restarted.Swap(scope, replayTestSnapshot(scope, 2, "policy-v2", "head-v2-mutated")); !errors.Is(err, ErrPolicyEpochEquivocation) {
		t.Fatalf("head equivocation error=%v", err)
	}
	reconciler, err := NewReconciler(ReconcilerConfig{
		Source:   &mutableSource{head: head, bundle: bundle},
		Store:    restarted,
		Compiler: testCompiler,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := reconciler.Reconcile(t.Context(), scope)
	if err != nil || !status.Updated {
		t.Fatalf("revalidate persisted epoch: status=%+v err=%v", status, err)
	}
	active, ok := restarted.Get(scope)
	if !ok || active.Validation.Status != StatusActive {
		t.Fatalf("revalidated snapshot=%+v", active)
	}
	epochThree := replayTestSnapshot(scope, 3, "policy-v3", "head-v3")
	if err := restarted.Swap(scope, epochThree); err != nil {
		t.Fatalf("advance watermark: %v", err)
	}
	restartedAgain, err := NewPersistentSnapshotStore(path)
	if err != nil {
		t.Fatal(err)
	}
	latest, ok := restartedAgain.Get(scope)
	if !ok || latest.PolicyEpoch != 3 || latest.PolicyHash != epochThree.PolicyHash || latest.PolicyHeadHash != epochThree.PolicyHeadHash {
		t.Fatalf("latest persisted watermark=%+v", latest)
	}
}

func TestPersistentSnapshotStoreFailsClosedOnInvalidOrUnwritableState(t *testing.T) {
	t.Run("corrupt", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy-replay-watermarks.json")
		if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewPersistentSnapshotStore(path); !errors.Is(err, ErrPolicyReplayStateInvalid) {
			t.Fatalf("corrupt state error=%v", err)
		}
	})

	t.Run("public mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy-replay-watermarks.json")
		store, err := NewPersistentSnapshotStore(path)
		if err != nil {
			t.Fatal(err)
		}
		scope := PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
		if err := store.Swap(scope, replayTestSnapshot(scope, 1, "policy-v1", "head-v1")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := NewPersistentSnapshotStore(path); !errors.Is(err, ErrPolicyReplayStateInvalid) {
			t.Fatalf("public state error=%v", err)
		}
	})

	t.Run("persistence failure", func(t *testing.T) {
		root := t.TempDir()
		blockedParent := filepath.Join(root, "blocked")
		path := filepath.Join(blockedParent, "policy-replay-watermarks.json")
		store, err := NewPersistentSnapshotStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(blockedParent, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		scope := PolicyScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
		if err := store.Swap(scope, replayTestSnapshot(scope, 1, "policy-v1", "head-v1")); err == nil {
			t.Fatal("snapshot installed without durable watermark")
		}
		if _, ok := store.Get(scope); ok {
			t.Fatal("persistence failure updated the in-memory snapshot")
		}
	})

	t.Run("oversized state", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy-replay-watermarks.json")
		watermark := policyReplayWatermark{
			TenantID:       strings.Repeat("t", maxPolicyReplayWatermarkBytes),
			WorkspaceID:    "workspace-a",
			PolicyEpoch:    1,
			PolicyHash:     HashBytes([]byte("policy-v1")),
			PolicyHeadHash: HashBytes([]byte("head-v1")),
		}
		if err := writePolicyReplayWatermarks(path, map[string]policyReplayWatermark{watermark.scope().Key(): watermark}); !errors.Is(err, ErrPolicyReplayStateInvalid) {
			t.Fatalf("oversized state error=%v", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("oversized state was written: %v", err)
		}
	})
}

func replayTestSnapshot(scope PolicyScope, epoch uint64, policy, head string) *EffectivePolicySnapshot {
	return &EffectivePolicySnapshot{
		TenantID:       scope.TenantID,
		WorkspaceID:    scope.WorkspaceID,
		PolicyEpoch:    epoch,
		PolicyHash:     HashBytes([]byte(policy)),
		PolicyHeadHash: HashBytes([]byte(head)),
		Validation:     ValidationStatus{Status: StatusActive},
	}
}
