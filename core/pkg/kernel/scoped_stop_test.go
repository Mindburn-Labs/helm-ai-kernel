package kernel

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newScopedStopStoreForTest(t *testing.T, now time.Time) (*sql.DB, *ScopedStopStore) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:scoped-stop?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	store := NewScopedStopStore(db, func() time.Time { return now })
	if err := store.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db, store
}

func testAcknowledgementIdentity() AcknowledgementIdentity {
	return AcknowledgementIdentity{
		KeyID:         "kernel-stop-test",
		SignerProfile: EmergencyStopSignerClassical,
		PublicKey:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func TestScopedStopStoreFencesScopeDurablyAndReplaysByCommandID(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	db, store := newScopedStopStoreForTest(t, now)
	command := FenceCommand{
		ContractVersion: EmergencyStopFenceContractVersion,
		Audience:        "kernel-test",
		KeyID:           "cp-stop-test",
		CommandID:       "stop-command-1",
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-a",
		Epoch:           1,
		ActorID:         "operator-a",
		Reason:          "containment",
		IssuedAt:        now.Add(-time.Minute),
		ExpiresAt:       now.Add(5 * time.Minute),
	}

	state, replayed, err := store.Fence(context.Background(), command, testAcknowledgementIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if replayed || state.ReceiptHash == "" {
		t.Fatalf("first fence = replayed=%t state=%+v", replayed, state)
	}

	reloaded := NewScopedStopStore(db, nowFunc(now.Add(time.Second)))
	if err := reloaded.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, fenced, err := reloaded.IsFenced(context.Background(), StopScope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err != nil {
		t.Fatal(err)
	}
	if !fenced || got.CommandID != command.CommandID || got.CommandHash != state.CommandHash || got.ReceiptHash != state.ReceiptHash || got.AcknowledgementIdentity != testAcknowledgementIdentity() || !got.ExpiresAt.Equal(command.ExpiresAt) {
		t.Fatalf("durable fence = fenced=%t state=%+v", fenced, got)
	}

	replay, replayed, err := reloaded.Fence(context.Background(), command, testAcknowledgementIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if !replayed || replay.ReceiptHash != state.ReceiptHash {
		t.Fatalf("replay = replayed=%t state=%+v", replayed, replay)
	}
}

func TestScopedStopStoreRejectsStaleEpochAndDoesNotCrossScopes(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	_, store := newScopedStopStoreForTest(t, now)
	_, _, err := store.Fence(context.Background(), FenceCommand{
		ContractVersion: EmergencyStopFenceContractVersion, Audience: "kernel-test", KeyID: "cp-stop-test",
		CommandID: "stop-command-2", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		Epoch: 2, ActorID: "operator-a", Reason: "containment", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}, testAcknowledgementIdentity())
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = store.Fence(context.Background(), FenceCommand{
		ContractVersion: EmergencyStopFenceContractVersion, Audience: "kernel-test", KeyID: "cp-stop-test",
		CommandID: "stop-command-stale", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		Epoch: 1, ActorID: "operator-a", Reason: "stale", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}, testAcknowledgementIdentity())
	if !errors.Is(err, ErrScopedStopStaleEpoch) {
		t.Fatalf("stale fence error = %v, want ErrScopedStopStaleEpoch", err)
	}

	_, fenced, err := store.IsFenced(context.Background(), StopScope{TenantID: "tenant-a", WorkspaceID: "workspace-b"})
	if err != nil {
		t.Fatal(err)
	}
	if fenced {
		t.Fatal("fence leaked across workspaces")
	}
}

func TestScopedStopStoreRejectsEpochOutsideJCSSafeIntegerRange(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	_, store := newScopedStopStoreForTest(t, now)
	_, _, err := store.Fence(context.Background(), FenceCommand{
		ContractVersion: EmergencyStopFenceContractVersion,
		Audience:        "kernel-test",
		KeyID:           "cp-stop-test",
		CommandID:       "stop-command-unsafe-epoch",
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-a",
		Epoch:           EmergencyStopMaxEpoch + 1,
		ActorID:         "operator-a",
		Reason:          "containment",
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
	}, testAcknowledgementIdentity())
	if !errors.Is(err, ErrScopedStopInvalid) {
		t.Fatalf("unsafe epoch error = %v, want ErrScopedStopInvalid", err)
	}
}

func TestScopedStopStoreRejectsOuterWhitespaceBeforeCanonicalization(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	_, store := newScopedStopStoreForTest(t, now)
	command := FenceCommand{
		ContractVersion: EmergencyStopFenceContractVersion,
		Audience:        " kernel-test ",
		KeyID:           "cp-stop-test",
		CommandID:       "stop-command-whitespace",
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-a",
		Epoch:           1,
		ActorID:         "operator-a",
		Reason:          "containment",
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
	}
	if _, _, err := store.Fence(context.Background(), command, testAcknowledgementIdentity()); !errors.Is(err, ErrScopedStopInvalid) {
		t.Fatalf("outer-whitespace command error = %v, want ErrScopedStopInvalid", err)
	}
}

func TestScopedStopStoreRejectsMutatedCommandIDReplay(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	_, store := newScopedStopStoreForTest(t, now)
	command := FenceCommand{
		ContractVersion: EmergencyStopFenceContractVersion,
		Audience:        "kernel-test",
		KeyID:           "cp-stop-test",
		CommandID:       "stop-command-replay",
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-a",
		Epoch:           1,
		ActorID:         "operator-a",
		Reason:          "containment",
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
	}
	state, replayed, err := store.Fence(context.Background(), command, testAcknowledgementIdentity())
	if err != nil || replayed {
		t.Fatalf("first fence = state=%+v replayed=%t err=%v", state, replayed, err)
	}

	mutated := command
	mutated.Reason = "different reason"
	mutated.ExpiresAt = mutated.ExpiresAt.Add(time.Second)
	if _, _, err := store.Fence(context.Background(), mutated, testAcknowledgementIdentity()); !errors.Is(err, ErrScopedStopConflict) {
		t.Fatalf("mutated replay error = %v, want ErrScopedStopConflict", err)
	}

	got, fenced, err := store.IsFenced(context.Background(), command.Scope())
	if err != nil || !fenced {
		t.Fatalf("active fence = state=%+v fenced=%t err=%v", got, fenced, err)
	}
	if got.CommandHash != state.CommandHash || got.Reason != command.Reason || !got.ExpiresAt.Equal(command.ExpiresAt) {
		t.Fatalf("mutated replay changed active fence: got=%+v want=%+v", got, state)
	}
}

func TestScopedStopStoreRejectsReplayUnderDifferentAcknowledgementIdentity(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	_, store := newScopedStopStoreForTest(t, now)
	command := FenceCommand{
		ContractVersion: EmergencyStopFenceContractVersion,
		Audience:        "kernel-test",
		KeyID:           "cp-stop-test",
		CommandID:       "stop-command-ack-identity",
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-a",
		Epoch:           1,
		ActorID:         "operator-a",
		Reason:          "containment",
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
	}
	identity := testAcknowledgementIdentity()
	state, replayed, err := store.Fence(context.Background(), command, identity)
	if err != nil || replayed {
		t.Fatalf("initial fence = state=%+v replayed=%t err=%v", state, replayed, err)
	}

	rotated := identity
	rotated.PublicKey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, _, err := store.Fence(context.Background(), command, rotated); !errors.Is(err, ErrScopedStopConflict) {
		t.Fatalf("rotated acknowledgement identity replay error = %v, want ErrScopedStopConflict", err)
	}
	got, fenced, err := store.IsFenced(context.Background(), command.Scope())
	if err != nil || !fenced {
		t.Fatalf("active fence = state=%+v fenced=%t err=%v", got, fenced, err)
	}
	if got.AcknowledgementIdentity != identity || got.ReceiptHash != state.ReceiptHash {
		t.Fatalf("acknowledgement identity changed on rejected replay: got=%+v want=%+v", got.AcknowledgementIdentity, identity)
	}
}

func TestScopedStopStoreConcurrentExactReplayHasOneInitialWrite(t *testing.T) {
	now := time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC)
	_, store := newScopedStopStoreForTest(t, now)
	command := FenceCommand{
		ContractVersion: EmergencyStopFenceContractVersion,
		Audience:        "kernel-test",
		KeyID:           "cp-stop-test",
		CommandID:       "stop-command-concurrent",
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-a",
		Epoch:           1,
		ActorID:         "operator-a",
		Reason:          "containment",
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
	}

	const callers = 8
	results := make(chan bool, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, replayed, err := store.Fence(context.Background(), command, testAcknowledgementIdentity())
			if err != nil {
				errs <- err
				return
			}
			results <- replayed
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent fence error: %v", err)
	}
	initialWrites := 0
	for replayed := range results {
		if !replayed {
			initialWrites++
		}
	}
	if initialWrites != 1 {
		t.Fatalf("initial writes = %d, want 1", initialWrites)
	}
}

func nowFunc(now time.Time) func() time.Time {
	return func() time.Time { return now }
}
