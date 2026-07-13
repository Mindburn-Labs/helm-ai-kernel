package safedep

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestControllerBlocksTerminalFreezeBeforeDispatch(t *testing.T) {
	controller := NewController(ControllerConfig{Clock: fixedSafeDepClock})
	result, err := controller.Gate(context.Background(), GateRequest{
		Signal: Signal{HazardCode: contracts.HazardDeadManExpired, ActiveClock: false, HighRiskLane: true},
		Action: "WORKSTATION_FILE_WRITE",
	})
	if err != nil {
		t.Fatalf("terminal freeze should produce a blocking result, not an error: %v", err)
	}
	if result.DispatchAllowed {
		t.Fatal("terminal freeze allowed dispatch")
	}
	if result.ReasonCode != contracts.ReasonSafeDepTerminalFreeze {
		t.Fatalf("unexpected reason code: %s", result.ReasonCode)
	}
	if result.ProofGraphRef == "" || result.EvidencePackRef == "" {
		t.Fatalf("blocking result missing evidence refs: %+v", result)
	}
}

func TestControllerAllowsOnlyInspectionInDeprecatedReadOnly(t *testing.T) {
	controller := NewController(ControllerConfig{Clock: fixedSafeDepClock})
	blocked, err := controller.Gate(context.Background(), GateRequest{
		Signal: Signal{HazardCode: contracts.HazardEnginePinMismatch, ActiveClock: true, HighRiskLane: true},
		Action: "WORKSTATION_FILE_WRITE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if blocked.DispatchAllowed {
		t.Fatal("read-only deprecation allowed a mutating action")
	}
	allowed, err := controller.Gate(context.Background(), GateRequest{
		Signal: Signal{HazardCode: contracts.HazardEnginePinMismatch, ActiveClock: true, HighRiskLane: true},
		Action: "inspect",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.DispatchAllowed || !allowed.ReadOnly {
		t.Fatalf("inspection should be allowed read-only: %+v", allowed)
	}
}

func TestControllerActivatesDegradedNarrowingWithCapsuleQuorumAndContinuity(t *testing.T) {
	now := fixedSafeDepClock()
	controller := NewController(ControllerConfig{
		Clock:                fixedSafeDepClock,
		DefaultQuorum:        3,
		RequireDeadManActive: true,
		RequireTransparency:  true,
	})
	capsule := validCapsule(now)
	cp := contracts.ContinuityCheckpoint{
		CheckpointID:                 "cp-controller-1",
		OrgGenomeHash:                capsule.OrgGenomeHash,
		PolicyHash:                   capsule.PolicyHash,
		PolicyEpoch:                  capsule.PolicyEpoch,
		HazardSequence:               1,
		LamportClock:                 42,
		DeadManWindowID:              "dm-1",
		DeadManActive:                true,
		LatestAcceptedCheckpointHash: "",
		Nonce:                        "nonce-controller-1",
		AttestedTime:                 now,
		ExpiresAt:                    now.Add(time.Minute),
	}
	result, err := controller.Gate(context.Background(), GateRequest{
		Signal:     Signal{HazardCode: contracts.HazardCredentialExpired, ActiveClock: true},
		Checkpoint: cp,
		Capsule:    &capsule,
		Action:     "credential.rotate.propose",
		ToolName:   "github",
	})
	if err != nil {
		t.Fatalf("valid activation rejected: %v", err)
	}
	if !result.DispatchAllowed || !result.NarrowedScope || result.ActivationReceipt == nil {
		t.Fatalf("activation did not allow narrowed dispatch: %+v", result)
	}
	if result.ActivationReceipt.ActivationID == "" || result.ActivationReceipt.DelegationSessionID != "session-1" {
		t.Fatalf("activation receipt missing validated emergency authority: %+v", result.ActivationReceipt)
	}
	if _, err := controller.Gate(context.Background(), GateRequest{
		Signal:     Signal{HazardCode: contracts.HazardCredentialExpired, ActiveClock: true},
		Checkpoint: cp,
		Capsule:    &capsule,
		Action:     "credential.rotate.propose",
		ToolName:   "github",
	}); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestControllerRejectsEmergencyWidening(t *testing.T) {
	now := fixedSafeDepClock()
	controller := NewController(ControllerConfig{Clock: fixedSafeDepClock})
	capsule := validCapsule(now)
	cp := contracts.ContinuityCheckpoint{
		CheckpointID:   "cp-widen",
		OrgGenomeHash:  capsule.OrgGenomeHash,
		PolicyHash:     capsule.PolicyHash,
		PolicyEpoch:    capsule.PolicyEpoch,
		HazardSequence: 1,
		DeadManActive:  true,
		Nonce:          "nonce-widen",
		AttestedTime:   now,
		ExpiresAt:      now.Add(time.Minute),
	}
	_, err := controller.Gate(context.Background(), GateRequest{
		Signal:     Signal{HazardCode: contracts.HazardCredentialExpired, ActiveClock: true},
		Checkpoint: cp,
		Capsule:    &capsule,
		Action:     "infra.destroy",
		ToolName:   "github",
	})
	if !errors.Is(err, ErrEmergencyCapsuleInvalid) {
		t.Fatalf("expected widening rejection, got %v", err)
	}
}

func TestSQLiteContinuityStoreRejectsReplayAndRollback(t *testing.T) {
	db, err := sql.Open("sqlite", "file:safedep-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLiteContinuityStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := fixedSafeDepClock()
	cp := contracts.ContinuityCheckpoint{
		CheckpointID:   "cp-sql-1",
		PolicyEpoch:    1,
		HazardSequence: 1,
		Nonce:          "nonce-sql-1",
		AttestedTime:   now,
		ExpiresAt:      now.Add(time.Minute),
	}
	state, err := store.AppendCheckpoint(context.Background(), cp)
	if err != nil {
		t.Fatalf("append checkpoint: %v", err)
	}
	if state.CheckpointHash == "" {
		t.Fatal("missing checkpoint hash")
	}
	if _, err := store.AppendCheckpoint(context.Background(), cp); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected nonce replay rejection, got %v", err)
	}
	cp.CheckpointID = "cp-sql-rollback"
	cp.Nonce = "nonce-sql-2"
	if _, err := store.AppendCheckpoint(context.Background(), cp); !errors.Is(err, ErrContinuityStale) {
		t.Fatalf("expected sequence rollback rejection, got %v", err)
	}
}

func fixedSafeDepClock() time.Time {
	return time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
}
