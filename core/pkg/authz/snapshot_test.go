package authz

import (
	"context"
	"testing"
	"time"
)

func TestRelationshipSnapshotHashDeterministic(t *testing.T) {
	ctx := context.Background()
	a := NewEngine()
	b := NewEngine()
	tuples := []RelationTuple{
		{Object: "tool:deploy", Relation: "can_call", Subject: "user:alice"},
		{Object: "group:ops", Relation: "member", Subject: "user:alice"},
	}
	for _, tuple := range tuples {
		if err := a.WriteTuple(ctx, tuple); err != nil {
			t.Fatalf("write tuple: %v", err)
		}
	}
	for i := len(tuples) - 1; i >= 0; i-- {
		if err := b.WriteTuple(ctx, tuples[i]); err != nil {
			t.Fatalf("write tuple: %v", err)
		}
	}

	hashA, err := a.RelationshipSnapshotHash()
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hashB, err := b.RelationshipSnapshotHash()
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if hashA != hashB {
		t.Fatalf("snapshot hash differs by tuple insertion order: %s != %s", hashA, hashB)
	}
}

func TestSnapshotCheckSealsDecisionAndTupleHash(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine()
	if err := engine.WriteTuple(ctx, RelationTuple{Object: "tool:deploy", Relation: "can_call", Subject: "user:alice"}); err != nil {
		t.Fatalf("write tuple: %v", err)
	}
	checkedAt := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	snapshot, err := engine.SnapshotCheck(ctx, "openfga-compatible", "model-a", "tool:deploy", "can_call", "user:alice", checkedAt, false, false)
	if err != nil {
		t.Fatalf("snapshot check: %v", err)
	}
	if !snapshot.Decision {
		t.Fatal("expected relationship decision to allow")
	}
	if snapshot.RelationshipHash == "" || snapshot.SnapshotHash == "" {
		t.Fatalf("snapshot hashes were not populated: %#v", snapshot)
	}

	if err := engine.WriteTuple(ctx, RelationTuple{Object: "tool:destroy", Relation: "can_call", Subject: "user:alice"}); err != nil {
		t.Fatalf("write tuple 2: %v", err)
	}
	changed, err := engine.SnapshotCheck(ctx, "openfga-compatible", "model-a", "tool:deploy", "can_call", "user:alice", checkedAt, false, false)
	if err != nil {
		t.Fatalf("snapshot changed: %v", err)
	}
	if changed.RelationshipHash == snapshot.RelationshipHash {
		t.Fatal("relationship hash did not change after tuple mutation")
	}
}

func TestSnapshotCheckBindsStaleAndModelMismatch(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine()
	if err := engine.WriteTuple(ctx, RelationTuple{Object: "tool:deploy", Relation: "can_call", Subject: "user:alice"}); err != nil {
		t.Fatalf("write tuple: %v", err)
	}
	checkedAt := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	fresh, err := engine.SnapshotCheck(ctx, "openfga-compatible", "model-a", "tool:deploy", "can_call", "user:alice", checkedAt, false, false)
	if err != nil {
		t.Fatalf("fresh snapshot: %v", err)
	}
	stale, err := engine.SnapshotCheck(ctx, "openfga-compatible", "model-a", "tool:deploy", "can_call", "user:alice", checkedAt, true, true)
	if err != nil {
		t.Fatalf("stale snapshot: %v", err)
	}
	if fresh.SnapshotHash == stale.SnapshotHash {
		t.Fatal("snapshot hash did not bind stale/model mismatch state")
	}
}
