package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// Snapshot creates a TrustSnapshot at the given lamport height.
// The snapshot hash is deterministic: given the same events, every node produces
// identical snapshot bytes (and therefore identical hashes).
func Snapshot(ctx context.Context, store EventStore, atLamport uint64) (*TrustSnapshot, error) {
	events, err := store.GetUpTo(ctx, atLamport)
	if err != nil {
		return nil, fmt.Errorf("get events up to lamport %d: %w", atLamport, err)
	}

	state := NewTrustState()
	if err := state.Reduce(events); err != nil {
		return nil, fmt.Errorf("reduce events: %w", err)
	}

	hash, err := computeStateHash(state)
	if err != nil {
		return nil, fmt.Errorf("compute state hash: %w", err)
	}

	return &TrustSnapshot{
		Lamport:      atLamport,
		SnapshotHash: hash,
		State:        *state,
		CreatedAt:    time.Now().UTC(),
	}, nil
}

// SnapshotFromRegistry creates a snapshot from the registry's current state.
func SnapshotFromRegistry(r *Registry) (*TrustSnapshot, error) {
	state := r.State()
	hash, err := computeStateHash(state)
	if err != nil {
		return nil, fmt.Errorf("compute state hash: %w", err)
	}

	return &TrustSnapshot{
		Lamport:      state.Lamport,
		SnapshotHash: hash,
		State:        *state,
		CreatedAt:    time.Now().UTC(),
	}, nil
}

// VerifySnapshot verifies that a snapshot matches the expected state at its lamport height.
func VerifySnapshot(ctx context.Context, store EventStore, snapshot *TrustSnapshot) (bool, error) {
	// Rebuild state from events up to the snapshot's lamport
	rebuilt, err := Snapshot(ctx, store, snapshot.Lamport)
	if err != nil {
		return false, fmt.Errorf("rebuild snapshot: %w", err)
	}
	return rebuilt.SnapshotHash == snapshot.SnapshotHash, nil
}

// Export serializes a snapshot to canonical JSON bytes.
func Export(snapshot *TrustSnapshot) ([]byte, error) {
	// Canonical JSON: sorted keys via JCS (Go's default map ordering is not stable,
	// but JCS handles deterministic sorting per RFC 8785).
	data, err := canonicalize.JCS(snapshot)
	if err != nil {
		return nil, fmt.Errorf("canonicalize snapshot: %w", err)
	}
	return data, nil
}

// Import deserializes a snapshot from JSON bytes and verifies its hash.
func Import(data []byte) (*TrustSnapshot, error) {
	var snapshot TrustSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}

	// Verify the embedded hash
	computed, err := computeStateHash(&snapshot.State)
	if err != nil {
		return nil, fmt.Errorf("compute state hash: %w", err)
	}
	if computed != snapshot.SnapshotHash {
		return nil, fmt.Errorf("snapshot hash mismatch: computed=%s, claimed=%s", computed, snapshot.SnapshotHash)
	}

	return &snapshot, nil
}

// computeStateHash computes a deterministic SHA256 of the trust state.
// Maps are sorted by key to ensure deterministic byte output.
func computeStateHash(state *TrustState) (string, error) {
	canonical, err := canonicalize.JCS(state)
	if err != nil {
		return "", fmt.Errorf("canonicalize state: %w", err)
	}
	h := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
