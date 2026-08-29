package reconcile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	policyReplayWatermarkVersion   = 1
	maxPolicyReplayWatermarkBytes  = 1 << 20
	maxPolicyReplayWatermarks      = 10_000
	persistedReplayWatermarkReason = "persisted replay watermark requires policy source revalidation"
)

var ErrPolicyReplayStateInvalid = errors.New("policy replay state invalid")

type policyReplayWatermarkState struct {
	Version    int                     `json:"version"`
	Watermarks []policyReplayWatermark `json:"watermarks"`
}

type policyReplayWatermark struct {
	TenantID       string `json:"tenant_id"`
	WorkspaceID    string `json:"workspace_id"`
	PolicyEpoch    uint64 `json:"policy_epoch"`
	PolicyHash     string `json:"policy_hash"`
	PolicyHeadHash string `json:"policy_head_hash"`
}

// PersistentSnapshotStore keeps active snapshots in memory and persists only
// the minimum replay watermark needed to reject rollback after a restart.
//
// ponytail: file serialization is process-local; move this state to a
// transactional shared store before running multiple Kernel writers.
type PersistentSnapshotStore struct {
	mu         sync.Mutex
	path       string
	memory     *AtomicSnapshotStore
	watermarks map[string]policyReplayWatermark
}

func NewPersistentSnapshotStore(path string) (*PersistentSnapshotStore, error) {
	if path == "" || path != strings.TrimSpace(path) {
		return nil, fmt.Errorf("%w: watermark path is invalid", ErrPolicyReplayStateInvalid)
	}
	path = filepath.Clean(path)
	watermarks, err := loadPolicyReplayWatermarks(path)
	if err != nil {
		return nil, err
	}
	store := &PersistentSnapshotStore{
		path:       path,
		memory:     NewAtomicSnapshotStore(),
		watermarks: watermarks,
	}
	for _, watermark := range watermarks {
		if err := store.memory.Swap(watermark.scope(), watermark.snapshot()); err != nil {
			return nil, fmt.Errorf("%w: restore watermark: %v", ErrPolicyReplayStateInvalid, err)
		}
	}
	return store, nil
}

func (s *PersistentSnapshotStore) Get(scope PolicyScope) (*EffectivePolicySnapshot, bool) {
	return s.memory.Get(scope)
}

func (s *PersistentSnapshotStore) Swap(scope PolicyScope, snapshot *EffectivePolicySnapshot) error {
	watermark, err := replayWatermarkFromSnapshot(scope, snapshot)
	if err != nil {
		return err
	}
	key := watermark.scope().Key()

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.watermarks[key]
	if ok && watermark.PolicyEpoch < existing.PolicyEpoch {
		return fmt.Errorf("%w: persisted epoch %d, proposed epoch %d", ErrPolicyEpochRollback, existing.PolicyEpoch, watermark.PolicyEpoch)
	}
	if ok && watermark.PolicyEpoch == existing.PolicyEpoch &&
		(watermark.PolicyHash != existing.PolicyHash || watermark.PolicyHeadHash != existing.PolicyHeadHash) {
		return fmt.Errorf("%w: epoch %d changed persisted policy head", ErrPolicyEpochEquivocation, watermark.PolicyEpoch)
	}
	if !ok || watermark != existing {
		next := make(map[string]policyReplayWatermark, len(s.watermarks)+1)
		for storedKey, stored := range s.watermarks {
			next[storedKey] = stored
		}
		next[key] = watermark
		if err := writePolicyReplayWatermarks(s.path, next); err != nil {
			return fmt.Errorf("persist policy replay watermark: %w", err)
		}
		s.watermarks = next
	}
	return s.memory.Swap(scope, snapshot)
}

func (s *PersistentSnapshotStore) Invalidate(scope PolicyScope, reason string) (*EffectivePolicySnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memory.Invalidate(scope, reason)
}

func replayWatermarkFromSnapshot(scope PolicyScope, snapshot *EffectivePolicySnapshot) (policyReplayWatermark, error) {
	if snapshot == nil {
		return policyReplayWatermark{}, errors.New("nil policy snapshot")
	}
	scope = scope.Normalize()
	if snapshot.Scope() != scope {
		return policyReplayWatermark{}, fmt.Errorf("%w: store scope %s, snapshot scope %s", ErrPolicyScopeMismatch, scope.Key(), snapshot.Scope().Key())
	}
	watermark := policyReplayWatermark{
		TenantID:       scope.TenantID,
		WorkspaceID:    scope.WorkspaceID,
		PolicyEpoch:    snapshot.PolicyEpoch,
		PolicyHash:     snapshot.PolicyHash,
		PolicyHeadHash: snapshot.PolicyHeadHash,
	}
	if err := validatePolicyReplayWatermark(watermark); err != nil {
		return policyReplayWatermark{}, err
	}
	return watermark, nil
}

func loadPolicyReplayWatermarks(path string) (map[string]policyReplayWatermark, error) {
	watermarks := make(map[string]policyReplayWatermark)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return watermarks, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load policy replay watermark: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: watermark file must be a private regular file", ErrPolicyReplayStateInvalid)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("load policy replay watermark: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxPolicyReplayWatermarkBytes+1))
	if err != nil {
		return nil, fmt.Errorf("load policy replay watermark: %w", err)
	}
	if len(data) > maxPolicyReplayWatermarkBytes {
		return nil, fmt.Errorf("%w: watermark file exceeds %d bytes", ErrPolicyReplayStateInvalid, maxPolicyReplayWatermarkBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state policyReplayWatermarkState
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("%w: decode watermark file: %v", ErrPolicyReplayStateInvalid, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: watermark file has trailing data", ErrPolicyReplayStateInvalid)
	}
	if state.Version != policyReplayWatermarkVersion || len(state.Watermarks) > maxPolicyReplayWatermarks {
		return nil, fmt.Errorf("%w: unsupported watermark state", ErrPolicyReplayStateInvalid)
	}
	for _, watermark := range state.Watermarks {
		if err := validatePolicyReplayWatermark(watermark); err != nil {
			return nil, err
		}
		key := watermark.scope().Key()
		if _, exists := watermarks[key]; exists {
			return nil, fmt.Errorf("%w: duplicate scope %s", ErrPolicyReplayStateInvalid, key)
		}
		watermarks[key] = watermark
	}
	return watermarks, nil
}

func writePolicyReplayWatermarks(path string, watermarks map[string]policyReplayWatermark) error {
	if len(watermarks) > maxPolicyReplayWatermarks {
		return fmt.Errorf("%w: watermark count exceeds %d", ErrPolicyReplayStateInvalid, maxPolicyReplayWatermarks)
	}
	state := policyReplayWatermarkState{Version: policyReplayWatermarkVersion}
	state.Watermarks = make([]policyReplayWatermark, 0, len(watermarks))
	for _, watermark := range watermarks {
		state.Watermarks = append(state.Watermarks, watermark)
	}
	sort.Slice(state.Watermarks, func(i, j int) bool {
		return state.Watermarks[i].scope().Key() < state.Watermarks[j].scope().Key()
	})
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxPolicyReplayWatermarkBytes {
		return fmt.Errorf("%w: watermark state exceeds %d bytes", ErrPolicyReplayStateInvalid, maxPolicyReplayWatermarkBytes)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%w: watermark target must be a regular file", ErrPolicyReplayStateInvalid)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func validatePolicyReplayWatermark(watermark policyReplayWatermark) error {
	if watermark.TenantID == "" || watermark.TenantID != strings.TrimSpace(watermark.TenantID) ||
		watermark.WorkspaceID == "" || watermark.WorkspaceID != strings.TrimSpace(watermark.WorkspaceID) ||
		watermark.PolicyEpoch == 0 || !validPolicyReplayDigest(watermark.PolicyHash) ||
		!validPolicyReplayDigest(watermark.PolicyHeadHash) {
		return fmt.Errorf("%w: watermark fields are invalid", ErrPolicyReplayStateInvalid)
	}
	return nil
}

func validPolicyReplayDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	digest := strings.TrimPrefix(value, prefix)
	if digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func (w policyReplayWatermark) scope() PolicyScope {
	return PolicyScope{TenantID: w.TenantID, WorkspaceID: w.WorkspaceID}
}

func (w policyReplayWatermark) snapshot() *EffectivePolicySnapshot {
	return &EffectivePolicySnapshot{
		TenantID:       w.TenantID,
		WorkspaceID:    w.WorkspaceID,
		PolicyEpoch:    w.PolicyEpoch,
		PolicyHash:     w.PolicyHash,
		PolicyHeadHash: w.PolicyHeadHash,
		Validation: ValidationStatus{
			Status: StatusInvalid,
			Reason: persistedReplayWatermarkReason,
		},
	}
}
