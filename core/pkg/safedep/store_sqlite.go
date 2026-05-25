package safedep

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

	_ "modernc.org/sqlite"
)

type SQLiteContinuityStore struct {
	db      *sql.DB
	writeMu sync.Mutex
}

func NewSQLiteContinuityStore(db *sql.DB) (*SQLiteContinuityStore, error) {
	if db == nil {
		return nil, fmt.Errorf("safe dep: sqlite db is required")
	}
	s := &SQLiteContinuityStore{db: db}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, fmt.Errorf("safe dep: enable WAL: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000;"); err != nil {
		return nil, fmt.Errorf("safe dep: set busy timeout: %w", err)
	}
	if err := s.migrate(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteContinuityStore) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS safedep_checkpoints (
			checkpoint_id TEXT PRIMARY KEY,
			checkpoint_hash TEXT NOT NULL UNIQUE,
			hazard_sequence INTEGER NOT NULL UNIQUE,
			policy_epoch INTEGER NOT NULL,
			lamport_clock INTEGER NOT NULL DEFAULT 0,
			dead_man_window_id TEXT NOT NULL DEFAULT '',
			nonce TEXT NOT NULL UNIQUE,
			attested_time TEXT NOT NULL,
			expires_at TEXT NOT NULL DEFAULT '',
			payload_json TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS safedep_activations (
			activation_id TEXT PRIMARY KEY,
			capsule_id TEXT NOT NULL,
			aperture_id TEXT NOT NULL,
			hazard_code TEXT NOT NULL,
			state TEXT NOT NULL,
			policy_epoch INTEGER NOT NULL,
			expires_at TEXT NOT NULL,
			closed_at TEXT NOT NULL DEFAULT '',
			payload_json TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_safedep_checkpoints_sequence ON safedep_checkpoints(hazard_sequence);`,
		`CREATE INDEX IF NOT EXISTS idx_safedep_activations_expiry ON safedep_activations(expires_at);`,
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteContinuityStore) Latest(ctx context.Context) (ContinuityState, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT checkpoint_id, checkpoint_hash, hazard_sequence, policy_epoch, lamport_clock, dead_man_window_id
		FROM safedep_checkpoints ORDER BY hazard_sequence DESC LIMIT 1`)
	var state ContinuityState
	err := row.Scan(&state.CheckpointID, &state.CheckpointHash, &state.HazardSequence, &state.PolicyEpoch, &state.LamportClock, &state.DeadManWindowID)
	if err == sql.ErrNoRows {
		return ContinuityState{}, false, nil
	}
	if err != nil {
		return ContinuityState{}, false, err
	}
	return state, true, nil
}

func (s *SQLiteContinuityStore) AppendCheckpoint(ctx context.Context, checkpoint contracts.ContinuityCheckpoint) (ContinuityState, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ContinuityState{}, err
	}
	defer func() { _ = tx.Rollback() }()

	latest, ok, err := latestInTx(ctx, tx)
	if err != nil {
		return ContinuityState{}, err
	}
	if ok {
		if checkpoint.HazardSequence <= latest.HazardSequence {
			return ContinuityState{}, fmt.Errorf("%w: hazard sequence rollback", ErrContinuityStale)
		}
		if checkpoint.LatestAcceptedCheckpointHash != "" && checkpoint.LatestAcceptedCheckpointHash != latest.CheckpointHash {
			return ContinuityState{}, fmt.Errorf("%w: latest checkpoint hash mismatch", ErrContinuityStale)
		}
	}
	var nonceCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM safedep_checkpoints WHERE nonce = ?`, checkpoint.Nonce).Scan(&nonceCount); err != nil {
		return ContinuityState{}, err
	}
	if nonceCount > 0 {
		return ContinuityState{}, fmt.Errorf("%w: nonce replay", ErrContinuityStale)
	}
	hash, err := CheckpointHash(checkpoint)
	if err != nil {
		return ContinuityState{}, err
	}
	payload, err := json.Marshal(checkpoint)
	if err != nil {
		return ContinuityState{}, err
	}
	state := ContinuityState{
		CheckpointID:    checkpoint.CheckpointID,
		CheckpointHash:  hash,
		HazardSequence:  checkpoint.HazardSequence,
		PolicyEpoch:     checkpoint.PolicyEpoch,
		LamportClock:    checkpoint.LamportClock,
		DeadManWindowID: checkpoint.DeadManWindowID,
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO safedep_checkpoints
		(checkpoint_id, checkpoint_hash, hazard_sequence, policy_epoch, lamport_clock, dead_man_window_id, nonce, attested_time, expires_at, payload_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		checkpoint.CheckpointID,
		hash,
		checkpoint.HazardSequence,
		checkpoint.PolicyEpoch,
		checkpoint.LamportClock,
		checkpoint.DeadManWindowID,
		checkpoint.Nonce,
		checkpoint.AttestedTime.UTC().Format(time.RFC3339Nano),
		formatTime(checkpoint.ExpiresAt),
		string(payload),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return ContinuityState{}, err
	}
	if err := tx.Commit(); err != nil {
		return ContinuityState{}, err
	}
	return state, nil
}

func (s *SQLiteContinuityStore) StoreActivation(ctx context.Context, receipt contracts.ActivationReceipt) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	payload, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO safedep_activations
		(activation_id, capsule_id, aperture_id, hazard_code, state, policy_epoch, expires_at, payload_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(activation_id) DO UPDATE SET payload_json = excluded.payload_json, expires_at = excluded.expires_at`,
		receipt.ActivationID,
		receipt.CapsuleID,
		receipt.ApertureID,
		string(receipt.HazardCode),
		string(receipt.State),
		receipt.PolicyEpoch,
		formatTime(receipt.ExpiresAt),
		string(payload),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *SQLiteContinuityStore) GetActivation(ctx context.Context, activationID string) (contracts.ActivationReceipt, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT payload_json FROM safedep_activations WHERE activation_id = ?`, activationID)
	var payload string
	if err := row.Scan(&payload); err == sql.ErrNoRows {
		return contracts.ActivationReceipt{}, false, nil
	} else if err != nil {
		return contracts.ActivationReceipt{}, false, err
	}
	var receipt contracts.ActivationReceipt
	if err := json.Unmarshal([]byte(payload), &receipt); err != nil {
		return contracts.ActivationReceipt{}, false, err
	}
	return receipt, true, nil
}

func (s *SQLiteContinuityStore) CloseActivation(ctx context.Context, activationID string, checkpoint contracts.ContinuityCheckpoint) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.ExecContext(ctx, `UPDATE safedep_activations SET closed_at = ? WHERE activation_id = ?`,
		formatTime(checkpoint.AttestedTime),
		activationID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("safe dep: activation %q not found", activationID)
	}
	return nil
}

func latestInTx(ctx context.Context, tx *sql.Tx) (ContinuityState, bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT checkpoint_id, checkpoint_hash, hazard_sequence, policy_epoch, lamport_clock, dead_man_window_id
		FROM safedep_checkpoints ORDER BY hazard_sequence DESC LIMIT 1`)
	var state ContinuityState
	err := row.Scan(&state.CheckpointID, &state.CheckpointHash, &state.HazardSequence, &state.PolicyEpoch, &state.LamportClock, &state.DeadManWindowID)
	if err == sql.ErrNoRows {
		return ContinuityState{}, false, nil
	}
	if err != nil {
		return ContinuityState{}, false, err
	}
	return state, true, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
