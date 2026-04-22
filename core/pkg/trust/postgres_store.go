package trust

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/lib/pq"
)

// PostgresTrustStore implements TrustStore, VersionStore, and KeyStatusStore.
type PostgresTrustStore struct {
	db *sql.DB
}

func NewPostgresTrustStore(db *sql.DB) *PostgresTrustStore {
	return &PostgresTrustStore{db: db}
}

// --- TrustStore (TUF Metadata) ---

func (s *PostgresTrustStore) Load() (*TUFMetadata, error) {
	// For simplicity, we assume we store the whole bundle or individual roles.
	// Let's assume we store individual roles and reconstruct.
	// Or we can just store the whole metadata object if it's small enough?
	// The `TUFMetadata` struct has Root, Timestamp, Snapshot, Targets.
	// Let's reuse the table structure: role_name -> json_data.

	meta := &TUFMetadata{}

	roles := []string{"root", "timestamp", "snapshot", "targets"}
	for _, role := range roles {
		var data []byte
		err := s.db.QueryRowContext(context.Background(), "SELECT json_data FROM trust_metadata WHERE role_name = $1", role).Scan(&data)
		if err == sql.ErrNoRows {
			continue // Partial metadata is allowed during bootstrap
		}
		if err != nil {
			return nil, err
		}

		var signedRole SignedRole
		if err := json.Unmarshal(data, &signedRole); err != nil {
			return nil, fmt.Errorf("failed to unmarshal role %s: %w", role, err)
		}

		switch role {
		case "root":
			meta.Root = &signedRole
		case "timestamp":
			meta.Timestamp = &signedRole
		case "snapshot":
			meta.Snapshot = &signedRole
		case "targets":
			meta.Targets = &signedRole
		}
	}

	if meta.Root == nil {
		return nil, nil // No root means no valid metadata
	}
	return meta, nil
}

func (s *PostgresTrustStore) Save(metadata *TUFMetadata) error {
	if metadata == nil {
		return nil
	}

	// Helper to save a role
	saveRole := func(name string, role *SignedRole) error {
		if role == nil {
			return nil
		}
		data, err := json.Marshal(role)
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(context.Background(), `
			INSERT INTO trust_metadata (role_name, json_data, updated_at) 
			VALUES ($1, $2, NOW())
			ON CONFLICT (role_name) DO UPDATE SET json_data = $2, updated_at = NOW()
		`, name, data)
		return err
	}

	if err := saveRole("root", metadata.Root); err != nil {
		return err
	}
	if err := saveRole("timestamp", metadata.Timestamp); err != nil {
		return err
	}
	if err := saveRole("snapshot", metadata.Snapshot); err != nil {
		return err
	}
	if err := saveRole("targets", metadata.Targets); err != nil {
		return err
	}
	return nil
}

// --- VersionStore ---

func (s *PostgresTrustStore) GetInstalledVersion(packID string) (*semver.Version, error) {
	var verStr string
	err := s.db.QueryRowContext(context.Background(), "SELECT version FROM trust_versions WHERE pack_id = $1", packID).Scan(&verStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return semver.NewVersion(verStr)
}

func (s *PostgresTrustStore) SetInstalledVersion(packID string, version *semver.Version) error {
	_, err := s.db.ExecContext(context.Background(), `
		INSERT INTO trust_versions (pack_id, version, installed_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (pack_id) DO UPDATE SET version = $2, installed_at = NOW()
	`, packID, version.String())
	return err
}

// --- KeyStatusStore ---

func (s *PostgresTrustStore) GetKeyStatus(keyID string) (KeyStatus, error) {
	var status string
	err := s.db.QueryRowContext(context.Background(), "SELECT status FROM trust_key_status WHERE key_id = $1", keyID).Scan(&status)
	if err == sql.ErrNoRows {
		return KeyStatusActive, nil // Default to active if not explicitly revoked
	}
	if err != nil {
		return "", err
	}
	return KeyStatus(status), nil
}

func (s *PostgresTrustStore) GetQuarantineOverride(keyID string) (*QuarantineOverride, error) {
	var o QuarantineOverride
	var authBy []string
	var sigs []string
	var expiresAt time.Time

	err := s.db.QueryRowContext(context.Background(), `
		SELECT reason, authorized_by, expires_at, signatures 
		FROM trust_quarantine_overrides WHERE key_id = $1
	`, keyID).Scan(&o.Reason, (*pq.StringArray)(&authBy), &expiresAt, (*pq.StringArray)(&sigs))

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	o.PublisherKeyID = keyID
	o.AuthorizedBy = authBy
	o.ExpiresAt = expiresAt.Format(time.RFC3339) // Simpler than parsing back/forth if struct uses string
	o.Signatures = sigs

	// Valid check logic in struct handles string parsing, but here we scanned time.Time.
	// QuarantineOverride struct uses string for ExpiresAt.
	return &o, nil
}
