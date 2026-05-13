package registry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/manifest"
)

// PostgresRegistry implements Registry with SQL persistence.
type PostgresRegistry struct {
	db *sql.DB
}

func NewPostgresRegistry(db *sql.DB) *PostgresRegistry {
	return &PostgresRegistry{db: db}
}

const pgRegistrySchema = `
CREATE TABLE IF NOT EXISTS registry_bundles (
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	bundle_json JSONB NOT NULL,
	created_at TIMESTAMP NOT NULL,
	PRIMARY KEY (name, version)
);

CREATE TABLE IF NOT EXISTS registry_rollouts (
	name TEXT PRIMARY KEY,
	canary_version TEXT,
	canary_bundle_json JSONB,
	percentage INT,
	updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS registry_installations (
	tenant_id TEXT NOT NULL,
	pack_id TEXT NOT NULL,
	installed_at TIMESTAMP NOT NULL,
	PRIMARY KEY (tenant_id, pack_id)
);
`

func (r *PostgresRegistry) Init(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, pgRegistrySchema)
	return err
}

func (r *PostgresRegistry) Register(bundle *manifest.Bundle) error {
	if bundle == nil {
		return errors.New("nil bundle")
	}

	ctx := context.Background() // NOTE: Register() uses background context; interface remains context-free by design.

	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle: %w", err)
	}

	// Upsert bundle
	query := `
		INSERT INTO registry_bundles (name, version, bundle_json, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name, version) DO UPDATE 
		SET bundle_json = $3, created_at = $4
	`
	_, err = r.db.ExecContext(ctx, query, bundle.Manifest.Name, bundle.Manifest.Version, bundleJSON, time.Now().UTC())
	return err
}

func (r *PostgresRegistry) Unregister(name string) error {
	ctx := context.Background()
	_, err := r.db.ExecContext(ctx, "DELETE FROM registry_bundles WHERE name = $1", name)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, "DELETE FROM registry_rollouts WHERE name = $1", name)
	return err
}

func (r *PostgresRegistry) SetRollout(name string, canaryBundle *manifest.Bundle, percentage int) error {
	if percentage < 0 || percentage > 100 {
		return errors.New("percentage must be 0-100")
	}

	ctx := context.Background()
	bundleJSON, err := json.Marshal(canaryBundle)
	if err != nil {
		return fmt.Errorf("failed to marshal canary bundle: %w", err)
	}

	query := `
		INSERT INTO registry_rollouts (name, canary_version, canary_bundle_json, percentage, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (name) DO UPDATE
		SET canary_version = $2, canary_bundle_json = $3, percentage = $4, updated_at = $5
	`
	_, err = r.db.ExecContext(ctx, query, name, canaryBundle.Manifest.Version, bundleJSON, percentage, time.Now().UTC())
	return err
}

func (r *PostgresRegistry) Get(name string) (*manifest.Bundle, error) {
	ctx := context.Background()

	rows, err := r.db.QueryContext(ctx, "SELECT version, bundle_json FROM registry_bundles WHERE name = $1", name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	type versionedBundle struct {
		v *semver.Version
		b []byte
	}
	var bundles []versionedBundle

	for rows.Next() {
		var verStr string
		var bJSON []byte
		if err := rows.Scan(&verStr, &bJSON); err != nil {
			continue
		}
		v, err := semver.NewVersion(verStr)
		if err != nil {
			continue
		}
		bundles = append(bundles, versionedBundle{v: v, b: bJSON})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(bundles) == 0 {
		return nil, ErrModuleNotFound
	}

	sort.Slice(bundles, func(i, j int) bool {
		return bundles[i].v.GreaterThan(bundles[j].v)
	})

	var bundle manifest.Bundle
	if err := json.Unmarshal(bundles[0].b, &bundle); err != nil {
		return nil, err
	}
	return &bundle, nil
}

func (r *PostgresRegistry) GetForUser(name, userID string) (*manifest.Bundle, error) {
	ctx := context.Background()

	// 1. Check Rollout
	var canaryJSON []byte
	var percentage int
	err := r.db.QueryRowContext(ctx, "SELECT canary_bundle_json, percentage FROM registry_rollouts WHERE name = $1", name).Scan(&canaryJSON, &percentage)

	if err == nil && percentage > 0 {
		// Hashing logic
		hash := sha256.Sum256([]byte(strings.ToLower(userID)))
		// Use first 4 bytes for int
		val := uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3])
		// 0-100 check. val % 100.
		if int(val%100) < percentage {
			var bundle manifest.Bundle
			if err := json.Unmarshal(canaryJSON, &bundle); err == nil {
				return &bundle, nil
			}
		}
	}

	// 2. Fallback to Stable
	return r.Get(name)
}

func (r *PostgresRegistry) List() []*manifest.Bundle {
	ctx := context.Background()
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT ON (name) bundle_json 
		FROM registry_bundles 
		ORDER BY name, created_at DESC
	`)
	if err != nil {
		return []*manifest.Bundle{}
	}
	defer func() { _ = rows.Close() }()

	var list []*manifest.Bundle
	for rows.Next() {
		var bJSON []byte
		if err := rows.Scan(&bJSON); err == nil {
			var b manifest.Bundle
			if err := json.Unmarshal(bJSON, &b); err == nil {
				list = append(list, &b)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return []*manifest.Bundle{}
	}
	return list
}

func (r *PostgresRegistry) Install(tenantID, packID string) error {
	ctx := context.Background()
	var exists bool
	err := r.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM registry_bundles WHERE name = $1)", packID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("pack not found")
	}
	query := `INSERT INTO registry_installations (tenant_id, pack_id, installed_at) VALUES ($1, $2, $3) ON CONFLICT (tenant_id, pack_id) DO UPDATE SET installed_at = $3`
	_, err = r.db.ExecContext(ctx, query, tenantID, packID, time.Now().UTC())
	return err
}
