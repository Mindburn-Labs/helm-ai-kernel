package activitytrail

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidPage is a malformed or cross-scope cursor, not a storage failure.
var ErrInvalidPage = errors.New("invalid activity page")

// CoverageMap is an authoritative read of the source configuration and the
// observed-only ledger. A source absent from this table is unmanaged.
func (s *Service) CoverageMap(ctx context.Context, scope Scope) (Coverage, error) {
	if err := scope.validate(); err != nil {
		return Coverage{}, err
	}
	coverage := Coverage{Repository: scope.Repository, Class: CoverageUnmanaged}
	err := s.inTenant(ctx, scope.TenantID, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		var pollAt, eventAt, nextEvent sql.NullTime
		err := tx.QueryRowContext(ctx, `SELECT enabled,default_branch,head_sha,last_poll_at,last_poll_error,
			last_event_poll_at,next_event_poll_at,event_window_capped FROM gateway_activity_sources
			WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3`, scope.TenantID, scope.WorkspaceID, scope.Repository).
			Scan(&coverage.Enabled, &coverage.DefaultBranch, &coverage.HeadSHA, &pollAt, &coverage.LastPollError, &eventAt, &nextEvent, &coverage.EventWindowCapped)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if coverage.Enabled {
			coverage.Class = CoverageObservedOnly
		}
		if pollAt.Valid {
			coverage.LastPollAt = &pollAt.Time
		}
		if eventAt.Valid {
			coverage.LastEventPollAt = &eventAt.Time
		}
		if nextEvent.Valid {
			coverage.NextEventPollAt = &nextEvent.Time
		}
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM gateway_activity_observations
			WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3
			AND (actor_login IS NULL OR provider_time IS NULL)`, scope.TenantID, scope.WorkspaceID, scope.Repository).
			Scan(&coverage.UnattributedCount)
		if err != nil {
			return err
		}
		coverage.AttributionComplete = coverage.Enabled && coverage.LastPollAt != nil && coverage.LastEventPollAt != nil &&
			coverage.UnattributedCount == 0 && coverage.LastPollError == "" && !coverage.EventWindowCapped
		return nil
	})
	return coverage, err
}

type pageCursor struct {
	TenantID    string    `json:"tenant_id"`
	WorkspaceID string    `json:"workspace_id"`
	Repository  string    `json:"repository"`
	ObservedAt  time.Time `json:"observed_at"`
	FactDigest  string    `json:"fact_digest"`
}

func decodePage(scope Scope, page Page) (pageCursor, int, error) {
	limit := page.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 0 || limit > 100 {
		return pageCursor{}, 0, fmt.Errorf("%w: limit must be between 1 and 100", ErrInvalidPage)
	}
	if page.After == "" {
		return pageCursor{}, limit, nil
	}
	if len(page.After) > 1024 {
		return pageCursor{}, 0, fmt.Errorf("%w: cursor is too long", ErrInvalidPage)
	}
	raw, err := base64.RawURLEncoding.DecodeString(page.After)
	if err != nil {
		return pageCursor{}, 0, fmt.Errorf("%w: cursor encoding", ErrInvalidPage)
	}
	var cursor pageCursor
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return pageCursor{}, 0, fmt.Errorf("%w: cursor JSON", ErrInvalidPage)
	}
	if cursor.TenantID != scope.TenantID || cursor.WorkspaceID != scope.WorkspaceID || cursor.Repository != scope.Repository || cursor.ObservedAt.IsZero() {
		return pageCursor{}, 0, fmt.Errorf("%w: cursor does not match scope", ErrInvalidPage)
	}
	digest, err := hex.DecodeString(cursor.FactDigest)
	if err != nil || len(digest) != 32 {
		return pageCursor{}, 0, fmt.Errorf("%w: cursor digest", ErrInvalidPage)
	}
	return cursor, limit, nil
}

func encodePage(scope Scope, o Observation) (string, error) {
	raw, err := json.Marshal(pageCursor{TenantID: scope.TenantID, WorkspaceID: scope.WorkspaceID, Repository: scope.Repository,
		ObservedAt: o.ObservedAt, FactDigest: o.FactDigest})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ListObservations returns a stable newest-first page. Scope is checked
// against the cursor and enforced again by PostgreSQL FORCE RLS.
func (s *Service) ListObservations(ctx context.Context, scope Scope, page Page) ([]Observation, string, error) {
	if err := scope.validate(); err != nil {
		return nil, "", err
	}
	cursor, limit, err := decodePage(scope, page)
	if err != nil {
		return nil, "", err
	}
	var out []Observation
	err = s.inTenant(ctx, scope.TenantID, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(tx *sql.Tx) error {
		var rows *sql.Rows
		var err error
		if page.After == "" {
			rows, err = tx.QueryContext(ctx, `SELECT repository,ref,before_sha,after_sha,fact_digest,actor_login,
				provider_time,observed_at,source,coverage,governed FROM gateway_activity_observations
				WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3
				ORDER BY observed_at DESC,fact_digest DESC LIMIT $4`, scope.TenantID, scope.WorkspaceID, scope.Repository, limit+1)
		} else {
			digest, _ := hex.DecodeString(cursor.FactDigest)
			rows, err = tx.QueryContext(ctx, `SELECT repository,ref,before_sha,after_sha,fact_digest,actor_login,
				provider_time,observed_at,source,coverage,governed FROM gateway_activity_observations
				WHERE tenant_id=$1 AND workspace_id=$2 AND repository=$3
				AND (observed_at,fact_digest) < ($4,$5)
				ORDER BY observed_at DESC,fact_digest DESC LIMIT $6`, scope.TenantID, scope.WorkspaceID, scope.Repository, cursor.ObservedAt, digest, limit+1)
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o Observation
			var digest []byte
			var actor sql.NullString
			var at sql.NullTime
			if err := rows.Scan(&o.Repository, &o.Ref, &o.BeforeSHA, &o.AfterSHA, &digest, &actor, &at, &o.ObservedAt, &o.Source, &o.Coverage, &o.Governed); err != nil {
				return err
			}
			o.FactDigest = hex.EncodeToString(digest)
			if actor.Valid {
				o.ActorLogin = actor.String
			}
			if at.Valid {
				o.ProviderTime = &at.Time
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", err
	}
	if len(out) <= limit {
		return out, "", nil
	}
	out = out[:limit]
	next, err := encodePage(scope, out[len(out)-1])
	return out, next, err
}

// ListOwnerExceptions is the exact observed-only change projection. Every
// returned row lacks governed attempt, approval and permit references by
// construction of the activity schema.
func (s *Service) ListOwnerExceptions(ctx context.Context, scope Scope, page Page) ([]OwnerException, string, error) {
	observations, next, err := s.ListObservations(ctx, scope, page)
	if err != nil {
		return nil, "", err
	}
	out := make([]OwnerException, 0, len(observations))
	for _, o := range observations {
		if o.Governed || o.Coverage != CoverageObservedOnly {
			return nil, "", fmt.Errorf("activity ledger has an invalid coverage classification")
		}
		out = append(out, OwnerException{Observation: o, Reason: OutsideHELMReason})
	}
	return out, next, nil
}
