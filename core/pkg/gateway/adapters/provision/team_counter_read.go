package provision

// The team counter is admission's own enforcement state. This read selects one
// applied team limit and its current buckets; it never sums copied limits on
// parent or child mandates and never creates a missing bucket.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

var (
	ErrTeamCounterBinding = errors.New("the team counter binding is not current")
	ErrTeamCounterAbsent  = errors.New("a current team counter bucket has not been materialized")
	ErrTeamCounterInvalid = errors.New("the team counter cannot be reported")
)

const maxTeamCounterSpan = 744

// TeamCounterBinding is copied from a GetProvisioning readback. The caller
// supplies the exact team node and limit, including the limit's dimensions;
// tenant and workspace come only from its authenticated credential.
type TeamCounterBinding struct {
	OrgRef       string `json:"org_ref"`
	VersionRef   string `json:"version_ref"`
	PlanDigest   string `json:"plan_digest"`
	Revision     int64  `json:"revision,string"`
	TeamNode     string `json:"team_node"`
	MandateID    string `json:"mandate_id"`
	LimitID      string `json:"limit_id"`
	LimitVersion int64  `json:"limit_version,string"`
	Unit         string `json:"unit"`
	Measure      string `json:"measure"`
	Window       string `json:"window"`
	Span         int    `json:"span"`
}

func (b TeamCounterBinding) valid() bool {
	digest, err := hex.DecodeString(b.PlanDigest)
	m, me := uuid.Parse(b.MandateID)
	l, le := uuid.Parse(b.LimitID)
	return effectargs.ValidOrgRef(b.OrgRef) && b.VersionRef != "" &&
		strings.HasPrefix(b.TeamNode, "team:") && len(b.TeamNode) > len("team:") &&
		authorityrows.ValidPrincipalID(b.TeamNode) && b.Revision > 0 && b.LimitVersion > 0 &&
		err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == b.PlanDigest &&
		me == nil && le == nil && m != uuid.Nil && l != uuid.Nil &&
		m.String() == b.MandateID && l.String() == b.LimitID &&
		b.Unit != "" && (b.Measure == "sum" || b.Measure == "count" || b.Measure == "distinct") &&
		(b.Window == "none" || b.Window == "hour" || b.Window == "day" || b.Window == "month") &&
		b.Span >= 1 && b.Span <= maxTeamCounterSpan && (b.Window != "none" || b.Span == 1)
}

type TeamCounterBucket struct {
	Start    time.Time `json:"start"`
	Used     int64     `json:"used,string"`
	Reserved int64     `json:"reserved,string"`
}

// TeamCounterSnapshot is one repeatable-read PostgreSQL snapshot. SnapshotID
// is pg_current_snapshot(), an observation point rather than a signed receipt.
// Used and Reserved are the sum of only this limit's active window buckets.
type TeamCounterSnapshot struct {
	Binding    TeamCounterBinding  `json:"binding"`
	ObservedAt time.Time           `json:"observed_at"`
	SnapshotID string              `json:"db_snapshot"`
	Cap        int64               `json:"cap,string"`
	Used       int64               `json:"used,string"`
	Reserved   int64               `json:"reserved,string"`
	WithinCap  bool                `json:"within_cap"`
	Buckets    []TeamCounterBucket `json:"buckets"`
}

// GetTeamCounter reads the exact live TEAM limit through the tenant's forced
// RLS role. A missing authority row, stale plan, foreign workspace, or absent
// counter bucket fails closed. The transaction is read only and creates no
// counter, reservation, posting, or attempt.
func GetTeamCounter(ctx context.Context, store *authorityrows.Store, tenant, workspace, principal string, b TeamCounterBinding) (*TeamCounterSnapshot, error) {
	if !b.valid() || tenant == "" || workspace == "" || principal == "" {
		return nil, authorityrows.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := &TeamCounterSnapshot{Binding: b, Buckets: []TeamCounterBucket{}}
	err := store.ReadInTenant(ctx, tenant, func(tx *authorityrows.Tx) error {
		if err := tx.SQL().QueryRowContext(ctx, `SELECT clock_timestamp(), pg_current_snapshot()::text`).
			Scan(&out.ObservedAt, &out.SnapshotID); err != nil {
			return err
		}
		p, err := tx.Principal(ctx, principal)
		if errors.Is(err, authorityrows.ErrNotFound) || (err == nil && (!p.Active || p.Kind != authorityrows.PrincipalService)) {
			return ErrBudgetReader
		}
		if err != nil {
			return err
		}
		applied, err := LoadApplied(ctx, tx.SQL(), tenant, b.OrgRef, false)
		if err != nil {
			return err
		}
		if applied == nil {
			return ErrNotProvisioned
		}
		var provisionWorkspace string
		if err := tx.SQL().QueryRowContext(ctx, `SELECT workspace_id FROM authority_effect_attempts
			WHERE tenant_id=$1 AND attempt_id=$2`, tenant, applied.AttemptID).Scan(&provisionWorkspace); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotProvisioned
			}
			return err
		}
		if provisionWorkspace != workspace {
			return ErrNotProvisioned
		}
		if principal != applied.Provisioner && principal != b.TeamNode {
			return ErrBudgetReader
		}
		var node AppliedNode
		matches := 0
		for _, candidate := range applied.Nodes {
			if candidate.Node == b.TeamNode {
				node, matches = candidate, matches+1
			}
		}
		if matches != 1 || node.MandateID != b.MandateID || node.HolderID != b.TeamNode ||
			applied.VersionRef != b.VersionRef || applied.Digest != b.PlanDigest || applied.Revision != b.Revision {
			return ErrTeamCounterBinding
		}
		m, err := tx.Mandate(ctx, uuid.MustParse(b.MandateID))
		if errors.Is(err, authorityrows.ErrNotFound) {
			return ErrTeamCounterBinding
		}
		if err != nil {
			return err
		}
		if !m.Active || m.HolderID != b.TeamNode || out.ObservedAt.Before(m.Terms.ValidFrom) || !out.ObservedAt.Before(m.Terms.ValidUntil) {
			return ErrTeamCounterBinding
		}
		team, err := tx.Principal(ctx, b.TeamNode)
		if errors.Is(err, authorityrows.ErrNotFound) {
			return ErrTeamCounterBinding
		}
		if err != nil {
			return err
		}
		if !team.Active || team.Kind != authorityrows.PrincipalService {
			return ErrTeamCounterBinding
		}
		limit, err := tx.Limit(ctx, uuid.MustParse(b.LimitID))
		if errors.Is(err, authorityrows.ErrNotFound) {
			return ErrTeamCounterBinding
		}
		if err != nil {
			return err
		}
		if limit.Version != b.LimitVersion || limit.Spec.MandateID == nil || limit.Spec.MandateID.String() != b.MandateID ||
			limit.Spec.Unit != b.Unit || limit.Spec.Measure != b.Measure || limit.Spec.Window != b.Window || limit.Spec.Span != b.Span {
			return ErrTeamCounterBinding
		}
		var membershipWorkspace string
		err = tx.SQL().QueryRowContext(ctx, `SELECT a.workspace_id FROM authority_provision_limits h
			JOIN authority_effect_attempts a ON a.tenant_id=h.tenant_id AND a.attempt_id=h.attempt_id
			WHERE h.tenant_id=$1 AND h.org_ref=$2 AND h.node=$3 AND h.mandate_id=$4 AND h.limit_id=$5
			AND h.first_revision <= $6`, tenant, b.OrgRef, b.TeamNode, b.MandateID, b.LimitID, b.Revision).Scan(&membershipWorkspace)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && membershipWorkspace != workspace) {
			return ErrTeamCounterBinding
		}
		if err != nil {
			return err
		}
		out.Cap = limit.Spec.Value
		var starts [maxTeamCounterSpan]time.Time
		for back := 0; back < b.Span; back++ {
			starts[back] = teamBucketStart(b.Window, out.ObservedAt, back)
		}
		rows, err := tx.SQL().QueryContext(ctx, `SELECT bucket_start, used, reserved FROM authority_counters
			WHERE tenant_id=$1 AND limit_id=$2 AND bucket_start = ANY ($3::timestamptz[])`,
			tenant, b.LimitID, pq.Array(starts[:b.Span]))
		if err != nil {
			return err
		}
		found := map[int64]TeamCounterBucket{}
		for rows.Next() {
			var bucket TeamCounterBucket
			if err := rows.Scan(&bucket.Start, &bucket.Used, &bucket.Reserved); err != nil {
				_ = rows.Close()
				return err
			}
			found[bucket.Start.UnixNano()] = bucket
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for back := 0; back < b.Span; back++ {
			bucket, ok := found[starts[back].UnixNano()]
			if !ok {
				return ErrTeamCounterAbsent
			}
			if bucket.Used < 0 || bucket.Reserved < 0 || bucket.Used > math.MaxInt64-out.Used || bucket.Reserved > math.MaxInt64-out.Reserved {
				return ErrTeamCounterInvalid
			}
			out.Used += bucket.Used
			out.Reserved += bucket.Reserved
			out.Buckets = append(out.Buckets, bucket)
		}
		if out.Used > math.MaxInt64-out.Reserved {
			return ErrTeamCounterInvalid
		}
		out.WithinCap = out.Used+out.Reserved <= out.Cap
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.ObservedAt = out.ObservedAt.UTC()
	return out, nil
}

// Mirrors admission.bucketStart. Both select UTC buckets; a windowless limit
// has one epoch bucket. This function performs no storage mutation.
func teamBucketStart(window string, now time.Time, back int) time.Time {
	u := now.UTC()
	switch window {
	case "hour":
		return u.Truncate(time.Hour).Add(-time.Duration(back) * time.Hour)
	case "day":
		return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -back)
	case "month":
		return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -back, 0)
	default:
		return time.Unix(0, 0).UTC()
	}
}
