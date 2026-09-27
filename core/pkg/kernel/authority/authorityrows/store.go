package authorityrows

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	// ErrExists reports a tenant, principal or effect type that is already there.
	ErrExists = errors.New("authority rows: already exists")
	// ErrStopped reports a delegation under an active stop on the tenant, the
	// delegator, or a mandate of the chain.
	ErrStopped = errors.New("authority rows: stopped")
)

// ScopeKind names the control row a stop applies to.
type ScopeKind string

const (
	ScopeTenant     ScopeKind = "tenant"
	ScopePrincipal  ScopeKind = "principal"
	ScopeMandate    ScopeKind = "mandate"
	ScopeEffectType ScopeKind = "effect_type"
)

// Scope is a stop's target: the tenant (Key is the tenant id), a principal
// id, a mandate id, or an effect type.
type Scope struct {
	Kind ScopeKind
	Key  string
}

// WideningApproval authorizes a transition that widens authority: activating
// a root mandate or lifting a stop. RequesterID asked for it; ApproverID, an
// active, human principal of the tenant, approved it. The approver is neither
// the requester nor the principal whose authority widens (the new mandate's
// holder, or the stopped principal or mandate holder). The zero value is no
// approval. HELM-751 replaces it with the approval record that the gateway's
// Approve path writes for the helm.authority.* effect.
type WideningApproval struct {
	RequesterID string
	ApproverID  string
}

// LimitSpec describes a limit: a cap of Value units per window. A nil
// MandateID makes it a tenant-level resource account. Span is the number of
// window buckets a sliding window covers (1 for a fixed window).
type LimitSpec struct {
	MandateID *uuid.UUID
	Unit      string // e.g. "usd_cents", "effects"
	Measure   string // sum | count | distinct
	Window    string // none | hour | day | month
	Value     int64
	Span      int
}

// Limit is a stored limit.
type Limit struct {
	ID      uuid.UUID
	Spec    LimitSpec
	Version int64
}

// StopSpec describes a stop. A nil ExpiresAt stops until lifted.
type StopSpec struct {
	Scope     Scope
	Reason    string
	IssuedBy  string
	ExpiresAt *time.Time
}

// Stop is a stored stop.
type Stop struct {
	ID        uuid.UUID
	Scope     Scope
	Reason    string
	IssuedBy  string
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// Store reads and writes the authority rows. Every call runs in one READ
// COMMITTED transaction bound to its tenant through app.current_tenant, so
// forced row security confines it to that tenant's rows.
type Store struct {
	db *sql.DB
}

// New returns a Store over db. The schema must already exist: `helm-ai-kernel
// migrate` creates it, and the Store never runs DDL.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("authority rows store requires a database")
	}
	return &Store{db: db}, nil
}

// CreateTenant adds a tenant's control row.
func (s *Store) CreateTenant(ctx context.Context, tenantID string) error {
	return s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO authority_tenants (tenant_id) VALUES ($1)`, tenantID)
		return classify(err)
	})
}

// CreatePrincipal registers an active principal. Registering grants nothing:
// authority comes from mandates.
func (s *Store) CreatePrincipal(ctx context.Context, tenantID, principalID string, kind PrincipalKind) error {
	if strings.TrimSpace(principalID) == "" {
		return fmt.Errorf("%w: empty principal id", ErrInvalid)
	}
	switch kind {
	case PrincipalHuman, PrincipalAgent, PrincipalService:
	default:
		return fmt.Errorf("%w: principal kind %q", ErrInvalid, kind)
	}
	return s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO authority_principals (tenant_id, principal_id, kind) VALUES ($1, $2, $3)`,
			tenantID, principalID, string(kind))
		return classify(err)
	})
}

// CreateEffectType adds an effect type's control row. A mandate can name an
// effect type only once its row exists, so creating one widens no mandate.
func (s *Store) CreateEffectType(ctx context.Context, tenantID, effectType string, risk RiskClass) error {
	if !effectTypePattern.MatchString(effectType) {
		return fmt.Errorf("%w: effect type %q", ErrInvalid, effectType)
	}
	switch risk {
	case RiskLow, RiskMedium, RiskHigh, RiskIrreversible:
	default:
		return fmt.Errorf("%w: risk class %q", ErrInvalid, risk)
	}
	return s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO authority_effect_types (tenant_id, effect_type, risk_class) VALUES ($1, $2, $3)`,
			tenantID, effectType, string(risk))
		return classify(err)
	})
}

// CreateMandate activates a root mandate for holderID. Activation widens
// authority, so it needs an approval (architecture §4.1 item 7).
func (s *Store) CreateMandate(ctx context.Context, tenantID, holderID string, terms Terms, approval WideningApproval) (Mandate, error) {
	if err := approval.check(); err != nil {
		return Mandate{}, err
	}
	if approval.ApproverID == holderID {
		return Mandate{}, fmt.Errorf("%w: the approver would hold the mandate", ErrApproverNotDistinct)
	}
	terms, err := normalized(terms)
	if err != nil {
		return Mandate{}, err
	}
	m := Mandate{HolderID: holderID, Terms: terms, Active: true, CreatedBy: approval.RequesterID, ApprovedBy: approval.ApproverID, Version: 1}
	err = s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		if err := approval.verify(ctx, tx, tenantID); err != nil {
			return err
		}
		if err := requireActivePrincipal(ctx, tx, tenantID, holderID); err != nil {
			return err
		}
		if err := requireEffectTypes(ctx, tx, tenantID, terms.EffectTypes); err != nil {
			return err
		}
		return insertMandate(ctx, tx, tenantID, &m)
	})
	return m, err
}

// Delegate creates a child of parentID, held by holderID. Only the parent's
// holder may delegate, every mandate in the chain must be active, and the
// child's terms must be within the terms of every mandate above it: delegation
// only narrows. No active stop may cover the tenant, the delegator, or a
// mandate of the chain, so a stop cannot be sidestepped by delegating.
//
// Locks follow ADR-0001 §1: the tenant row, the two principals, then the chain
// root to leaf, all FOR SHARE, and stops are read after them. A concurrent
// narrowing or stop of any of those rows commits first and is seen, or waits.
func (s *Store) Delegate(ctx context.Context, tenantID string, parentID uuid.UUID, delegatorID, holderID string, terms Terms) (Mandate, error) {
	terms, err := normalized(terms)
	if err != nil {
		return Mandate{}, err
	}
	m := Mandate{HolderID: holderID, Terms: terms, Active: true, CreatedBy: delegatorID, Version: 1}
	err = s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM authority_tenants WHERE tenant_id = $1 FOR SHARE`, tenantID).Scan(new(int)); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: tenant %q", ErrNotFound, tenantID)
			}
			return err
		}
		if err := lockActivePrincipals(ctx, tx, tenantID, delegatorID, holderID); err != nil {
			return err
		}
		chain, err := readChain(ctx, tx, tenantID, parentID, true)
		if err != nil {
			return err
		}
		parent := chain[len(chain)-1]
		if parent.HolderID != delegatorID {
			return ErrNotDelegator
		}
		stopKeys := []string{string(ScopeTenant) + ":" + tenantID, string(ScopePrincipal) + ":" + delegatorID}
		for _, link := range chain {
			if !link.Active {
				return fmt.Errorf("%w: mandate %s is revoked", ErrInactive, link.ID)
			}
			if err := terms.Within(link.Terms); err != nil {
				return err
			}
			stopKeys = append(stopKeys, string(ScopeMandate)+":"+link.ID.String())
		}
		var stopped bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_stops
				WHERE tenant_id = $1 AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > now())
				  AND scope_kind || ':' || scope_key = ANY($2::text[]))`,
			tenantID, pq.Array(stopKeys)).Scan(&stopped); err != nil {
			return err
		}
		if stopped {
			return ErrStopped
		}
		if parent.Depth == math.MaxInt32 {
			return fmt.Errorf("%w: delegation depth overflows", ErrInvalid)
		}
		m.ParentID = &parent.ID
		m.Depth = parent.Depth + 1
		return insertMandate(ctx, tx, tenantID, &m)
	})
	return m, err
}

// Revoke revokes an active mandate. It narrows, so it needs no approval; the
// mandate is its own control row, and its version is bumped. Every mandate
// delegated from it stops admitting too, because admission checks every link.
func (s *Store) Revoke(ctx context.Context, tenantID string, mandateID uuid.UUID) error {
	return s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE authority_mandates SET status = 'revoked', version = version + 1
			WHERE tenant_id = $1 AND mandate_id = $2 AND status = 'active'`, tenantID, mandateID)
		if err != nil {
			return classify(err)
		}
		if affected(res) == 1 {
			return nil
		}
		if _, err := readMandate(ctx, tx, tenantID, mandateID); err != nil {
			return err
		}
		return fmt.Errorf("%w: mandate %s is already revoked", ErrInactive, mandateID)
	})
}

// Narrow replaces an active mandate's terms with terms within them, and bumps
// its version. Mandates delegated from it keep their rows; admission checks
// every link, so they cannot admit more than the narrowed mandate allows.
func (s *Store) Narrow(ctx context.Context, tenantID string, mandateID uuid.UUID, terms Terms) (Mandate, error) {
	terms, err := normalized(terms)
	if err != nil {
		return Mandate{}, err
	}
	var m Mandate
	err = s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		current, err := mandates.ScanMandate(tx.QueryRowContext(ctx, `SELECT `+mandates.MandateColumns+` FROM authority_mandates m
			WHERE tenant_id = $1 AND mandate_id = $2 FOR NO KEY UPDATE`, tenantID, mandateID))
		if err != nil {
			return err
		}
		if !current.Active {
			return fmt.Errorf("%w: mandate %s is revoked", ErrInactive, mandateID)
		}
		if err := terms.Within(current.Terms); err != nil {
			return err
		}
		// A replaced condition could admit what the old one refused; only
		// adding one, or keeping it, narrows.
		if current.Terms.Condition != "" && terms.Condition != current.Terms.Condition {
			return &WidensError{Field: "condition"}
		}
		m = current
		m.Terms = terms
		targets, condition, risks, required, err := termsColumns(terms)
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `UPDATE authority_mandates
			SET effect_types = $3, per_call_limit = $4, approval_threshold = $5, valid_from = $6, valid_until = $7,
			    targets = $8, condition = $9, risk_classes = $10, approval_required = $11, version = version + 1
			WHERE tenant_id = $1 AND mandate_id = $2 RETURNING version`,
			tenantID, mandateID, pq.Array(terms.EffectTypes), nullAmount(terms.PerCallLimit), nullAmount(terms.ApprovalThreshold),
			terms.ValidFrom, terms.ValidUntil, targets, condition, risks, required).Scan(&m.Version)
	})
	return m, err
}

// Chain returns a mandate and every mandate above it, root first.
func (s *Store) Chain(ctx context.Context, tenantID string, mandateID uuid.UUID) ([]Mandate, error) {
	var chain []Mandate
	err := s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		var err error
		chain, err = readChain(ctx, tx, tenantID, mandateID, false)
		return err
	})
	return chain, err
}

var unitPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func (spec LimitSpec) validate() error {
	switch {
	case !unitPattern.MatchString(spec.Unit):
		return fmt.Errorf("%w: limit unit %q", ErrInvalid, spec.Unit)
	case spec.Measure != "sum" && spec.Measure != "count" && spec.Measure != "distinct":
		return fmt.Errorf("%w: limit measure %q", ErrInvalid, spec.Measure)
	case spec.Window != "none" && spec.Window != "hour" && spec.Window != "day" && spec.Window != "month":
		return fmt.Errorf("%w: limit window %q", ErrInvalid, spec.Window)
	case spec.Value < 0:
		return fmt.Errorf("%w: negative limit", ErrInvalid)
	case spec.Span < 1 || spec.Span > 744:
		return fmt.Errorf("%w: limit span %d", ErrInvalid, spec.Span)
	case spec.Span != 1 && (spec.Window == "none" || spec.Measure == "distinct"):
		return fmt.Errorf("%w: a %s %s limit has one bucket", ErrInvalid, spec.Window, spec.Measure)
	}
	return nil
}

// CreateLimit adds a limit. A new limit only narrows, so it bumps the version
// of its scope's control row: the mandate, or the tenant for a resource
// account. A limit on a delegated mandate must be no higher than any limit
// with the same unit, measure and window above it.
func (s *Store) CreateLimit(ctx context.Context, tenantID string, spec LimitSpec) (Limit, error) {
	if err := spec.validate(); err != nil {
		return Limit{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Limit{}, err
	}
	limit := Limit{ID: id, Spec: spec, Version: 1}
	err = s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		if spec.MandateID == nil {
			return bumpControlRow(ctx, tx, tenantID, Scope{Kind: ScopeTenant, Key: tenantID}, func() error {
				return insertLimit(ctx, tx, tenantID, limit)
			})
		}
		mandateScope := Scope{Kind: ScopeMandate, Key: spec.MandateID.String()}
		return bumpControlRow(ctx, tx, tenantID, mandateScope, func() error {
			chain, err := readChain(ctx, tx, tenantID, *spec.MandateID, false)
			if err != nil {
				return err
			}
			ancestors := make([]uuid.UUID, 0, len(chain)-1)
			for _, link := range chain[:len(chain)-1] {
				ancestors = append(ancestors, link.ID)
			}
			var ceiling sql.NullInt64
			if err := tx.QueryRowContext(ctx, `SELECT min(limit_value) FROM (
					SELECT limit_value FROM authority_limits
					WHERE tenant_id = $1 AND mandate_id = ANY($2::uuid[])
					  AND unit = $3 AND measure = $4 AND window_kind = $5 AND span = $6
					ORDER BY limit_id FOR SHARE) AS ancestor_limits`,
				tenantID, pq.Array(uuidStrings(ancestors)), spec.Unit, spec.Measure, spec.Window, spec.Span).Scan(&ceiling); err != nil {
				return classify(err)
			}
			if ceiling.Valid && spec.Value > ceiling.Int64 {
				return &WidensError{Field: "limit_value"}
			}
			return insertLimit(ctx, tx, tenantID, limit)
		})
	})
	return limit, err
}

// LowerLimit lowers a limit to value (or keeps it) and bumps the limit's
// version. Raising a limit widens authority and is not offered.
func (s *Store) LowerLimit(ctx context.Context, tenantID string, limitID uuid.UUID, value int64) error {
	if value < 0 {
		return fmt.Errorf("%w: negative limit", ErrInvalid)
	}
	return s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE authority_limits SET limit_value = $3, version = version + 1
			WHERE tenant_id = $1 AND limit_id = $2 AND limit_value >= $3`, tenantID, limitID, value)
		if err != nil {
			return classify(err)
		}
		if affected(res) == 1 {
			return nil
		}
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_limits WHERE tenant_id = $1 AND limit_id = $2)`,
			tenantID, limitID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: limit %s", ErrNotFound, limitID)
		}
		return &WidensError{Field: "limit_value"}
	})
}

// Stop issues a stop on scope. It narrows, so it needs no approval. It bumps
// the scope's control row, which blocks behind any admission holding that row
// FOR SHARE, and inserts the stop in the same transaction.
func (s *Store) Stop(ctx context.Context, tenantID string, spec StopSpec) (Stop, error) {
	scope, err := spec.Scope.normalized()
	if err != nil {
		return Stop{}, err
	}
	if n := len(spec.Reason); n == 0 || n > 1024 {
		return Stop{}, fmt.Errorf("%w: a stop needs a reason of 1 to 1024 bytes", ErrInvalid)
	}
	if strings.TrimSpace(spec.IssuedBy) == "" {
		return Stop{}, fmt.Errorf("%w: a stop needs an issuer", ErrInvalid)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Stop{}, err
	}
	stop := Stop{ID: id, Scope: scope, Reason: spec.Reason, IssuedBy: spec.IssuedBy}
	if spec.ExpiresAt != nil {
		expires := spec.ExpiresAt.UTC().Truncate(time.Microsecond)
		stop.ExpiresAt = &expires
	}
	err = s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		return bumpControlRow(ctx, tx, tenantID, scope, func() error {
			var expires sql.NullTime
			if stop.ExpiresAt != nil {
				expires = sql.NullTime{Time: *stop.ExpiresAt, Valid: true}
			}
			err := tx.QueryRowContext(ctx, `INSERT INTO authority_stops (tenant_id, stop_id, scope_kind, scope_key, reason, issued_by, expires_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING created_at`,
				tenantID, stop.ID, string(scope.Kind), scope.Key, stop.Reason, stop.IssuedBy, expires).Scan(&stop.CreatedAt)
			stop.CreatedAt = stop.CreatedAt.UTC()
			return classify(err)
		})
	})
	return stop, err
}

// Lift lifts an active stop. Lifting widens authority, so it needs an
// approval; without one the stop stays and nothing changes. It bumps the
// scope's control row like any other authority change.
func (s *Store) Lift(ctx context.Context, tenantID string, stopID uuid.UUID, approval WideningApproval) error {
	if err := approval.check(); err != nil {
		return err
	}
	return s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		var scope Scope
		var kind string
		var lifted sql.NullTime
		err := tx.QueryRowContext(ctx, `SELECT scope_kind, scope_key, lifted_at FROM authority_stops
			WHERE tenant_id = $1 AND stop_id = $2 FOR UPDATE`, tenantID, stopID).Scan(&kind, &scope.Key, &lifted)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: stop %s", ErrNotFound, stopID)
		} else if err != nil {
			return err
		}
		scope.Kind = ScopeKind(kind)
		if lifted.Valid {
			return fmt.Errorf("%w: stop %s is already lifted", ErrInactive, stopID)
		}
		subject := ""
		switch scope.Kind {
		case ScopePrincipal:
			subject = scope.Key
		case ScopeMandate:
			if err := tx.QueryRowContext(ctx, `SELECT holder_id FROM authority_mandates WHERE tenant_id = $1 AND mandate_id = $2::uuid`,
				tenantID, scope.Key).Scan(&subject); err != nil {
				return err
			}
		}
		if approval.ApproverID == subject {
			return fmt.Errorf("%w: the approver is the stopped principal", ErrApproverNotDistinct)
		}
		if err := approval.verify(ctx, tx, tenantID); err != nil {
			return err
		}
		return bumpControlRow(ctx, tx, tenantID, scope, func() error {
			_, err := tx.ExecContext(ctx, `UPDATE authority_stops SET lifted_at = now(), lift_requested_by = $3, lift_approved_by = $4
				WHERE tenant_id = $1 AND stop_id = $2`, tenantID, stopID, approval.RequesterID, approval.ApproverID)
			return classify(err)
		})
	})
}

// ActiveStops returns the stops of the tenant that are active at `at`: not
// lifted and not expired. With scopes, it returns only stops on one of them.
//
// Admission reads stops in a statement after it holds its FOR SHARE locks
// (ADR-0001 §5.1). The filter deliberately ignores created_at: a stop that
// committed while admission waited for a lock can carry a created_at later
// than admission's own clock, and it must still be seen.
func (s *Store) ActiveStops(ctx context.Context, tenantID string, at time.Time, scopes ...Scope) ([]Stop, error) {
	if at.IsZero() {
		return nil, fmt.Errorf("%w: active stops need a time", ErrInvalid)
	}
	keys := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope, err := scope.normalized()
		if err != nil {
			return nil, err
		}
		if scope.Kind == ScopeTenant && scope.Key != tenantID {
			return nil, fmt.Errorf("%w: tenant scope %q is not the transaction's tenant", ErrInvalid, scope.Key)
		}
		keys = append(keys, string(scope.Kind)+":"+scope.Key)
	}
	// Truncate, not round: the database keeps microseconds, and rounding up
	// could report a stop as expired just before it is.
	at = at.UTC().Truncate(time.Microsecond)
	var stops []Stop
	err := s.inTenant(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT stop_id, scope_kind, scope_key, reason, issued_by, created_at, expires_at
			FROM authority_stops
			WHERE tenant_id = $1 AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > $2)
			  AND (cardinality($3::text[]) = 0 OR scope_kind || ':' || scope_key = ANY($3::text[]))
			ORDER BY created_at, stop_id`, tenantID, at, pq.Array(keys))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var stop Stop
			var kind string
			var expires sql.NullTime
			if err := rows.Scan(&stop.ID, &kind, &stop.Scope.Key, &stop.Reason, &stop.IssuedBy, &stop.CreatedAt, &expires); err != nil {
				return err
			}
			stop.Scope.Kind = ScopeKind(kind)
			stop.CreatedAt = stop.CreatedAt.UTC()
			if expires.Valid {
				expiresAt := expires.Time.UTC()
				stop.ExpiresAt = &expiresAt
			}
			stops = append(stops, stop)
		}
		return rows.Err()
	})
	return stops, err
}

// inTenant runs fn in one READ COMMITTED transaction bound to tenantID.
// set_config(..., true) ends with the transaction.
func (s *Store) inTenant(ctx context.Context, tenantID string, fn func(*sql.Tx) error) error {
	if s == nil || s.db == nil {
		return errors.New("authority rows store requires a database")
	}
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("%w: empty tenant id", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenantID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (a WideningApproval) check() error {
	if strings.TrimSpace(a.RequesterID) == "" || strings.TrimSpace(a.ApproverID) == "" {
		return ErrApprovalRequired
	}
	if a.RequesterID == a.ApproverID {
		return ErrApproverNotDistinct
	}
	return nil
}

// verify checks the approval's principals inside the transaction: the
// requester is active, and the approver is an active human. The rows are not
// locked: nothing in this slice disables a principal. The admission
// transaction (HELM-751) takes principals FOR SHARE in the ADR-0001 order.
func (a WideningApproval) verify(ctx context.Context, tx *sql.Tx, tenantID string) error {
	var eligible bool
	err := tx.QueryRowContext(ctx, `SELECT
			EXISTS (SELECT 1 FROM authority_principals WHERE tenant_id = $1 AND principal_id = $2 AND status = 'active')
			AND EXISTS (SELECT 1 FROM authority_principals WHERE tenant_id = $1 AND principal_id = $3 AND status = 'active' AND kind = 'human')`,
		tenantID, a.RequesterID, a.ApproverID).Scan(&eligible)
	if err != nil {
		return err
	}
	if !eligible {
		return ErrApproverNotEligible
	}
	return nil
}

func (scope Scope) normalized() (Scope, error) {
	switch scope.Kind {
	case ScopeTenant, ScopePrincipal, ScopeEffectType:
		if strings.TrimSpace(scope.Key) == "" {
			return Scope{}, fmt.Errorf("%w: empty %s scope", ErrInvalid, scope.Kind)
		}
		return scope, nil
	case ScopeMandate:
		id, err := uuid.Parse(scope.Key)
		if err != nil {
			return Scope{}, fmt.Errorf("%w: mandate scope %q", ErrInvalid, scope.Key)
		}
		return Scope{Kind: ScopeMandate, Key: id.String()}, nil
	default:
		return Scope{}, fmt.Errorf("%w: scope kind %q", ErrInvalid, scope.Kind)
	}
}

// bumpControlRow updates scope's control row, bumping its version, then runs
// detail in the same transaction. The UPDATE takes a row lock that conflicts
// with FOR SHARE (ADR-0001 §1), and version overflow is a database error, not
// a wrap-around.
func bumpControlRow(ctx context.Context, tx *sql.Tx, tenantID string, scope Scope, detail func() error) error {
	var query string
	args := []any{tenantID}
	switch scope.Kind {
	case ScopeTenant:
		if scope.Key != tenantID {
			return fmt.Errorf("%w: tenant scope %q is not the transaction's tenant", ErrInvalid, scope.Key)
		}
		query = `UPDATE authority_tenants SET version = version + 1 WHERE tenant_id = $1`
	case ScopePrincipal:
		query, args = `UPDATE authority_principals SET version = version + 1 WHERE tenant_id = $1 AND principal_id = $2`, append(args, scope.Key)
	case ScopeMandate:
		query, args = `UPDATE authority_mandates SET version = version + 1 WHERE tenant_id = $1 AND mandate_id = $2::uuid`, append(args, scope.Key)
	case ScopeEffectType:
		query, args = `UPDATE authority_effect_types SET version = version + 1 WHERE tenant_id = $1 AND effect_type = $2`, append(args, scope.Key)
	default:
		return fmt.Errorf("%w: scope kind %q", ErrInvalid, scope.Kind)
	}
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return classify(err)
	}
	if affected(res) != 1 {
		return fmt.Errorf("%w: %s %s", ErrNotFound, scope.Kind, scope.Key)
	}
	return detail()
}

func insertMandate(ctx context.Context, tx *sql.Tx, tenantID string, m *Mandate) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	m.ID = id
	var parent any
	if m.ParentID != nil {
		parent = *m.ParentID
	}
	var approvedBy any
	if m.ApprovedBy != "" {
		approvedBy = m.ApprovedBy
	}
	targets, condition, risks, required, err := termsColumns(m.Terms)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO authority_mandates (tenant_id, mandate_id, holder_id, parent_id, depth, effect_types,
			per_call_limit, approval_threshold, valid_from, valid_until, created_by, approved_by, targets, condition, risk_classes, approval_required)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		tenantID, m.ID, m.HolderID, parent, m.Depth, pq.Array(m.Terms.EffectTypes),
		nullAmount(m.Terms.PerCallLimit), nullAmount(m.Terms.ApprovalThreshold), m.Terms.ValidFrom, m.Terms.ValidUntil,
		m.CreatedBy, approvedBy, targets, condition, risks, required)
	return classify(err)
}

func insertLimit(ctx context.Context, tx *sql.Tx, tenantID string, limit Limit) error {
	var mandate any
	if limit.Spec.MandateID != nil {
		mandate = *limit.Spec.MandateID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO authority_limits (tenant_id, limit_id, mandate_id, unit, measure, window_kind, limit_value, span)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		tenantID, limit.ID, mandate, limit.Spec.Unit, limit.Spec.Measure, limit.Spec.Window, limit.Spec.Value, limit.Spec.Span)
	return classify(err)
}

// lockActivePrincipals takes FOR SHARE on the named principals, in id order,
// and requires each to exist and be active.
func lockActivePrincipals(ctx context.Context, tx *sql.Tx, tenantID string, principalIDs ...string) error {
	rows, err := tx.QueryContext(ctx, `SELECT principal_id, status FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = ANY($2::text[]) ORDER BY principal_id FOR SHARE`, tenantID, pq.Array(principalIDs))
	if err != nil {
		return err
	}
	defer rows.Close()
	status := make(map[string]string, len(principalIDs))
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err != nil {
			return err
		}
		status[id] = state
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range principalIDs {
		switch state, ok := status[id]; {
		case !ok:
			return fmt.Errorf("%w: principal %q", ErrNotFound, id)
		case state != "active":
			return fmt.Errorf("%w: principal %q is %s", ErrInactive, id, state)
		}
	}
	return nil
}

func requireActivePrincipal(ctx context.Context, tx *sql.Tx, tenantID, principalID string) error {
	var status string
	err := tx.QueryRowContext(ctx, `SELECT status FROM authority_principals WHERE tenant_id = $1 AND principal_id = $2`,
		tenantID, principalID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: principal %q", ErrNotFound, principalID)
	} else if err != nil {
		return err
	}
	if status != "active" {
		return fmt.Errorf("%w: principal %q is %s", ErrInactive, principalID, status)
	}
	return nil
}

func requireEffectTypes(ctx context.Context, tx *sql.Tx, tenantID string, effectTypes []string) error {
	var known int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM authority_effect_types WHERE tenant_id = $1 AND effect_type = ANY($2::text[])`,
		tenantID, pq.Array(effectTypes)).Scan(&known); err != nil {
		return err
	}
	if known != len(effectTypes) {
		return fmt.Errorf("%w: an effect type in %v has no control row", ErrNotFound, effectTypes)
	}
	return nil
}

func nullAmount(amount *int64) any {
	if amount == nil {
		return nil
	}
	return *amount
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func affected(res sql.Result) int64 {
	n, err := res.RowsAffected()
	if err != nil {
		return -1
	}
	return n
}

// classify maps constraint violations onto the store's errors, keeping the
// database error in the chain.
func classify(err error) error {
	var pgErr *pq.Error
	if !errors.As(err, &pgErr) {
		return err
	}
	switch pgErr.Code {
	case "23505": // unique_violation
		return fmt.Errorf("%w: %v", ErrExists, err)
	case "23503": // foreign_key_violation
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case "23514": // check_violation
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return err
}

// termsColumns are the s2b term values in the order targets, condition,
// risk_classes, approval_required, each NULL when unset.
func termsColumns(t Terms) (any, any, any, any, error) {
	var targets, condition, risks, required any
	if t.ApprovalRequired != nil {
		required = pq.Array(t.ApprovalRequired)
	}
	if t.Targets != nil {
		targets = pq.Array(t.Targets)
	}
	if t.Condition != "" {
		condition = t.Condition
	}
	if len(t.RiskClasses) > 0 {
		encoded, err := json.Marshal(t.RiskClasses)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		risks = encoded
	}
	return targets, condition, risks, required, nil
}

func readMandate(ctx context.Context, tx *sql.Tx, tenantID string, mandateID uuid.UUID) (Mandate, error) {
	return mandates.ScanMandate(tx.QueryRowContext(ctx, `SELECT `+mandates.MandateColumns+` FROM authority_mandates m
		WHERE tenant_id = $1 AND mandate_id = $2`, tenantID, mandateID))
}

func readChain(ctx context.Context, tx *sql.Tx, tenantID string, mandateID uuid.UUID, lock bool) ([]Mandate, error) {
	return mandates.ChainInTx(ctx, tx, tenantID, mandateID, lock)
}
