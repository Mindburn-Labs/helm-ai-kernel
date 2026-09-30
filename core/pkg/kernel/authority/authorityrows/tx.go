package authorityrows

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

// Tx is the store's write operations inside a transaction the caller owns: one
// READ COMMITTED transaction bound to one tenant through app.current_tenant.
// The Store's own methods each run one Tx. The gateway's provisioning API runs
// several operations in one, together with its idempotency record and a
// single-use approval token, so that they commit or roll back as one.
type Tx struct {
	tx       *sql.Tx
	tenantID string
}

// InTenant runs fn in one READ COMMITTED transaction bound to tenantID and
// commits when fn returns nil.
func (s *Store) InTenant(ctx context.Context, tenantID string, fn func(*Tx) error) error {
	return s.inTenant(ctx, tenantID, func(tx *sql.Tx) error { return fn(&Tx{tx: tx, tenantID: tenantID}) })
}

// SQL returns the underlying transaction, for statements that must commit with
// the store's.
func (t *Tx) SQL() *sql.Tx { return t.tx }

// TenantID is the tenant the transaction is bound to.
func (t *Tx) TenantID() string { return t.tenantID }

// Tenant is a tenant's control row.
type Tenant struct {
	ID        string
	Version   int64
	CreatedAt time.Time
}

// ExternalSubject names a principal in the system that vouches for it, such as
// the Control Plane's user id. One external subject names one principal in a
// tenant, so a person registered twice cannot count as two people.
type ExternalSubject struct {
	System string
	ID     string
}

// PrincipalSpec is a principal to register. A human needs an External subject.
type PrincipalSpec struct {
	ID       string
	Kind     PrincipalKind
	External *ExternalSubject
}

// Principal is a stored principal.
type Principal struct {
	ID       string
	Kind     PrincipalKind
	Active   bool
	Version  int64
	External *ExternalSubject
}

// EffectType is a stored effect-type control row.
type EffectType struct {
	Name    string
	Risk    RiskClass
	Version int64
}

var (
	externalSystemPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	// the unique index authority_principals_external_subject.
	externalSubjectIndex = "authority_principals_external_subject"
)

// ValidPrincipalID reports whether id can name a principal: 1 to 255 bytes of
// UTF-8 without control characters or edge whitespace.
func ValidPrincipalID(id string) bool { return validPrincipalID(id) }

func validPrincipalID(id string) bool {
	return id != "" && len(id) <= 255 && utf8.ValidString(id) && strings.TrimSpace(id) == id &&
		strings.IndexFunc(id, unicode.IsControl) < 0
}

func (e ExternalSubject) validate() error {
	if !externalSystemPattern.MatchString(e.System) {
		return fmt.Errorf("%w: external system %q", ErrInvalid, e.System)
	}
	if e.ID == "" || len(e.ID) > 255 || !utf8.ValidString(e.ID) || strings.IndexFunc(e.ID, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: external subject id", ErrInvalid)
	}
	return nil
}

// EnsureTenant creates the tenant's control row when it does not exist, and
// returns it, with whether this call created it.
func (t *Tx) EnsureTenant(ctx context.Context) (Tenant, bool, error) {
	out := Tenant{ID: t.tenantID}
	err := t.tx.QueryRowContext(ctx, `INSERT INTO authority_tenants (tenant_id) VALUES ($1)
		ON CONFLICT (tenant_id) DO NOTHING RETURNING version, created_at`, t.tenantID).Scan(&out.Version, &out.CreatedAt)
	switch {
	case err == nil:
		out.CreatedAt = out.CreatedAt.UTC()
		return out, true, nil
	case !errors.Is(err, sql.ErrNoRows):
		return Tenant{}, false, classify(err)
	}
	out, err = t.Tenant(ctx)
	return out, false, err
}

// Tenant reads the tenant's control row.
func (t *Tx) Tenant(ctx context.Context) (Tenant, error) {
	out := Tenant{ID: t.tenantID}
	err := t.tx.QueryRowContext(ctx, `SELECT version, created_at FROM authority_tenants WHERE tenant_id = $1`,
		t.tenantID).Scan(&out.Version, &out.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, fmt.Errorf("%w: tenant %q", ErrNotFound, t.tenantID)
	}
	out.CreatedAt = out.CreatedAt.UTC()
	return out, err
}

const principalColumns = `kind, status, version, external_system, external_subject`

func scanPrincipal(id string, row interface{ Scan(...any) error }) (Principal, error) {
	p := Principal{ID: id}
	var kind, status string
	var system, subject sql.NullString
	if err := row.Scan(&kind, &status, &p.Version, &system, &subject); err != nil {
		return Principal{}, err
	}
	p.Kind, p.Active = PrincipalKind(kind), status == "active"
	if system.Valid {
		p.External = &ExternalSubject{System: system.String, ID: subject.String}
	}
	return p, nil
}

// Principal reads one principal.
func (t *Tx) Principal(ctx context.Context, principalID string) (Principal, error) {
	p, err := scanPrincipal(principalID, t.tx.QueryRowContext(ctx, `SELECT `+principalColumns+` FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = $2`, t.tenantID, principalID))
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, fmt.Errorf("%w: principal %q", ErrNotFound, principalID)
	}
	return p, err
}

// UpsertPrincipal registers a principal, or returns the one already registered
// under the same id. Registering grants nothing: authority comes from
// mandates.
//
// A principal's kind never changes, a disabled principal is never re-enabled
// (both would widen what its mandates reach), and an external subject, once
// set, is never changed: any of these is an error. A human needs an external
// subject, and one external subject names one principal in a tenant: a second
// principal presenting it is an ErrIdentityConflict. An external subject may
// be attached to a principal that has none.
func (t *Tx) UpsertPrincipal(ctx context.Context, spec PrincipalSpec) (Principal, error) {
	if !validPrincipalID(spec.ID) {
		return Principal{}, fmt.Errorf("%w: principal id", ErrInvalid)
	}
	switch spec.Kind {
	case PrincipalHuman, PrincipalAgent, PrincipalService:
	default:
		return Principal{}, fmt.Errorf("%w: principal kind %q", ErrInvalid, spec.Kind)
	}
	if spec.External != nil {
		if err := spec.External.validate(); err != nil {
			return Principal{}, err
		}
	}
	if spec.Kind == PrincipalHuman && spec.External == nil {
		return Principal{}, fmt.Errorf("%w: a human principal needs an external subject", ErrInvalid)
	}
	var system, subject any
	if spec.External != nil {
		system, subject = spec.External.System, spec.External.ID
	}
	res, err := t.tx.ExecContext(ctx, `INSERT INTO authority_principals (tenant_id, principal_id, kind, external_system, external_subject)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, principal_id) DO NOTHING`,
		t.tenantID, spec.ID, string(spec.Kind), system, subject)
	if err != nil {
		return Principal{}, identityConflict(err)
	}
	if affected(res) == 1 {
		return t.Principal(ctx, spec.ID)
	}
	current, err := scanPrincipal(spec.ID, t.tx.QueryRowContext(ctx, `SELECT `+principalColumns+` FROM authority_principals
		WHERE tenant_id = $1 AND principal_id = $2 FOR UPDATE`, t.tenantID, spec.ID))
	if err != nil {
		return Principal{}, err
	}
	switch {
	case current.Kind != spec.Kind:
		return Principal{}, fmt.Errorf("%w: principal %q is a %s, and a kind never changes", ErrIdentityConflict, spec.ID, current.Kind)
	case !current.Active:
		return Principal{}, fmt.Errorf("%w: %q is disabled, and a disabled principal is not re-enabled", ErrPrincipalInactive, spec.ID)
	case spec.External == nil:
		return current, nil
	case current.External != nil && *current.External != *spec.External:
		return Principal{}, fmt.Errorf("%w: principal %q has another external subject", ErrIdentityConflict, spec.ID)
	case current.External != nil:
		return current, nil
	}
	// A subject attached once to a principal that had none. It is not
	// authority, so the row's version stays.
	if _, err := t.tx.ExecContext(ctx, `UPDATE authority_principals SET external_system = $3, external_subject = $4
		WHERE tenant_id = $1 AND principal_id = $2`, t.tenantID, spec.ID, spec.External.System, spec.External.ID); err != nil {
		return Principal{}, identityConflict(err)
	}
	return t.Principal(ctx, spec.ID)
}

// identityConflict maps a violation of the external-subject index to
// ErrIdentityConflict, and anything else through classify.
func identityConflict(err error) error {
	var pgErr *pq.Error
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.Constraint == externalSubjectIndex {
		return fmt.Errorf("%w: the external subject already names another principal", ErrIdentityConflict)
	}
	return classify(err)
}

// DisablePrincipal disables a principal. It narrows: admission denies the
// principal, and the row's version is bumped so a permit issued under it fails
// its dispatch claim. Disabling a disabled principal changes nothing.
func (t *Tx) DisablePrincipal(ctx context.Context, principalID string) (Principal, error) {
	if _, err := t.tx.ExecContext(ctx, `UPDATE authority_principals SET status = 'disabled', version = version + 1
		WHERE tenant_id = $1 AND principal_id = $2 AND status = 'active'`, t.tenantID, principalID); err != nil {
		return Principal{}, classify(err)
	}
	return t.Principal(ctx, principalID)
}

// EnsureEffectType registers an effect type with a risk class, or returns the
// registered one. A registered type keeps its class or has it raised, which
// narrows (the version is bumped); lowering it widens and is refused with a
// *WidensError (LowerEffectTypeRisk lowers it under an approval). The row is
// locked only when it changes, so registering what is registered blocks nothing.
func (t *Tx) EnsureEffectType(ctx context.Context, effectType string, risk RiskClass) (EffectType, error) {
	if err := validEffectTypeRisk(effectType, risk); err != nil {
		return EffectType{}, err
	}
	res, err := t.tx.ExecContext(ctx, `INSERT INTO authority_effect_types (tenant_id, effect_type, risk_class) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, effect_type) DO NOTHING`, t.tenantID, effectType, string(risk))
	if err != nil {
		return EffectType{}, classify(err)
	}
	if affected(res) == 1 {
		return t.EffectType(ctx, effectType)
	}
	current, err := t.EffectType(ctx, effectType)
	if err != nil {
		return EffectType{}, err
	}
	switch {
	case risk == current.Risk:
		return current, nil
	case mandates.HigherRisk(current.Risk, risk) == current.Risk:
		return EffectType{}, &WidensError{Field: "risk_class"}
	}
	return t.setEffectTypeRisk(ctx, effectType, risk)
}

// LowerEffectTypeRisk sets an effect type's risk class to risk, which may be
// lower than the registered one. Lowering widens authority (a mandate's calls
// escalate less), so it needs an approval, as activating a root mandate does.
func (t *Tx) LowerEffectTypeRisk(ctx context.Context, effectType string, risk RiskClass, approval WideningApproval) (EffectType, error) {
	if err := validEffectTypeRisk(effectType, risk); err != nil {
		return EffectType{}, err
	}
	if err := approval.check(); err != nil {
		return EffectType{}, err
	}
	if err := approval.verify(ctx, t.tx, t.tenantID); err != nil {
		return EffectType{}, err
	}
	return t.setEffectTypeRisk(ctx, effectType, risk)
}

func validEffectTypeRisk(effectType string, risk RiskClass) error {
	if !effectTypePattern.MatchString(effectType) {
		return fmt.Errorf("%w: effect type %q", ErrInvalid, effectType)
	}
	switch risk {
	case RiskLow, RiskMedium, RiskHigh, RiskIrreversible:
		return nil
	}
	return fmt.Errorf("%w: risk class %q", ErrInvalid, risk)
}

// setEffectTypeRisk locks the row and, when its class is not risk, sets it and
// bumps the version.
func (t *Tx) setEffectTypeRisk(ctx context.Context, effectType string, risk RiskClass) (EffectType, error) {
	var current string
	err := t.tx.QueryRowContext(ctx, `SELECT risk_class FROM authority_effect_types
		WHERE tenant_id = $1 AND effect_type = $2 FOR UPDATE`, t.tenantID, effectType).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return EffectType{}, fmt.Errorf("%w: effect type %q", ErrNotFound, effectType)
	}
	if err != nil {
		return EffectType{}, err
	}
	if current != string(risk) {
		if _, err := t.tx.ExecContext(ctx, `UPDATE authority_effect_types SET risk_class = $3, version = version + 1
			WHERE tenant_id = $1 AND effect_type = $2`, t.tenantID, effectType, string(risk)); err != nil {
			return EffectType{}, classify(err)
		}
	}
	return t.EffectType(ctx, effectType)
}

// EffectType reads one effect-type control row.
func (t *Tx) EffectType(ctx context.Context, effectType string) (EffectType, error) {
	out := EffectType{Name: effectType}
	var risk string
	err := t.tx.QueryRowContext(ctx, `SELECT risk_class, version FROM authority_effect_types
		WHERE tenant_id = $1 AND effect_type = $2`, t.tenantID, effectType).Scan(&risk, &out.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return EffectType{}, fmt.Errorf("%w: effect type %q", ErrNotFound, effectType)
	}
	out.Risk = RiskClass(risk)
	return out, err
}

// CreateMandate activates a root mandate for holderID. Activation widens
// authority, so it needs an approval (architecture §4.1 item 7).
func (t *Tx) CreateMandate(ctx context.Context, holderID string, terms Terms, approval WideningApproval) (Mandate, error) {
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
	if err := approval.verify(ctx, t.tx, t.tenantID); err != nil {
		return m, err
	}
	if err := requireActivePrincipal(ctx, t.tx, t.tenantID, holderID); err != nil {
		return m, err
	}
	if err := requireEffectTypes(ctx, t.tx, t.tenantID, terms.EffectTypes); err != nil {
		return m, err
	}
	return m, insertMandate(ctx, t.tx, t.tenantID, &m)
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
func (t *Tx) Delegate(ctx context.Context, parentID uuid.UUID, delegatorID, holderID string, terms Terms) (Mandate, error) {
	terms, err := normalized(terms)
	if err != nil {
		return Mandate{}, err
	}
	m := Mandate{HolderID: holderID, Terms: terms, Active: true, CreatedBy: delegatorID, Version: 1}
	tenantID, tx := t.tenantID, t.tx
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM authority_tenants WHERE tenant_id = $1 FOR SHARE`, tenantID).Scan(new(int)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return m, fmt.Errorf("%w: tenant %q", ErrNotFound, tenantID)
		}
		return m, err
	}
	if err := lockActivePrincipals(ctx, tx, tenantID, delegatorID, holderID); err != nil {
		return m, err
	}
	chain, err := readChain(ctx, tx, tenantID, parentID, true)
	if err != nil {
		return m, err
	}
	parent := chain[len(chain)-1]
	if parent.HolderID != delegatorID {
		return m, ErrNotDelegator
	}
	stopKeys := []string{string(ScopeTenant) + ":" + tenantID, string(ScopePrincipal) + ":" + delegatorID}
	for _, link := range chain {
		if !link.Active {
			return m, fmt.Errorf("%w: mandate %s is revoked", ErrMandateInactive, link.ID)
		}
		if err := terms.Within(link.Terms); err != nil {
			return m, err
		}
		stopKeys = append(stopKeys, string(ScopeMandate)+":"+link.ID.String())
	}
	var stopped bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_stops
			WHERE tenant_id = $1 AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > now())
			  AND scope_kind || ':' || scope_key = ANY($2::text[]))`,
		tenantID, pq.Array(stopKeys)).Scan(&stopped); err != nil {
		return m, err
	}
	if stopped {
		return m, ErrStopped
	}
	if parent.Depth == math.MaxInt32 {
		return m, fmt.Errorf("%w: delegation depth overflows", ErrInvalid)
	}
	m.ParentID = &parent.ID
	m.Depth = parent.Depth + 1
	return m, insertMandate(ctx, tx, tenantID, &m)
}

// Revoke revokes an active mandate. It narrows, so it needs no approval; the
// mandate is its own control row, and its version is bumped. Every mandate
// delegated from it stops admitting too, because admission checks every link.
func (t *Tx) Revoke(ctx context.Context, mandateID uuid.UUID) error {
	res, err := t.tx.ExecContext(ctx, `UPDATE authority_mandates SET status = 'revoked', version = version + 1
		WHERE tenant_id = $1 AND mandate_id = $2 AND status = 'active'`, t.tenantID, mandateID)
	if err != nil {
		return classify(err)
	}
	if affected(res) == 1 {
		return nil
	}
	if _, err := readMandate(ctx, t.tx, t.tenantID, mandateID); err != nil {
		return err
	}
	return fmt.Errorf("%w: mandate %s is already revoked", ErrMandateInactive, mandateID)
}

// Narrow replaces an active mandate's terms with terms within them, and bumps
// its version. A condition may be added to a mandate that has none, or kept; a
// replaced one could admit what the old one refused. Mandates delegated from it
// keep their rows: admission checks every link, so they cannot admit more than
// the narrowed mandate allows.
func (t *Tx) Narrow(ctx context.Context, mandateID uuid.UUID, terms Terms) (Mandate, error) {
	terms, err := normalized(terms)
	if err != nil {
		return Mandate{}, err
	}
	current, err := mandates.ScanMandate(t.tx.QueryRowContext(ctx, `SELECT `+mandates.MandateColumns+` FROM authority_mandates m
		WHERE tenant_id = $1 AND mandate_id = $2 FOR NO KEY UPDATE`, t.tenantID, mandateID))
	if err != nil {
		return Mandate{}, err
	}
	if !current.Active {
		return Mandate{}, fmt.Errorf("%w: mandate %s is revoked", ErrMandateInactive, mandateID)
	}
	if err := terms.Within(current.Terms); err != nil {
		return Mandate{}, err
	}
	if current.Terms.Condition != "" && terms.Condition != current.Terms.Condition {
		return Mandate{}, &WidensError{Field: "condition"}
	}
	targets, condition, risks, required, err := termsColumns(terms)
	if err != nil {
		return Mandate{}, err
	}
	m := current
	m.Terms = terms
	err = t.tx.QueryRowContext(ctx, `UPDATE authority_mandates
		SET effect_types = $3, per_call_limit = $4, approval_threshold = $5, valid_from = $6, valid_until = $7,
		    targets = $8, condition = $9, risk_classes = $10, approval_required = $11, version = version + 1
		WHERE tenant_id = $1 AND mandate_id = $2 RETURNING version`,
		t.tenantID, mandateID, pq.Array(terms.EffectTypes), nullAmount(terms.PerCallLimit), nullAmount(terms.ApprovalThreshold),
		terms.ValidFrom, terms.ValidUntil, targets, condition, risks, required).Scan(&m.Version)
	return m, err
}

// Mandate reads one mandate.
func (t *Tx) Mandate(ctx context.Context, mandateID uuid.UUID) (Mandate, error) {
	return readMandate(ctx, t.tx, t.tenantID, mandateID)
}

// MandateForUpdate reads a mandate while holding its control row's mutation
// lock until this transaction ends. Read the mandate's stops and limits only
// after this call: concurrent stops and narrowings either commit before this
// read or wait for the transaction. Admission's FOR SHARE lock also conflicts,
// so no admission can create a new counter bucket after this lock is acquired.
func (t *Tx) MandateForUpdate(ctx context.Context, mandateID uuid.UUID) (Mandate, error) {
	m, err := mandates.ScanMandate(t.tx.QueryRowContext(ctx, `SELECT `+mandates.MandateColumns+` FROM authority_mandates m
		WHERE tenant_id = $1 AND mandate_id = $2 FOR NO KEY UPDATE`, t.tenantID, mandateID))
	if errors.Is(err, sql.ErrNoRows) {
		return Mandate{}, fmt.Errorf("%w: mandate %s", ErrNotFound, mandateID)
	}
	return m, err
}

// CreateLimit adds a limit. A new limit only narrows, so it bumps the version
// of its scope's control row: the mandate, or the tenant for a resource
// account. A limit on a delegated mandate must be no higher than any limit
// with the same unit, measure and window above it.
func (t *Tx) CreateLimit(ctx context.Context, spec LimitSpec) (Limit, error) {
	if err := spec.Validate(); err != nil {
		return Limit{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Limit{}, err
	}
	limit := Limit{ID: id, Spec: spec, Version: 1}
	tenantID, tx := t.tenantID, t.tx
	if spec.MandateID == nil {
		return limit, bumpControlRow(ctx, tx, tenantID, Scope{Kind: ScopeTenant, Key: tenantID}, func() error {
			return insertLimit(ctx, tx, tenantID, limit)
		})
	}
	mandateScope := Scope{Kind: ScopeMandate, Key: spec.MandateID.String()}
	return limit, bumpControlRow(ctx, tx, tenantID, mandateScope, func() error {
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
}

// LowerLimit lowers a limit to value (or keeps it) and bumps the limit's
// version. Raising a limit widens authority and is not offered.
func (t *Tx) LowerLimit(ctx context.Context, limitID uuid.UUID, value int64) error {
	if value < 0 {
		return fmt.Errorf("%w: negative limit", ErrInvalid)
	}
	res, err := t.tx.ExecContext(ctx, `UPDATE authority_limits SET limit_value = $3, version = version + 1
		WHERE tenant_id = $1 AND limit_id = $2 AND limit_value >= $3`, t.tenantID, limitID, value)
	if err != nil {
		return classify(err)
	}
	if affected(res) == 1 {
		return nil
	}
	var exists bool
	if err := t.tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM authority_limits WHERE tenant_id = $1 AND limit_id = $2)`,
		t.tenantID, limitID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: limit %s", ErrNotFound, limitID)
	}
	return &WidensError{Field: "limit_value"}
}

const limitColumns = `limit_id, mandate_id, unit, measure, window_kind, limit_value, span, version`

func scanLimit(row interface{ Scan(...any) error }) (Limit, error) {
	var l Limit
	var mandate uuid.NullUUID
	if err := row.Scan(&l.ID, &mandate, &l.Spec.Unit, &l.Spec.Measure, &l.Spec.Window, &l.Spec.Value, &l.Spec.Span, &l.Version); err != nil {
		return Limit{}, err
	}
	if mandate.Valid {
		l.Spec.MandateID = &mandate.UUID
	}
	return l, nil
}

// Limit reads one limit.
func (t *Tx) Limit(ctx context.Context, limitID uuid.UUID) (Limit, error) {
	l, err := scanLimit(t.tx.QueryRowContext(ctx, `SELECT `+limitColumns+` FROM authority_limits
		WHERE tenant_id = $1 AND limit_id = $2`, t.tenantID, limitID))
	if errors.Is(err, sql.ErrNoRows) {
		return Limit{}, fmt.Errorf("%w: limit %s", ErrNotFound, limitID)
	}
	return l, err
}

// MandateLimits reads the limits of one mandate, oldest first.
func (t *Tx) MandateLimits(ctx context.Context, mandateID uuid.UUID) ([]Limit, error) {
	rows, err := t.tx.QueryContext(ctx, `SELECT `+limitColumns+` FROM authority_limits
		WHERE tenant_id = $1 AND mandate_id = $2 ORDER BY limit_id`, t.tenantID, mandateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Limit
	for rows.Next() {
		l, err := scanLimit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SetLimit adds a limit for its scope (the mandate, or the tenant when the
// spec names none), or lowers the limit that already has the same unit,
// measure, window and span. Both narrow. A value above the stored one would
// widen and is refused with a *WidensError; the same value changes nothing.
//
// The scope's row is locked first, so two calls for one scope are serialized
// and cannot both add the limit; the lock is ADR-0001's order (the mandate
// before its limits).
func (t *Tx) SetLimit(ctx context.Context, spec LimitSpec) (Limit, error) {
	if err := spec.Validate(); err != nil {
		return Limit{}, err
	}
	var found bool
	var err error
	if spec.MandateID == nil {
		err = t.tx.QueryRowContext(ctx, `SELECT true FROM authority_tenants WHERE tenant_id = $1 FOR NO KEY UPDATE`,
			t.tenantID).Scan(&found)
	} else {
		err = t.tx.QueryRowContext(ctx, `SELECT true FROM authority_mandates WHERE tenant_id = $1 AND mandate_id = $2 FOR NO KEY UPDATE`,
			t.tenantID, *spec.MandateID).Scan(&found)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Limit{}, fmt.Errorf("%w: the limit's scope", ErrNotFound)
	}
	if err != nil {
		return Limit{}, err
	}
	var mandate any
	if spec.MandateID != nil {
		mandate = *spec.MandateID
	}
	rows, err := t.tx.QueryContext(ctx, `SELECT `+limitColumns+` FROM authority_limits
		WHERE tenant_id = $1 AND mandate_id IS NOT DISTINCT FROM $2 AND unit = $3 AND measure = $4
		  AND window_kind = $5 AND span = $6 ORDER BY limit_id FOR UPDATE`,
		t.tenantID, mandate, spec.Unit, spec.Measure, spec.Window, spec.Span)
	if err != nil {
		return Limit{}, err
	}
	var existing []Limit
	for rows.Next() {
		l, err := scanLimit(rows)
		if err != nil {
			_ = rows.Close()
			return Limit{}, err
		}
		existing = append(existing, l)
	}
	if err := rows.Close(); err != nil {
		return Limit{}, err
	}
	if len(existing) == 0 {
		return t.CreateLimit(ctx, spec)
	}
	lowest := existing[0].Spec.Value
	for _, l := range existing {
		lowest = min(lowest, l.Spec.Value)
	}
	if spec.Value > lowest {
		return Limit{}, &WidensError{Field: "limit_value"}
	}
	for _, l := range existing {
		if l.Spec.Value > spec.Value {
			if err := t.LowerLimit(ctx, l.ID, spec.Value); err != nil {
				return Limit{}, err
			}
		}
	}
	return t.Limit(ctx, existing[0].ID)
}
