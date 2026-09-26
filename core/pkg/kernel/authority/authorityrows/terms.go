// Package authorityrows keeps the kernel's authority rows in Postgres
// (HELM-750, ADR-0001 §2): tenants, principals, effect types, mandates,
// limits and stops, each a typed row with a version (rules R3 and R5).
//
// Delegation only narrows: a child mandate's terms must be within the terms of
// every mandate above it. Narrowing transitions (stop, revoke, narrow, lower or
// add a limit) update their scope's control row and bump its version in the
// same transaction as their detail row (ADR-0001 §5.1), so an admission that
// holds FOR SHARE on that row either sees the change or blocks it.
//
// Widening authority needs an approval: activating a root mandate and lifting
// a stop take a WideningApproval naming a requester and a distinct, active,
// human approver. In the product these are helm.authority.* effects approved
// through the gateway (HELM-751), which replaces the argument with the
// verified approval record.
//
// The schema belongs to postgresmigration (migrations/001_authority_rows.sql).
// Nothing in the request path reads these rows yet; the admission transaction
// (HELM-751, HELM-750 s2b) is their first runtime caller.
package authorityrows

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

var (
	// ErrInvalid reports input the store refuses before touching the database.
	ErrInvalid = errors.New("authority rows: invalid input")
	// ErrNotFound reports a row that does not exist in the caller's tenant.
	ErrNotFound = errors.New("authority rows: not found")
	// ErrWidens reports a delegation or narrowing that would widen authority.
	ErrWidens = errors.New("authority rows: would widen authority")
	// ErrInactive reports a revoked mandate, a disabled principal, or a lifted
	// stop where an active one is required.
	ErrInactive = errors.New("authority rows: not active")
	// ErrNotDelegator reports a delegation by anyone but the parent's holder.
	ErrNotDelegator = errors.New("authority rows: only the parent mandate's holder may delegate it")
	// ErrApprovalRequired reports a widening transition without an approval.
	ErrApprovalRequired = errors.New("authority rows: widening authority requires an approval")
	// ErrApproverNotDistinct reports an approval by its own requester.
	ErrApproverNotDistinct = errors.New("authority rows: the approver must be distinct from the requester")
	// ErrApproverNotEligible reports an approver who is not an active human
	// principal of the tenant, or a requester who is not an active principal.
	ErrApproverNotEligible = errors.New("authority rows: approval principals are not eligible")
)

// WidensError names the term that a child mandate or a narrowing would widen.
type WidensError struct {
	Field string
}

func (e *WidensError) Error() string { return fmt.Sprintf("%v: %s", ErrWidens, e.Field) }

func (e *WidensError) Unwrap() error { return ErrWidens }

// Terms are a mandate's typed grant. Amounts are integer minor units of the
// effect's resource; a nil PerCallLimit or ApprovalThreshold sets none.
type Terms struct {
	// EffectTypes is the scope: the effect types the mandate may admit.
	EffectTypes []string
	// PerCallLimit caps the amount of one call.
	PerCallLimit *int64
	// ApprovalThreshold is the approval rule: a call whose amount is at least
	// this needs an approval (0 means every call). Without it, approval
	// follows the effect type's risk class alone.
	ApprovalThreshold *int64
	// ValidFrom and ValidUntil bound the mandate, [ValidFrom, ValidUntil).
	ValidFrom  time.Time
	ValidUntil time.Time
}

var effectTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

// normalized validates t and returns it in the form the database stores:
// sorted, de-duplicated effect types, and UTC times at microsecond precision.
func (t Terms) normalized() (Terms, error) {
	if len(t.EffectTypes) == 0 {
		return Terms{}, fmt.Errorf("%w: a mandate needs at least one effect type", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(t.EffectTypes))
	types := make([]string, 0, len(t.EffectTypes))
	for _, effectType := range t.EffectTypes {
		if !effectTypePattern.MatchString(effectType) {
			return Terms{}, fmt.Errorf("%w: effect type %q", ErrInvalid, effectType)
		}
		if _, dup := seen[effectType]; !dup {
			seen[effectType] = struct{}{}
			types = append(types, effectType)
		}
	}
	sort.Strings(types)
	if t.PerCallLimit != nil && *t.PerCallLimit < 0 {
		return Terms{}, fmt.Errorf("%w: negative per-call limit", ErrInvalid)
	}
	if t.ApprovalThreshold != nil && *t.ApprovalThreshold < 0 {
		return Terms{}, fmt.Errorf("%w: negative approval threshold", ErrInvalid)
	}
	if t.ValidFrom.IsZero() || t.ValidUntil.IsZero() {
		return Terms{}, fmt.Errorf("%w: a mandate needs a validity window", ErrInvalid)
	}
	out := Terms{
		EffectTypes:       types,
		PerCallLimit:      copyAmount(t.PerCallLimit),
		ApprovalThreshold: copyAmount(t.ApprovalThreshold),
		ValidFrom:         t.ValidFrom.UTC().Truncate(time.Microsecond),
		ValidUntil:        t.ValidUntil.UTC().Truncate(time.Microsecond),
	}
	if !out.ValidUntil.After(out.ValidFrom) {
		return Terms{}, fmt.Errorf("%w: valid_until must be after valid_from", ErrInvalid)
	}
	return out, nil
}

// Within returns nil when t grants nothing outer does not: its scope is a
// subset, its per-call limit and approval threshold are no higher (and present
// wherever outer's are), and its validity window lies inside outer's. Otherwise
// it returns a *WidensError naming the first term that widens.
func (t Terms) Within(outer Terms) error {
	allowed := make(map[string]struct{}, len(outer.EffectTypes))
	for _, effectType := range outer.EffectTypes {
		allowed[effectType] = struct{}{}
	}
	for _, effectType := range t.EffectTypes {
		if _, ok := allowed[effectType]; !ok {
			return &WidensError{Field: "effect_types"}
		}
	}
	if !amountWithin(t.PerCallLimit, outer.PerCallLimit) {
		return &WidensError{Field: "per_call_limit"}
	}
	if !amountWithin(t.ApprovalThreshold, outer.ApprovalThreshold) {
		return &WidensError{Field: "approval_threshold"}
	}
	if t.ValidFrom.Before(outer.ValidFrom) {
		return &WidensError{Field: "valid_from"}
	}
	if t.ValidUntil.After(outer.ValidUntil) {
		return &WidensError{Field: "valid_until"}
	}
	return nil
}

// amountWithin: a bound narrows another when the other sets none, or when it is
// set and no higher. For a per-call limit, lower is tighter; for an approval
// threshold, lower asks for approval on more calls, which is also tighter.
func amountWithin(inner, outer *int64) bool {
	if outer == nil {
		return true
	}
	return inner != nil && *inner <= *outer
}

func copyAmount(amount *int64) *int64 {
	if amount == nil {
		return nil
	}
	value := *amount
	return &value
}
