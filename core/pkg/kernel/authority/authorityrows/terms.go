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
// The schema is schema.sql (SchemaDDL). The effect gateway's admission
// transaction (HELM-751, HELM-750 s2b, core/pkg/gateway/admission) reads these
// rows: it locks them, evaluates the mandate chain, and re-checks that each
// link is within the one above it.
package authorityrows

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates"
)

var (
	// ErrInvalid reports input the store refuses before touching the database.
	ErrInvalid = errors.New("authority rows: invalid input")
	// ErrNotFound reports a row that does not exist in the caller's tenant.
	ErrNotFound = mandates.ErrNotFound
	// ErrWidens reports a delegation or narrowing that would widen authority.
	ErrWidens = mandates.ErrWidens
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

// The mandate terms, types and chain read live in package mandates, which the
// effect gateway imports without this store.
type (
	PrincipalKind = mandates.PrincipalKind
	RiskClass     = mandates.RiskClass
	WidensError   = mandates.WidensError
	Terms         = mandates.Terms
	Mandate       = mandates.Mandate
)

const (
	PrincipalHuman   = mandates.PrincipalHuman
	PrincipalAgent   = mandates.PrincipalAgent
	PrincipalService = mandates.PrincipalService

	RiskLow          = mandates.RiskLow
	RiskMedium       = mandates.RiskMedium
	RiskHigh         = mandates.RiskHigh
	RiskIrreversible = mandates.RiskIrreversible

	MaxConditionBytes = mandates.MaxConditionBytes
)

// Tables are the authority rows (mandates.Tables).
var Tables = mandates.Tables

// SchemaDDL returns the authority rows' DDL (mandates.SchemaDDL).
func SchemaDDL() string { return mandates.SchemaDDL() }

var effectTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

// normalized validates t and returns it in the form the database stores:
// sorted, de-duplicated effect types, and UTC times at microsecond precision.
func normalized(t Terms) (Terms, error) {
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
		Condition:         t.Condition,
	}
	if !out.ValidUntil.After(out.ValidFrom) {
		return Terms{}, fmt.Errorf("%w: valid_until must be after valid_from", ErrInvalid)
	}
	if t.Targets != nil {
		if len(t.Targets) == 0 {
			return Terms{}, fmt.Errorf("%w: an empty target list allows nothing; omit it to allow any target", ErrInvalid)
		}
		seenTargets := make(map[string]struct{}, len(t.Targets))
		for _, target := range t.Targets {
			if target == "" || len(target) > 512 || strings.IndexFunc(target, unicode.IsControl) >= 0 {
				return Terms{}, fmt.Errorf("%w: target %q", ErrInvalid, target)
			}
			if _, dup := seenTargets[target]; !dup {
				seenTargets[target] = struct{}{}
				out.Targets = append(out.Targets, target)
			}
		}
		sort.Strings(out.Targets)
	}
	if t.Condition != "" {
		if len(t.Condition) > MaxConditionBytes {
			return Terms{}, fmt.Errorf("%w: condition longer than %d bytes", ErrInvalid, MaxConditionBytes)
		}
		if _, err := mandates.CompileCondition(t.Condition); err != nil {
			return Terms{}, fmt.Errorf("%w: condition does not compile: %v", ErrInvalid, err)
		}
	}
	if t.ApprovalRequired != nil {
		required := map[string]struct{}{}
		for _, effectType := range t.ApprovalRequired {
			if _, ok := seen[effectType]; !ok {
				return Terms{}, fmt.Errorf("%w: approval required for %q, which is not in the mandate's scope", ErrInvalid, effectType)
			}
			if _, dup := required[effectType]; !dup {
				required[effectType] = struct{}{}
				out.ApprovalRequired = append(out.ApprovalRequired, effectType)
			}
		}
		if len(out.ApprovalRequired) == 0 {
			out.ApprovalRequired = nil
		}
		sort.Strings(out.ApprovalRequired)
	}
	if len(t.RiskClasses) > 0 {
		out.RiskClasses = make(map[string]RiskClass, len(t.RiskClasses))
		for effectType, class := range t.RiskClasses {
			if _, ok := seen[effectType]; !ok {
				return Terms{}, fmt.Errorf("%w: risk class for %q, which is not in the mandate's scope", ErrInvalid, effectType)
			}
			if class != RiskLow && class != RiskMedium && class != RiskHigh && class != RiskIrreversible {
				return Terms{}, fmt.Errorf("%w: risk class %q", ErrInvalid, class)
			}
			out.RiskClasses[effectType] = class
		}
	}
	return out, nil
}

func copyAmount(amount *int64) *int64 {
	if amount == nil {
		return nil
	}
	value := *amount
	return &value
}
