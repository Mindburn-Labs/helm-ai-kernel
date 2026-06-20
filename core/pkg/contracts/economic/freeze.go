package economic

// Spend-authority freeze + payment-failure handling (SPEND6 / MIN-471).
//
// A reconciliation mismatch or a provider payment failure must be able to
// degrade spend authority for the affected provider, account, or tenant "per
// policy", and a payment failure must do so WITHOUT exposing provider keys to
// agents and WITHOUT ever creating a negative *unmanaged* balance.
//
// A FreezeDirective is the policy decision artifact: it names the scope and the
// reason, references the reconciliation run or payment-failure event that
// triggered it, and binds an EvidencePack. It deliberately carries no provider
// credentials — only opaque provider/account/tenant identifiers and reason
// codes — so the freeze can be surfaced to an agent or audit log without leaking
// a key. Applying a directive flips the BalanceAccount to FROZEN, after which
// the SPEND5 fail-closed paths (Reserve / commit / credit) already refuse.

import (
	"errors"
	"time"
)

// FreezeScope identifies what a freeze degrades.
type FreezeScope string

const (
	// FreezeScopeAccount freezes a single balance account.
	FreezeScopeAccount FreezeScope = "ACCOUNT"
	// FreezeScopeProvider freezes routing through one provider for a tenant.
	FreezeScopeProvider FreezeScope = "PROVIDER"
	// FreezeScopeTenant freezes all spend authority for a tenant.
	FreezeScopeTenant FreezeScope = "TENANT"
)

// FreezeReason is the typed cause of a freeze so a frozen route surfaces a
// stable, agent-safe reason.
type FreezeReason string

const (
	// FreezeReasonReconciliationMismatch: a provider reconciliation run produced
	// exceptions or a non-zero delta beyond policy tolerance.
	FreezeReasonReconciliationMismatch FreezeReason = "RECONCILIATION_MISMATCH"
	// FreezeReasonPaymentFailure: a provider payment / charge failed.
	FreezeReasonPaymentFailure FreezeReason = "PAYMENT_FAILURE"
)

// FreezeDirective is the policy decision to degrade spend authority. It is
// content-addressed and append-only: a freeze is never edited, only superseded
// by an unfreeze that itself requires an approval ceremony.
type FreezeDirective struct {
	ID         string       `json:"id"`
	Scope      FreezeScope  `json:"scope"`
	TenantID   string       `json:"tenant_id"`
	ProviderID string       `json:"provider_id,omitempty"`
	AccountID  string       `json:"account_id,omitempty"`
	Reason     FreezeReason `json:"reason"`
	// SourceRef binds the triggering artifact: a ProviderReconciliationRun content
	// hash (mismatch) or a payment-failure event id. It is the evidence that the
	// freeze was earned, not arbitrary.
	SourceRef string `json:"source_ref"`
	// DegradeOnly requests a degrade (block new spend authority, keep existing
	// settlement honorable) rather than a hard freeze. Both refuse new debits;
	// the distinction is recorded for downstream policy.
	DegradeOnly     bool      `json:"degrade_only"`
	EvidencePackRef string    `json:"evidence_pack_ref"`
	CreatedAt       time.Time `json:"created_at"`
	ContentHash     string    `json:"content_hash"`
}

// NewFreezeDirective builds a freeze directive with a deterministic hash.
func NewFreezeDirective(id string, scope FreezeScope, tenantID string, reason FreezeReason, sourceRef, evidencePackRef string) *FreezeDirective {
	d := &FreezeDirective{
		ID:              id,
		Scope:           scope,
		TenantID:        tenantID,
		Reason:          reason,
		SourceRef:       sourceRef,
		EvidencePackRef: evidencePackRef,
		CreatedAt:       time.Now().UTC(),
	}
	d.ContentHash = d.computeHash()
	return d
}

// Reseal recomputes ContentHash after scope-specific identifiers (ProviderID,
// AccountID) or DegradeOnly are populated post-construction.
func (d *FreezeDirective) Reseal() string {
	if d == nil {
		return ""
	}
	d.ContentHash = d.computeHash()
	return d.ContentHash
}

// ExposesProviderKey is a guardrail predicate asserting a freeze directive never
// carries a provider credential. SPEND6 requires payment-failure freezes to be
// surfaced to agents without exposing keys; this returns true if any field looks
// like it leaked one, so the invariant can be tested directly.
func (d *FreezeDirective) ExposesProviderKey() bool {
	if d == nil {
		return false
	}
	for _, v := range []string{d.ID, d.TenantID, d.ProviderID, d.AccountID, d.SourceRef, d.EvidencePackRef} {
		if looksLikeSecret(v) {
			return true
		}
	}
	return false
}

// Validate ensures the directive is well-formed and scope-consistent.
func (d *FreezeDirective) Validate() error {
	if d == nil {
		return errors.New("freeze_directive: directive is nil")
	}
	if d.ID == "" {
		return errors.New("freeze_directive: id is required")
	}
	if d.TenantID == "" {
		return errors.New("freeze_directive: tenant_id is required")
	}
	if d.Reason == "" {
		return errors.New("freeze_directive: reason is required")
	}
	if d.SourceRef == "" {
		return errors.New("freeze_directive: source_ref is required (the triggering artifact)")
	}
	if d.EvidencePackRef == "" {
		return errors.New("freeze_directive: evidence_pack_ref is required")
	}
	switch d.Scope {
	case FreezeScopeAccount:
		if d.AccountID == "" {
			return errors.New("freeze_directive: account_id is required for ACCOUNT scope")
		}
	case FreezeScopeProvider:
		if d.ProviderID == "" {
			return errors.New("freeze_directive: provider_id is required for PROVIDER scope")
		}
	case FreezeScopeTenant:
		// tenant id already validated above
	default:
		return errors.New("freeze_directive: scope must be ACCOUNT, PROVIDER, or TENANT")
	}
	if d.ExposesProviderKey() {
		return errors.New("freeze_directive: directive must not carry a provider credential")
	}
	return nil
}

func (d *FreezeDirective) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID          string       `json:"id"`
		Scope       FreezeScope  `json:"scope"`
		TenantID    string       `json:"tenant_id"`
		ProviderID  string       `json:"provider_id,omitempty"`
		AccountID   string       `json:"account_id,omitempty"`
		Reason      FreezeReason `json:"reason"`
		SourceRef   string       `json:"source_ref"`
		DegradeOnly bool         `json:"degrade_only"`
	}{d.ID, d.Scope, d.TenantID, d.ProviderID, d.AccountID, d.Reason, d.SourceRef, d.DegradeOnly})
}

// looksLikeSecret is a conservative heuristic: provider key prefixes and bearer
// tokens that must never appear in an agent-visible freeze directive.
func looksLikeSecret(v string) bool {
	if len(v) < 12 {
		return false
	}
	prefixes := []string{"sk-", "sk_", "rk-", "rk_", "Bearer ", "xoxb-", "ghp_", "AKIA"}
	for _, p := range prefixes {
		if len(v) >= len(p) && v[:len(p)] == p {
			return true
		}
	}
	return false
}
