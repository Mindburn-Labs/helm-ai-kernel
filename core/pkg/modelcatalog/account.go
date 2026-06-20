// Package modelcatalog is the kernel-owned provider catalog.
//
// It binds three source-owned facts together so that multi-provider routing is
// explicit, contract-aware, and auditable BEFORE any spend is claimed:
//
//   - the provider/model capability record (contracts.ModelProvider);
//   - the provider account record that says HOW HELM is allowed to reach a
//     provider (managed org account, BYOK, partner, or self-hosted) and WHERE
//     its credential lives — by opaque reference only;
//   - the provider terms profile (resale/retention/region/contract refs) that
//     defines the legal and commercial boundary of the route.
//
// Credential boundary: a ProviderAccount never carries a secret. It carries a
// CredentialRef — an opaque pointer into the kernel credential store. Agents
// receive spend authority (an AgentSpendEnvelope), never provider-key
// authority. The catalog refuses to construct an account whose CredentialRef
// looks like an inline secret, and exposes no API that returns secret material.
package modelcatalog

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// AccountMode describes how HELM is allowed to route through a provider account.
//
// It is a superset of economic.ProviderAccountMode: the spend-authority package
// models BYOK / DIRECT / MANAGED_ORG_ACCOUNT for billing, while the catalog also
// needs to distinguish PARTNER resale relationships and SELF_HOSTED weights that
// have no external provider credential at all.
type AccountMode string

const (
	// AccountManaged is a HELM-managed organization account. HELM holds the
	// provider credential and bills the tenant through a governed usage balance.
	AccountManaged AccountMode = "MANAGED"
	// AccountBYOK is a bring-your-own-key account. The tenant's credential is
	// held in the kernel credential store and never surfaced to agents.
	AccountBYOK AccountMode = "BYOK"
	// AccountPartner is a partner/reseller relationship governed by a contract.
	AccountPartner AccountMode = "PARTNER"
	// AccountSelfHosted is a tenant-operated endpoint (e.g. local vLLM) that
	// needs no external provider credential.
	AccountSelfHosted AccountMode = "SELF_HOSTED"
)

// valid reports whether the mode is a known catalog account mode.
func (m AccountMode) valid() bool {
	switch m {
	case AccountManaged, AccountBYOK, AccountPartner, AccountSelfHosted:
		return true
	default:
		return false
	}
}

// RequiresCredential reports whether the mode needs a credential reference.
// Self-hosted endpoints are reachable without an external provider key.
func (m AccountMode) RequiresCredential() bool {
	return m == AccountManaged || m == AccountBYOK || m == AccountPartner
}

// ToTermsAccountMode maps the catalog account mode onto the economic terms
// vocabulary so a terms profile can be matched against an account. PARTNER and
// SELF_HOSTED have no direct billing analogue and map to DIRECT.
func (m AccountMode) ToTermsAccountMode() economic.ProviderAccountMode {
	switch m {
	case AccountManaged:
		return economic.ProviderAccountManagedOrgAccount
	case AccountBYOK:
		return economic.ProviderAccountBYOK
	default:
		return economic.ProviderAccountDirect
	}
}

// HealthState is the routability of a provider account.
type HealthState string

const (
	// HealthUnknown means no probe has reported yet. Fails closed: an account
	// with unknown health is not routable.
	HealthUnknown HealthState = "UNKNOWN"
	// HealthHealthy means the account is routable.
	HealthHealthy HealthState = "HEALTHY"
	// HealthDegraded means the account is impaired but may still be escalated.
	HealthDegraded HealthState = "DEGRADED"
	// HealthUnhealthy means the account must not be dispatched to.
	HealthUnhealthy HealthState = "UNHEALTHY"
)

// AccountHealth is a point-in-time health view for a provider account.
//
// It is advisory evidence the router consumes; it never carries credentials.
// Staleness is fail-closed: a probe older than the account's MaxHealthAge is
// treated as UNKNOWN.
type AccountHealth struct {
	State       HealthState `json:"state"`
	Detail      string      `json:"detail,omitempty"`
	ObservedAt  time.Time   `json:"observed_at"`
	LatencyP95  int         `json:"latency_p95_ms,omitempty"`
	ErrorRatePM int         `json:"error_rate_per_mille,omitempty"`
}

// effectiveState returns the health state, downgrading to UNKNOWN when the probe
// is older than maxAge (maxAge <= 0 disables the staleness check).
func (h AccountHealth) effectiveState(now time.Time, maxAge time.Duration) HealthState {
	if h.State == "" {
		return HealthUnknown
	}
	if maxAge > 0 && !h.ObservedAt.IsZero() && now.Sub(h.ObservedAt) > maxAge {
		return HealthUnknown
	}
	return h.State
}

// ProviderAccount is the kernel-owned record of one routable way to reach a
// provider. It is the join point between a capability record, a credential, and
// a terms profile — and it is the object that keeps provider keys away from
// agents.
type ProviderAccount struct {
	ID             string      `json:"id"`
	TenantID       string      `json:"tenant_id,omitempty"`
	ProviderID     string      `json:"provider_id"`
	Mode           AccountMode `json:"mode"`
	TermsProfileID string      `json:"terms_profile_id"`
	// CredentialRef is an opaque pointer into the kernel credential store.
	// It MUST NOT contain secret material; the catalog rejects inline secrets.
	CredentialRef string        `json:"credential_ref,omitempty"`
	Endpoint      string        `json:"endpoint,omitempty"`
	Regions       []string      `json:"regions,omitempty"`
	Enabled       bool          `json:"enabled"`
	Approved      bool          `json:"approved"`
	MaxHealthAge  time.Duration `json:"max_health_age,omitempty"`
	Health        AccountHealth `json:"health"`
	ContentHash   string        `json:"content_hash"`
}

// credentialRefLooksLikeSecret rejects values that look like inline secret
// material rather than an opaque store reference. This is a defense-in-depth
// check for the "provider creds never exposed" invariant — a CredentialRef is a
// handle (e.g. "kcred://tenant/openai/primary"), never a key.
func credentialRefLooksLikeSecret(ref string) bool {
	r := strings.TrimSpace(ref)
	if r == "" {
		return false
	}
	lower := strings.ToLower(r)
	for _, prefix := range []string{"sk-", "sk_", "pk-", "pk_", "ghp_", "xoxb-", "bearer ", "aws_", "akia"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	// Long, opaque, delimiter-free strings are almost certainly raw secrets.
	if len(r) >= 40 && !strings.ContainsAny(r, ":/@ ") {
		return true
	}
	return false
}

// NewProviderAccount creates a disabled, unapproved provider account and computes
// its content hash. New accounts start unapproved: a provider cannot enter the
// routable catalog without an explicit approval step (Catalog.ApproveAccount).
func NewProviderAccount(id, providerID string, mode AccountMode, termsProfileID, credentialRef string) (*ProviderAccount, error) {
	a := &ProviderAccount{
		ID:             id,
		ProviderID:     providerID,
		Mode:           mode,
		TermsProfileID: termsProfileID,
		CredentialRef:  strings.TrimSpace(credentialRef),
		Health:         AccountHealth{State: HealthUnknown},
		MaxHealthAge:   5 * time.Minute,
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	a.ContentHash = a.computeHash()
	return a, nil
}

// Validate enforces structural and credential-boundary invariants.
func (a *ProviderAccount) Validate() error {
	if a == nil {
		return errors.New("provider_account: account is nil")
	}
	if a.ID == "" {
		return errors.New("provider_account: id is required")
	}
	if a.ProviderID == "" {
		return errors.New("provider_account: provider_id is required")
	}
	if !a.Mode.valid() {
		return fmt.Errorf("provider_account: unknown mode %q", a.Mode)
	}
	if a.TermsProfileID == "" {
		return errors.New("provider_account: terms_profile_id is required")
	}
	if a.Mode.RequiresCredential() && a.CredentialRef == "" {
		return fmt.Errorf("provider_account: credential_ref is required for mode %s", a.Mode)
	}
	if credentialRefLooksLikeSecret(a.CredentialRef) {
		return errors.New("provider_account: credential_ref must be an opaque store reference, not an inline secret")
	}
	if a.MaxHealthAge < 0 {
		return errors.New("provider_account: max_health_age cannot be negative")
	}
	return nil
}

// Routable reports whether the account may currently receive dispatch and, if
// not, the canonical spend reason code explaining why. The boolean is true only
// for an enabled, approved account whose effective health is HEALTHY.
//
// Fail-closed ordering: approval and enablement gate first, then health. A
// DEGRADED account is reported as not-routable but the caller may choose to
// escalate; an UNHEALTHY or UNKNOWN account is a hard deny.
func (a *ProviderAccount) Routable(now time.Time) (bool, economic.SpendReasonCode) {
	if a == nil {
		return false, economic.SpendReasonProviderNotAllowed
	}
	if !a.Approved {
		return false, economic.SpendReasonApprovalRequired
	}
	if !a.Enabled {
		return false, economic.SpendReasonProviderNotAllowed
	}
	switch a.Health.effectiveState(now, a.MaxHealthAge) {
	case HealthHealthy:
		return true, economic.SpendReasonOKWithinEnvelope
	case HealthDegraded:
		return false, economic.SpendReasonApprovalRequired
	default:
		return false, economic.SpendReasonProviderNotAllowed
	}
}

func (a *ProviderAccount) computeHash() string {
	return hashCanonical(struct {
		ID             string      `json:"id"`
		TenantID       string      `json:"tenant_id,omitempty"`
		ProviderID     string      `json:"provider_id"`
		Mode           AccountMode `json:"mode"`
		TermsProfileID string      `json:"terms_profile_id"`
		CredentialRef  string      `json:"credential_ref,omitempty"`
		Endpoint       string      `json:"endpoint,omitempty"`
		Regions        []string    `json:"regions,omitempty"`
		Enabled        bool        `json:"enabled"`
		Approved       bool        `json:"approved"`
	}{a.ID, a.TenantID, a.ProviderID, a.Mode, a.TermsProfileID, a.CredentialRef, a.Endpoint, a.Regions, a.Enabled, a.Approved})
}
