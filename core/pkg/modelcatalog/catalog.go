package modelcatalog

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// ErrUnknownProvider is returned when a provider id is not in the catalog.
var ErrUnknownProvider = errors.New("modelcatalog: unknown provider")

// ErrUnknownAccount is returned when an account id is not in the catalog.
var ErrUnknownAccount = errors.New("modelcatalog: unknown account")

// ErrUnknownTermsProfile is returned when a terms profile id is not in the catalog.
var ErrUnknownTermsProfile = errors.New("modelcatalog: unknown terms profile")

// Catalog is the kernel-owned registry of providers, the accounts that can reach
// them, and the terms profiles that bound them. It is the single source the
// router consults to decide whether a route is permissible before dispatch.
//
// The catalog is fail-closed by construction: a provider must be approved before
// any of its accounts can route, and a terms profile must validate before it can
// gate a route. The catalog never stores or returns credential material.
type Catalog struct {
	providers map[string]contracts.ModelProvider
	accounts  map[string]*ProviderAccount
	terms     map[string]*economic.ProviderTermsProfile
}

// NewCatalog returns an empty catalog.
func NewCatalog() *Catalog {
	return &Catalog{
		providers: make(map[string]contracts.ModelProvider),
		accounts:  make(map[string]*ProviderAccount),
		terms:     make(map[string]*economic.ProviderTermsProfile),
	}
}

// AddProvider registers a provider capability record. A provider with no
// ProviderID, no capabilities, or no regions is rejected. Re-adding an existing
// id overwrites the capability record but never silently re-approves accounts.
func (c *Catalog) AddProvider(p contracts.ModelProvider) error {
	if p.ProviderID == "" {
		return errors.New("modelcatalog: provider_id is required")
	}
	if len(p.Capabilities) == 0 {
		return fmt.Errorf("modelcatalog: provider %s has no capabilities", p.ProviderID)
	}
	if len(p.Regions) == 0 {
		return fmt.Errorf("modelcatalog: provider %s has no regions", p.ProviderID)
	}
	c.providers[p.ProviderID] = p
	return nil
}

// AddTermsProfile registers a validated provider terms profile.
func (c *Catalog) AddTermsProfile(p *economic.ProviderTermsProfile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if _, ok := c.providers[p.ProviderID]; !ok {
		return fmt.Errorf("%w: %s (terms profile %s)", ErrUnknownProvider, p.ProviderID, p.ID)
	}
	c.terms[p.ID] = p
	return nil
}

// AddAccount registers a provider account. The referenced provider and terms
// profile must already exist, and the terms profile must belong to the same
// provider. Accounts are registered unapproved; approval is a distinct step.
func (c *Catalog) AddAccount(a *ProviderAccount) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if _, ok := c.providers[a.ProviderID]; !ok {
		return fmt.Errorf("%w: %s (account %s)", ErrUnknownProvider, a.ProviderID, a.ID)
	}
	tp, ok := c.terms[a.TermsProfileID]
	if !ok {
		return fmt.Errorf("%w: %s (account %s)", ErrUnknownTermsProfile, a.TermsProfileID, a.ID)
	}
	if tp.ProviderID != a.ProviderID {
		return fmt.Errorf("modelcatalog: terms profile %s is for provider %s, not %s", tp.ID, tp.ProviderID, a.ProviderID)
	}
	a.ContentHash = a.computeHash()
	c.accounts[a.ID] = a
	return nil
}

// ApproveAccount marks an account approved and enabled. This is the explicit
// new-provider approval gate: an account cannot route until it passes through
// here, satisfying the "new-provider approval" done-gate.
func (c *Catalog) ApproveAccount(accountID string) error {
	a, ok := c.accounts[accountID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAccount, accountID)
	}
	a.Approved = true
	a.Enabled = true
	a.ContentHash = a.computeHash()
	return nil
}

// SetAccountHealth records a health observation for an account.
func (c *Catalog) SetAccountHealth(accountID string, health AccountHealth) error {
	a, ok := c.accounts[accountID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAccount, accountID)
	}
	if health.ObservedAt.IsZero() {
		health.ObservedAt = time.Now().UTC()
	}
	a.Health = health
	return nil
}

// Provider returns the capability record for a provider id.
func (c *Catalog) Provider(providerID string) (contracts.ModelProvider, bool) {
	p, ok := c.providers[providerID]
	return p, ok
}

// Account returns the account record for an account id.
func (c *Catalog) Account(accountID string) (*ProviderAccount, bool) {
	a, ok := c.accounts[accountID]
	return a, ok
}

// TermsProfile returns the terms profile for a profile id.
func (c *Catalog) TermsProfile(profileID string) (*economic.ProviderTermsProfile, bool) {
	p, ok := c.terms[profileID]
	return p, ok
}

// Providers returns the registered providers sorted by id for deterministic
// iteration. The returned slice is a copy.
func (c *Catalog) Providers() []contracts.ModelProvider {
	out := make([]contracts.ModelProvider, 0, len(c.providers))
	for _, p := range c.providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProviderID < out[j].ProviderID })
	return out
}

// ApprovedAccountsForProvider returns the approved, enabled accounts for a
// provider, sorted by account id. Unapproved or disabled accounts are excluded;
// this is the routable surface the router iterates.
func (c *Catalog) ApprovedAccountsForProvider(providerID string) []*ProviderAccount {
	var out []*ProviderAccount
	for _, a := range c.accounts {
		if a.ProviderID == providerID && a.Approved && a.Enabled {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ProviderCount returns the number of registered providers.
func (c *Catalog) ProviderCount() int { return len(c.providers) }
