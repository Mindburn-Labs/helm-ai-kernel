package modelcatalog

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// DefaultCatalog builds a provider-neutral catalog with at least three
// providers, one validated terms profile per provider, and one approved account
// per provider exercising the managed, BYOK, and self-hosted account modes.
//
// It satisfies the ">=3 providers in catalog" acceptance criterion and gives the
// router a realistic, contract-aware surface to score against. Provider records
// are intentionally neutral (no current-provider claims) so public code does not
// drift with commercial provider release cycles; deployments generate a live
// catalog from verified source metadata.
//
// now seeds health-observation timestamps so callers can drive deterministic
// staleness tests.
func DefaultCatalog(now time.Time) (*Catalog, error) {
	c := NewCatalog()

	providers := contracts.KnownModelProviders()
	for _, p := range providers {
		if err := c.AddProvider(p); err != nil {
			return nil, err
		}
	}

	// One terms profile + one approved account per seeded provider. Modes rotate
	// across MANAGED, BYOK, SELF_HOSTED so the catalog covers the account-mode
	// matrix. PARTNER is exercised directly in router tests.
	modes := []AccountMode{AccountManaged, AccountBYOK, AccountSelfHosted}
	for i, p := range providers {
		mode := modes[i%len(modes)]
		tp := economic.NewProviderTermsProfile(
			"terms:"+p.ProviderID,
			p.ProviderID,
			mode.ToTermsAccountMode(),
			"v1",
			"legal-review://"+p.ProviderID,
		)
		tp.Jurisdiction = firstRegion(p.Regions)
		tp.DataRetentionDays = 30
		tp.EffectiveAt = now
		if tp.RequiresContractForManagedBilling {
			tp.ContractRef = "contract://" + p.ProviderID
		}
		expiry := now.Add(365 * 24 * time.Hour)
		tp.ExpiresAt = &expiry
		if err := c.AddTermsProfile(tp); err != nil {
			return nil, err
		}

		credRef := ""
		if mode.RequiresCredential() {
			credRef = "kcred://" + p.ProviderID + "/primary"
		}
		acct, err := NewProviderAccount("acct:"+p.ProviderID, p.ProviderID, mode, tp.ID, credRef)
		if err != nil {
			return nil, err
		}
		acct.Regions = p.Regions
		if err := c.AddAccount(acct); err != nil {
			return nil, err
		}
		if err := c.ApproveAccount(acct.ID); err != nil {
			return nil, err
		}
		if err := c.SetAccountHealth(acct.ID, AccountHealth{
			State:      HealthHealthy,
			ObservedAt: now,
			LatencyP95: p.Latency95th,
		}); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func firstRegion(regions []string) string {
	if len(regions) == 0 {
		return ""
	}
	return regions[0]
}
