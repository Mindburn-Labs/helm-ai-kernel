package modelcatalog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

func freshTermsProfile(t *testing.T, id, providerID string, mode AccountMode, now time.Time) *economic.ProviderTermsProfile {
	t.Helper()
	tp := economic.NewProviderTermsProfile(id, providerID, mode.ToTermsAccountMode(), "v1", "legal-review://"+providerID)
	tp.DataRetentionDays = 30
	if tp.RequiresContractForManagedBilling {
		tp.ContractRef = "contract://" + providerID
	}
	exp := now.Add(24 * time.Hour)
	tp.ExpiresAt = &exp
	if err := tp.Validate(); err != nil {
		t.Fatalf("seed terms profile invalid: %v", err)
	}
	return tp
}

func TestDefaultCatalog_HasAtLeastThreeProviders(t *testing.T) {
	now := time.Now().UTC()
	c, err := DefaultCatalog(now)
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	if c.ProviderCount() < 3 {
		t.Fatalf("catalog has %d providers, want >= 3", c.ProviderCount())
	}
	// Every seeded provider must have an approved, routable account.
	for _, p := range c.Providers() {
		accts := c.ApprovedAccountsForProvider(p.ProviderID)
		if len(accts) == 0 {
			t.Fatalf("provider %s has no approved account", p.ProviderID)
		}
		if ok, code := accts[0].Routable(now); !ok {
			t.Fatalf("provider %s account not routable: %s", p.ProviderID, code)
		}
	}
}

func TestProviderAccount_NewProviderApprovalGate(t *testing.T) {
	now := time.Now().UTC()
	a, err := NewProviderAccount("acct:p", "example:p", AccountManaged, "terms:p", "kcred://example/p")
	if err != nil {
		t.Fatalf("NewProviderAccount: %v", err)
	}
	// A freshly created account is unapproved and therefore not routable.
	if a.Approved {
		t.Fatal("new account must not be pre-approved")
	}
	if ok, code := a.Routable(now); ok || code != economic.SpendReasonApprovalRequired {
		t.Fatalf("unapproved account routable=%v code=%s, want false/ERR_APPROVAL_REQUIRED", ok, code)
	}
}

func TestCatalog_ApproveAccountMakesRoutable(t *testing.T) {
	now := time.Now().UTC()
	c := NewCatalog()
	if err := c.AddProvider(contracts.ModelProvider{
		ProviderID:   "example:p",
		Name:         "P",
		Capabilities: []string{"TEXT"},
		Regions:      []string{"US"},
		RiskTier:     "LOW",
		Active:       true,
	}); err != nil {
		t.Fatalf("AddProvider: %v", err)
	}
	if err := c.AddTermsProfile(freshTermsProfile(t, "terms:p", "example:p", AccountManaged, now)); err != nil {
		t.Fatalf("AddTermsProfile: %v", err)
	}
	acct, err := NewProviderAccount("acct:p", "example:p", AccountManaged, "terms:p", "kcred://example/p")
	if err != nil {
		t.Fatalf("NewProviderAccount: %v", err)
	}
	if err := c.AddAccount(acct); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	// Before approval: not in the approved set.
	if got := c.ApprovedAccountsForProvider("example:p"); len(got) != 0 {
		t.Fatalf("approved accounts before approval = %d, want 0", len(got))
	}
	if err := c.ApproveAccount("acct:p"); err != nil {
		t.Fatalf("ApproveAccount: %v", err)
	}
	if err := c.SetAccountHealth("acct:p", AccountHealth{State: HealthHealthy, ObservedAt: now}); err != nil {
		t.Fatalf("SetAccountHealth: %v", err)
	}
	got := c.ApprovedAccountsForProvider("example:p")
	if len(got) != 1 {
		t.Fatalf("approved accounts after approval = %d, want 1", len(got))
	}
	if ok, _ := got[0].Routable(now); !ok {
		t.Fatal("approved healthy account should be routable")
	}
}

func TestProviderAccount_UnhealthyAndStaleHealthFailClosed(t *testing.T) {
	now := time.Now().UTC()
	base := func() *ProviderAccount {
		a, err := NewProviderAccount("acct:p", "example:p", AccountManaged, "terms:p", "kcred://example/p")
		if err != nil {
			t.Fatalf("NewProviderAccount: %v", err)
		}
		a.Approved = true
		a.Enabled = true
		return a
	}

	cases := []struct {
		name     string
		health   AccountHealth
		wantOK   bool
		wantCode economic.SpendReasonCode
	}{
		{"healthy", AccountHealth{State: HealthHealthy, ObservedAt: now}, true, economic.SpendReasonOKWithinEnvelope},
		{"unhealthy denies", AccountHealth{State: HealthUnhealthy, ObservedAt: now}, false, economic.SpendReasonProviderNotAllowed},
		{"degraded escalates", AccountHealth{State: HealthDegraded, ObservedAt: now}, false, economic.SpendReasonApprovalRequired},
		{"unknown denies", AccountHealth{State: HealthUnknown, ObservedAt: now}, false, economic.SpendReasonProviderNotAllowed},
		{"stale probe denies", AccountHealth{State: HealthHealthy, ObservedAt: now.Add(-time.Hour)}, false, economic.SpendReasonProviderNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := base()
			a.Health = tc.health
			ok, code := a.Routable(now)
			if ok != tc.wantOK || code != tc.wantCode {
				t.Fatalf("Routable = (%v,%s), want (%v,%s)", ok, code, tc.wantOK, tc.wantCode)
			}
		})
	}
}

// TestProviderAccount_RejectsInlineSecret is the credential-boundary regression:
// the catalog must refuse a CredentialRef that looks like raw secret material,
// enforcing "provider creds never exposed to agents" at construction time.
func TestProviderAccount_RejectsInlineSecret(t *testing.T) {
	secrets := []string{
		"sk-abc123def456ghi789jkl012mno345pqr678stu",
		"ghp_0123456789abcdef0123456789abcdef0123",
		"AKIAIOSFODNN7EXAMPLE",
		"Bearer eyJhbGciOiJIUzI1NiIsInR5cC16IkpXVCJ9",
		"0123456789abcdef0123456789abcdef01234567", // 40-char opaque blob
	}
	for _, s := range secrets {
		if _, err := NewProviderAccount("acct:p", "example:p", AccountBYOK, "terms:p", s); err == nil {
			t.Fatalf("NewProviderAccount accepted inline secret %q, want rejection", s)
		}
	}
	// An opaque store reference is accepted.
	if _, err := NewProviderAccount("acct:p", "example:p", AccountBYOK, "terms:p", "kcred://tenant/example/primary"); err != nil {
		t.Fatalf("NewProviderAccount rejected opaque ref: %v", err)
	}
}

// TestProviderAccount_NoSecretInSerialization asserts the account record never
// carries secret material in its JSON form — only the opaque reference.
func TestProviderAccount_NoSecretInSerialization(t *testing.T) {
	a, err := NewProviderAccount("acct:p", "example:p", AccountBYOK, "terms:p", "kcred://tenant/example/primary")
	if err != nil {
		t.Fatalf("NewProviderAccount: %v", err)
	}
	blob, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(blob)
	if strings.Contains(s, "sk-") || strings.Contains(s, "secret") || strings.Contains(s, "api_key") {
		t.Fatalf("serialized account leaks secret-shaped material: %s", s)
	}
	if !strings.Contains(s, "kcred://") {
		t.Fatalf("serialized account dropped credential_ref handle: %s", s)
	}
}

func TestCatalog_RejectsMissingDepsAndModeCredentialRules(t *testing.T) {
	now := time.Now().UTC()
	c := NewCatalog()

	// Terms profile referencing an unknown provider is rejected.
	tp := freshTermsProfile(t, "terms:p", "example:p", AccountManaged, now)
	if err := c.AddTermsProfile(tp); err == nil {
		t.Fatal("AddTermsProfile for unknown provider should fail")
	}

	if err := c.AddProvider(contracts.ModelProvider{
		ProviderID: "example:p", Name: "P", Capabilities: []string{"TEXT"}, Regions: []string{"US"}, RiskTier: "LOW", Active: true,
	}); err != nil {
		t.Fatalf("AddProvider: %v", err)
	}
	if err := c.AddTermsProfile(tp); err != nil {
		t.Fatalf("AddTermsProfile: %v", err)
	}

	// Self-hosted account needs no credential.
	sh, err := NewProviderAccount("acct:sh", "example:p", AccountSelfHosted, "terms:p", "")
	if err != nil {
		t.Fatalf("self-hosted account should not require credential: %v", err)
	}
	if err := c.AddAccount(sh); err != nil {
		t.Fatalf("AddAccount(self-hosted): %v", err)
	}

	// BYOK account without a credential is rejected.
	if _, err := NewProviderAccount("acct:byok", "example:p", AccountBYOK, "terms:p", ""); err == nil {
		t.Fatal("BYOK account without credential_ref should fail")
	}
}
