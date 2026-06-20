package router

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/modelcatalog"
)

// Provider ids and economics come from contracts.KnownModelProviders():
//
//	example:frontier-reasoning  cost 10.0  lat 2500  regions US,EU      MANAGED
//	example:vision-tool         cost  5.0  lat 2000  regions US,EU,APAC BYOK
//	example:local-open-weight   cost  0.0  lat 1000  regions LOCAL      SELF_HOSTED
const (
	provFrontier = "example:frontier-reasoning"
	provVision   = "example:vision-tool"
	provLocal    = "example:local-open-weight"
)

func knownLikeProvider(id string) contracts.ModelProvider {
	return contracts.ModelProvider{
		ProviderID:   id,
		Name:         id,
		Capabilities: []string{"TEXT", "CODE"},
		Regions:      []string{"US", "EU"},
		RiskTier:     "LOW",
		MaxTokens:    100000,
		CostPerMTok:  7.5,
		Latency95th:  2200,
		Active:       true,
	}
}

// fullEnvelope grants spend authority across all three seeded providers/models.
func fullEnvelope(t *testing.T) *economic.AgentSpendEnvelope {
	t.Helper()
	e := economic.NewAgentSpendEnvelope("env-1", "tenant-1", "agent-1", "principal-1", "budget-1", "USD", economic.SpendPeriodMonthly, 100000, 5000, "sha256:policy")
	e.AllowedProviders = []string{provFrontier, provVision, provLocal}
	e.AllowedModels = []string{provFrontier, provVision, provLocal}
	if err := e.Validate(); err != nil {
		t.Fatalf("envelope invalid: %v", err)
	}
	return e
}

func newRouter(t *testing.T, now time.Time) *Router {
	t.Helper()
	c, err := modelcatalog.DefaultCatalog(now)
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	r, err := New(c)
	if err != nil {
		t.Fatalf("New router: %v", err)
	}
	return r
}

func balancedPolicy() *RoutePolicy {
	return &RoutePolicy{ID: "rp-balanced", Mode: RouteModeBalanced}
}

// --- Done-gate denial tests ------------------------------------------------

// Forbidden model: the requested model is outside the agent spend envelope.
func TestDecide_DeniesForbiddenModel(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	e := fullEnvelope(t)
	e.AllowedModels = []string{provVision} // frontier no longer allowed

	dec := r.Decide(Request{RequestedModelID: provFrontier, Envelope: e}, balancedPolicy(), now)
	if dec.Verdict != economic.BudgetVerdictDeny || dec.ReasonCode != economic.SpendReasonModelNotAllowed {
		t.Fatalf("got (%s,%s), want (DENY,ERR_SPEND_MODEL_NOT_ALLOWED): %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
	if dec.RoutePolicyHash == "" {
		t.Fatal("denial must still carry a route_policy_hash for audit")
	}
}

// Forbidden provider: a pinned provider request outside the envelope is denied.
func TestDecide_DeniesForbiddenProvider(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	e := fullEnvelope(t)
	e.AllowedProviders = []string{provVision, provLocal} // frontier not allowed

	dec := r.Decide(Request{
		RequestedModelID:    provFrontier,
		RequestedProviderID: provFrontier,
		Envelope:            e,
	}, balancedPolicy(), now)
	if dec.Verdict != economic.BudgetVerdictDeny || dec.ReasonCode != economic.SpendReasonProviderNotAllowed {
		t.Fatalf("got (%s,%s), want (DENY,ERR_SPEND_PROVIDER_NOT_ALLOWED): %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
}

// Stale terms profile: an expired terms profile blocks the route BEFORE dispatch.
func TestDecide_DeniesStaleTermsProfile(t *testing.T) {
	now := time.Now().UTC()
	c, err := modelcatalog.DefaultCatalog(now)
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	// Expire the frontier provider's terms profile in the past.
	tp, ok := c.TermsProfile("terms:" + provFrontier)
	if !ok {
		t.Fatal("seed terms profile missing")
	}
	past := now.Add(-time.Hour)
	tp.ExpiresAt = &past

	r, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Pin to the frontier provider so the stale terms profile is the deciding gate.
	pol := &RoutePolicy{ID: "rp-pin", Mode: RouteModeProviderPinned, PinnedProviderID: provFrontier}
	dec := r.Decide(Request{RequestedModelID: provFrontier, RequestedProviderID: provFrontier, Envelope: fullEnvelope(t)}, pol, now)
	if dec.Verdict != economic.BudgetVerdictDeny || dec.ReasonCode != economic.SpendReasonProviderContractNeeded {
		t.Fatalf("got (%s,%s), want (DENY,ERR_PROVIDER_CONTRACT_NEEDED): %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
}

// Unhealthy account: an UNHEALTHY account denies before dispatch.
func TestDecide_DeniesUnhealthyAccount(t *testing.T) {
	now := time.Now().UTC()
	c, err := modelcatalog.DefaultCatalog(now)
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	if err := c.SetAccountHealth("acct:"+provFrontier, modelcatalog.AccountHealth{State: modelcatalog.HealthUnhealthy, ObservedAt: now}); err != nil {
		t.Fatalf("SetAccountHealth: %v", err)
	}
	r, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pol := &RoutePolicy{ID: "rp-pin", Mode: RouteModeProviderPinned, PinnedProviderID: provFrontier}
	dec := r.Decide(Request{RequestedModelID: provFrontier, RequestedProviderID: provFrontier, Envelope: fullEnvelope(t)}, pol, now)
	if dec.Verdict != economic.BudgetVerdictDeny || dec.ReasonCode != economic.SpendReasonProviderNotAllowed {
		t.Fatalf("got (%s,%s), want (DENY,ERR_SPEND_PROVIDER_NOT_ALLOWED): %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
}

// Degraded account: maps to ESCALATE, not DENY.
func TestDecide_EscalatesDegradedAccount(t *testing.T) {
	now := time.Now().UTC()
	c, err := modelcatalog.DefaultCatalog(now)
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	if err := c.SetAccountHealth("acct:"+provFrontier, modelcatalog.AccountHealth{State: modelcatalog.HealthDegraded, ObservedAt: now}); err != nil {
		t.Fatalf("SetAccountHealth: %v", err)
	}
	r, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pol := &RoutePolicy{ID: "rp-pin", Mode: RouteModeProviderPinned, PinnedProviderID: provFrontier}
	dec := r.Decide(Request{RequestedModelID: provFrontier, RequestedProviderID: provFrontier, Envelope: fullEnvelope(t)}, pol, now)
	if dec.Verdict != economic.BudgetVerdictEscalate || dec.ReasonCode != economic.SpendReasonApprovalRequired {
		t.Fatalf("got (%s,%s), want (ESCALATE,ERR_APPROVAL_REQUIRED): %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
}

// New-provider approval: a provider whose account is not approved cannot route.
// We register a fourth provider with an unapproved account and pin to it.
func TestDecide_DeniesUnapprovedNewProvider(t *testing.T) {
	now := time.Now().UTC()
	c, err := modelcatalog.DefaultCatalog(now)
	if err != nil {
		t.Fatalf("DefaultCatalog: %v", err)
	}
	const provNew = "example:new-entrant"
	if err := c.AddProvider(knownLikeProvider(provNew)); err != nil {
		t.Fatalf("AddProvider: %v", err)
	}
	tp := economic.NewProviderTermsProfile("terms:"+provNew, provNew, economic.ProviderAccountManagedOrgAccount, "v1", "legal://new")
	tp.ContractRef = "contract://new"
	tp.EffectiveAt = now
	exp := now.Add(24 * time.Hour)
	tp.ExpiresAt = &exp
	if err := c.AddTermsProfile(tp); err != nil {
		t.Fatalf("AddTermsProfile: %v", err)
	}
	acct, err := modelcatalog.NewProviderAccount("acct:"+provNew, provNew, modelcatalog.AccountManaged, "terms:"+provNew, "kcred://new/primary")
	if err != nil {
		t.Fatalf("NewProviderAccount: %v", err)
	}
	if err := c.AddAccount(acct); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	// Deliberately DO NOT approve acct:new-entrant.

	r, err := New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e := fullEnvelope(t)
	e.AllowedProviders = append(e.AllowedProviders, provNew)
	e.AllowedModels = append(e.AllowedModels, provNew)
	pol := &RoutePolicy{ID: "rp-pin", Mode: RouteModeProviderPinned, PinnedProviderID: provNew}
	dec := r.Decide(Request{RequestedModelID: provNew, RequestedProviderID: provNew, Envelope: e}, pol, now)
	if dec.Verdict == economic.BudgetVerdictAllow {
		t.Fatalf("unapproved new provider must not ALLOW, got %s/%s", dec.Verdict, dec.ReasonCode)
	}
	if dec.ReasonCode != economic.SpendReasonApprovalRequired {
		t.Fatalf("got reason %s, want ERR_APPROVAL_REQUIRED: %s", dec.ReasonCode, dec.Reason)
	}

	// After approval, the same request succeeds.
	if err := c.ApproveAccount("acct:" + provNew); err != nil {
		t.Fatalf("ApproveAccount: %v", err)
	}
	if err := c.SetAccountHealth("acct:"+provNew, modelcatalog.AccountHealth{State: modelcatalog.HealthHealthy, ObservedAt: now}); err != nil {
		t.Fatalf("SetAccountHealth: %v", err)
	}
	dec = r.Decide(Request{RequestedModelID: provNew, RequestedProviderID: provNew, Envelope: e}, pol, now)
	if dec.Verdict != economic.BudgetVerdictAllow {
		t.Fatalf("approved provider should ALLOW, got %s/%s: %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
}

// --- Happy path + scoring --------------------------------------------------

func TestDecide_AllowsAndSelects(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	dec := r.Decide(Request{RequestedModelID: provVision, RequestedProviderID: provVision, Envelope: fullEnvelope(t)}, balancedPolicy(), now)
	if dec.Verdict != economic.BudgetVerdictAllow {
		t.Fatalf("got %s/%s, want ALLOW: %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
	if dec.Selected == nil || dec.Selected.ProviderID != provVision {
		t.Fatalf("selected = %+v, want provider %s", dec.Selected, provVision)
	}
	if dec.RoutePolicyHash == "" {
		t.Fatal("ALLOW must carry route_policy_hash")
	}
}

// cost_first with a concrete model resolves to that provider and must report the
// cheapest as selected when the model is the cheapest provider.
func TestDecide_CostFirstSelectsCheapest(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	e := fullEnvelope(t)
	pol := &RoutePolicy{ID: "rp-cost", Mode: RouteModeCostFirst}
	dec := r.Decide(Request{RequestedModelID: provLocal, Envelope: e}, pol, now)
	if dec.Verdict != economic.BudgetVerdictAllow || dec.Selected == nil {
		t.Fatalf("got %s/%s, want ALLOW with selection: %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
	if dec.Selected.ProviderID != provLocal {
		t.Fatalf("cost_first selected %s, want %s (cheapest)", dec.Selected.ProviderID, provLocal)
	}
}

// Region/retention participate in scoring: a compliance_first policy with a
// region requirement that only some providers serve must select a region match.
func TestDecide_RegionParticipatesInScoring(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	e := fullEnvelope(t)
	// APAC is only served by vision-tool among the seed providers.
	pol := &RoutePolicy{ID: "rp-region", Mode: RouteModeComplianceFirst, RequiredRegion: "APAC"}
	dec := r.Decide(Request{RequestedModelID: provVision, Region: "APAC", Envelope: e}, pol, now)
	if dec.Verdict != economic.BudgetVerdictAllow || dec.Selected == nil {
		t.Fatalf("got %s/%s, want ALLOW: %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
	if dec.Selected.ProviderID != provVision {
		t.Fatalf("region scoring selected %s, want %s (only APAC provider)", dec.Selected.ProviderID, provVision)
	}

	// A region nobody serves denies before dispatch.
	dec = r.Decide(Request{RequestedModelID: provVision, Region: "ANTARCTICA", Envelope: e}, pol, now)
	if dec.Verdict != economic.BudgetVerdictDeny {
		t.Fatalf("unservable region should DENY, got %s/%s", dec.Verdict, dec.ReasonCode)
	}
}

// Retention ceiling participates: a policy retention cap below the account's
// retention denies the route.
func TestDecide_RetentionCeilingDenies(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	e := fullEnvelope(t)
	// Seed retention is 30 days; cap at 7 forces a contract-needed denial.
	pol := &RoutePolicy{ID: "rp-ret", Mode: RouteModeProviderPinned, PinnedProviderID: provVision, MaxDataRetentionDays: 7}
	dec := r.Decide(Request{RequestedModelID: provVision, RequestedProviderID: provVision, Envelope: e}, pol, now)
	if dec.Verdict != economic.BudgetVerdictDeny || dec.ReasonCode != economic.SpendReasonProviderContractNeeded {
		t.Fatalf("got (%s,%s), want (DENY,ERR_PROVIDER_CONTRACT_NEEDED): %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
}

// Pinned mode denies a model mismatch.
func TestDecide_PinnedModeRejectsMismatch(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	e := fullEnvelope(t)
	pol := &RoutePolicy{ID: "rp-pinned", Mode: RouteModePinned, PinnedProviderID: provVision, PinnedModelID: provVision}
	// Request the frontier model under a vision pin: model mismatch -> deny.
	dec := r.Decide(Request{RequestedModelID: provFrontier, Envelope: e}, pol, now)
	if dec.Verdict != economic.BudgetVerdictDeny {
		t.Fatalf("pinned mismatch should DENY, got %s/%s: %s", dec.Verdict, dec.ReasonCode, dec.Reason)
	}
}

func TestDecide_InvalidPolicyDenies(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	// pinned mode without pins is structurally invalid.
	dec := r.Decide(Request{RequestedModelID: provVision, Envelope: fullEnvelope(t)}, &RoutePolicy{ID: "bad", Mode: RouteModePinned}, now)
	if dec.Verdict != economic.BudgetVerdictDeny || dec.ReasonCode != economic.SpendReasonProviderContractNeeded {
		t.Fatalf("got (%s,%s), want (DENY,ERR_PROVIDER_CONTRACT_NEEDED)", dec.Verdict, dec.ReasonCode)
	}
}

func TestDecide_DeterministicSelection(t *testing.T) {
	now := time.Now().UTC()
	r := newRouter(t, now)
	e := fullEnvelope(t)
	pol := balancedPolicy()
	first := r.Decide(Request{RequestedModelID: provVision, RequestedProviderID: provVision, Envelope: e}, pol, now)
	if first.Selected == nil {
		t.Fatalf("expected a selection, got %s/%s: %s", first.Verdict, first.ReasonCode, first.Reason)
	}
	for i := 0; i < 5; i++ {
		again := r.Decide(Request{RequestedModelID: provVision, RequestedProviderID: provVision, Envelope: e}, pol, now)
		if again.Selected == nil || again.Selected.AccountID != first.Selected.AccountID || again.RoutePolicyHash != first.RoutePolicyHash {
			t.Fatalf("non-deterministic route: %+v vs %+v", again.Selected, first.Selected)
		}
	}
}

func TestRouteModes_CountAndPolicyHashStability(t *testing.T) {
	if len(RouteModes()) != 9 {
		t.Fatalf("want 9 route modes, got %d", len(RouteModes()))
	}
	p := &RoutePolicy{ID: "rp", Mode: RouteModeBalanced}
	if p.Hash() != p.Hash() {
		t.Fatal("policy hash must be stable")
	}
	q := &RoutePolicy{ID: "rp", Mode: RouteModeCostFirst}
	if p.Hash() == q.Hash() {
		t.Fatal("policies with different modes must hash differently")
	}
}
