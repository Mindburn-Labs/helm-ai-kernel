package router

import (
	"errors"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/modelcatalog"
)

// Request is a fully-specified route request. The router never trusts an agent
// for credentials: the caller provides only intent (model, region, capability)
// plus the spend envelope that grants spend — not provider-key — authority.
type Request struct {
	TenantID string `json:"tenant_id,omitempty"`
	// RequestedModelID is the model the caller wants. Required.
	RequestedModelID string `json:"requested_model_id"`
	// RequestedProviderID optionally narrows to one provider.
	RequestedProviderID string `json:"requested_provider_id,omitempty"`
	// Region is the region the workload must run in, if constrained.
	Region string `json:"region,omitempty"`
	// RequiredCapabilities must all be present on the provider record.
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	// Envelope is the agent spend envelope. Its AllowedProviders/AllowedModels
	// are the authoritative agent-facing allow-list; the router enforces it
	// before any catalog candidate is considered.
	Envelope *economic.AgentSpendEnvelope `json:"-"`
}

// Candidate is one provider/model/account the router evaluated, with its score.
type Candidate struct {
	ProviderID string  `json:"provider_id"`
	ModelID    string  `json:"model_id"`
	AccountID  string  `json:"account_id"`
	Score      float64 `json:"score"`
}

// Decision is the fail-closed outcome of a route evaluation.
type Decision struct {
	Verdict         economic.BudgetVerdict   `json:"verdict"`
	ReasonCode      economic.SpendReasonCode `json:"reason_code"`
	Reason          string                   `json:"reason"`
	Selected        *Candidate               `json:"selected,omitempty"`
	RoutePolicyHash string                   `json:"route_policy_hash"`
	Considered      []Candidate              `json:"considered,omitempty"`
}

func deny(code economic.SpendReasonCode, reason, policyHash string) Decision {
	return Decision{Verdict: economic.BudgetVerdictDeny, ReasonCode: code, Reason: reason, RoutePolicyHash: policyHash}
}

func escalateDecision(code economic.SpendReasonCode, reason, policyHash string) Decision {
	return Decision{Verdict: economic.BudgetVerdictEscalate, ReasonCode: code, Reason: reason, RoutePolicyHash: policyHash}
}

// Router evaluates route requests against a catalog under a route policy.
type Router struct {
	catalog *modelcatalog.Catalog
}

// New returns a router bound to a catalog.
func New(catalog *modelcatalog.Catalog) (*Router, error) {
	if catalog == nil {
		return nil, errors.New("router: catalog is required")
	}
	return &Router{catalog: catalog}, nil
}

// Decide selects a route or refuses, fail-closed. It enforces, in order:
//  1. structural validity of policy and request;
//  2. the agent spend envelope allow-list (forbidden provider/model -> DENY);
//  3. policy pins (pinned/provider_pinned/model_pinned/region_pinned);
//  4. per-candidate compliance — terms profile validity & freshness, retention
//     ceiling, region, risk tier, and account health;
//  5. mode-specific scoring, where region and retention participate.
//
// A DEGRADED account on the winning route yields ESCALATE; an empty compliant
// set yields DENY (or ESCALATE) with the most specific reason observed.
func (r *Router) Decide(req Request, policy *RoutePolicy, now time.Time) Decision {
	if err := policy.Validate(); err != nil {
		return deny(economic.SpendReasonProviderContractNeeded, "invalid route policy: "+err.Error(), "")
	}
	policyHash := policy.Hash()

	if req.RequestedModelID == "" {
		return deny(economic.SpendReasonModelNotAllowed, "requested_model_id is required", policyHash)
	}
	if req.Envelope == nil {
		return deny(economic.SpendReasonEnvelopeNotFound, "spend envelope is required for routing", policyHash)
	}

	// Agent-facing allow-list gates first: the envelope is the agent's authority.
	// A provider or model outside it is denied before any catalog lookup, so a
	// compromised or over-reaching agent cannot widen its provider reach.
	if req.RequestedProviderID != "" && !req.Envelope.AllowsProvider(req.RequestedProviderID) {
		return deny(economic.SpendReasonProviderNotAllowed, "requested provider is not in the spend envelope allow-list", policyHash)
	}
	if !req.Envelope.AllowsModel(req.RequestedModelID) {
		return deny(economic.SpendReasonModelNotAllowed, "requested model is not in the spend envelope allow-list", policyHash)
	}

	providerIDs, pinReason := r.candidateProviderIDs(req, policy)
	if len(providerIDs) == 0 {
		return deny(pinReason.code, pinReason.reason, policyHash)
	}

	cands, lastDeny := r.buildCandidates(req, policy, providerIDs, now)
	if len(cands) == 0 {
		if lastDeny.code == "" {
			return deny(economic.SpendReasonProviderNotAllowed, "no compliant route candidate", policyHash)
		}
		if lastDeny.escalate {
			return escalateDecision(lastDeny.code, lastDeny.reason, policyHash)
		}
		return deny(lastDeny.code, lastDeny.reason, policyHash)
	}

	r.scoreCandidates(cands, policy)
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].cand.Score != cands[j].cand.Score {
			return cands[i].cand.Score > cands[j].cand.Score
		}
		if cands[i].cand.ProviderID != cands[j].cand.ProviderID {
			return cands[i].cand.ProviderID < cands[j].cand.ProviderID
		}
		return cands[i].cand.AccountID < cands[j].cand.AccountID
	})

	considered := make([]Candidate, 0, len(cands))
	for _, sc := range cands {
		considered = append(considered, sc.cand)
	}
	winner := cands[0]

	verdict := economic.BudgetVerdictAllow
	reasonCode := economic.SpendReasonOKWithinEnvelope
	reason := "route selected within policy and envelope"
	if winner.degraded {
		verdict = economic.BudgetVerdictEscalate
		reasonCode = economic.SpendReasonApprovalRequired
		reason = "selected account is degraded; route requires approval"
	}

	sel := winner.cand
	return Decision{
		Verdict:         verdict,
		ReasonCode:      reasonCode,
		Reason:          reason,
		Selected:        &sel,
		RoutePolicyHash: policyHash,
		Considered:      considered,
	}
}

type denyInfo struct {
	code     economic.SpendReasonCode
	reason   string
	escalate bool
}

// candidateProviderIDs resolves which providers are eligible under the policy
// pins and the requested provider. Returns the provider id set and, when empty,
// the reason it is empty.
func (r *Router) candidateProviderIDs(req Request, policy *RoutePolicy) ([]string, denyInfo) {
	want := func(id string) bool {
		return req.RequestedProviderID == "" || req.RequestedProviderID == id
	}

	switch policy.Mode {
	case RouteModePinned, RouteModeProviderPinned:
		if req.RequestedProviderID != "" && req.RequestedProviderID != policy.PinnedProviderID {
			return nil, denyInfo{economic.SpendReasonProviderNotAllowed, "requested provider conflicts with pinned provider", false}
		}
		if _, ok := r.catalog.Provider(policy.PinnedProviderID); !ok {
			return nil, denyInfo{economic.SpendReasonProviderNotAllowed, "pinned provider is not in the catalog", false}
		}
		return []string{policy.PinnedProviderID}, denyInfo{}
	default:
		var ids []string
		for _, p := range r.catalog.Providers() {
			if want(p.ProviderID) {
				ids = append(ids, p.ProviderID)
			}
		}
		if len(ids) == 0 {
			return nil, denyInfo{economic.SpendReasonProviderNotAllowed, "requested provider is not in the catalog", false}
		}
		return ids, denyInfo{}
	}
}

type scoredCandidate struct {
	cand     Candidate
	degraded bool
	// raw scoring inputs retained for blended scoring
	costPerMTok float64
	latencyMS   int
	retention   int
	regionMatch bool
}

// buildCandidates filters the eligible providers down to compliant routes. Each
// rejection is fail-closed and records the most specific reason, so an empty
// result still explains itself.
func (r *Router) buildCandidates(req Request, policy *RoutePolicy, providerIDs []string, now time.Time) ([]scoredCandidate, denyInfo) {
	var out []scoredCandidate
	var last denyInfo

	for _, providerID := range providerIDs {
		prov, ok := r.catalog.Provider(providerID)
		if !ok {
			last = denyInfo{economic.SpendReasonProviderNotAllowed, "provider not in catalog", false}
			continue
		}

		modelID := req.RequestedModelID
		if policy.Mode == RouteModePinned || policy.Mode == RouteModeModelPinned {
			if policy.PinnedModelID != modelID {
				last = denyInfo{economic.SpendReasonModelNotAllowed, "requested model conflicts with pinned model", false}
				continue
			}
		}

		if !hasAllCapabilities(prov.Capabilities, req.RequiredCapabilities) {
			last = denyInfo{economic.SpendReasonModelNotAllowed, "provider lacks a required capability", false}
			continue
		}

		if policy.MaxRiskTier != "" && riskTierRank(prov.RiskTier) > riskTierRank(policy.MaxRiskTier) {
			last = denyInfo{economic.SpendReasonProviderNotAllowed, "provider risk tier exceeds policy ceiling", false}
			continue
		}

		region := req.Region
		if policy.Mode == RouteModeRegionPinned {
			region = policy.RequiredRegion
		} else if region == "" {
			region = policy.RequiredRegion
		}
		regionMatch := region == "" || containsString(prov.Regions, region)
		if region != "" && !regionMatch {
			last = denyInfo{economic.SpendReasonProviderNotAllowed, "provider does not serve required region " + region, false}
			continue
		}

		accounts := r.catalog.ApprovedAccountsForProvider(providerID)
		if len(accounts) == 0 {
			// No approved account => provider not yet admitted (new-provider gate).
			last = denyInfo{economic.SpendReasonApprovalRequired, "provider has no approved account", true}
			continue
		}

		for _, acct := range accounts {
			tp, ok := r.catalog.TermsProfile(acct.TermsProfileID)
			if !ok {
				last = denyInfo{economic.SpendReasonProviderContractNeeded, "account terms profile is missing", false}
				continue
			}
			if err := tp.Validate(); err != nil {
				last = denyInfo{economic.SpendReasonProviderContractNeeded, "account terms profile is invalid: " + err.Error(), false}
				continue
			}
			if termsProfileStale(tp, now) {
				last = denyInfo{economic.SpendReasonProviderContractNeeded, "account terms profile is expired/stale", false}
				continue
			}
			if policy.MaxDataRetentionDays > 0 && tp.DataRetentionDays > policy.MaxDataRetentionDays {
				last = denyInfo{economic.SpendReasonProviderContractNeeded, "account retention exceeds policy ceiling", false}
				continue
			}

			routable, hcode := acct.Routable(now)
			if !routable {
				esc := hcode == economic.SpendReasonApprovalRequired
				last = denyInfo{hcode, "account not routable (health/approval): " + acct.ID, esc}
				if !esc {
					continue
				}
				out = append(out, newScoredCandidate(prov, modelID, acct, tp, regionMatch, true))
				continue
			}

			out = append(out, newScoredCandidate(prov, modelID, acct, tp, regionMatch, false))
		}
	}

	return out, last
}

func newScoredCandidate(prov contracts.ModelProvider, modelID string, acct *modelcatalog.ProviderAccount, tp *economic.ProviderTermsProfile, regionMatch, degraded bool) scoredCandidate {
	return scoredCandidate{
		cand: Candidate{
			ProviderID: prov.ProviderID,
			ModelID:    modelID,
			AccountID:  acct.ID,
		},
		degraded:    degraded,
		costPerMTok: prov.CostPerMTok,
		latencyMS:   prov.Latency95th,
		retention:   tp.DataRetentionDays,
		regionMatch: regionMatch,
	}
}

func hasAllCapabilities(have, want []string) bool {
	for _, w := range want {
		if !containsString(have, w) {
			return false
		}
	}
	return true
}

func termsProfileStale(tp *economic.ProviderTermsProfile, now time.Time) bool {
	if tp == nil {
		return true
	}
	if tp.ExpiresAt != nil && !now.Before(*tp.ExpiresAt) {
		return true
	}
	if tp.EffectiveAt.After(now) {
		return true
	}
	return false
}
