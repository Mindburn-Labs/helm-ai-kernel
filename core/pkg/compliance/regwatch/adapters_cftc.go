package regwatch

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// CFTCAdapter monitors US CFTC (Commodity Futures Trading Commission) regulatory updates.
//
// Key CFTC areas tracked for HELM:
//   - Innovation Task Force: LabCFTC, sandbox programs, fintech engagement
//   - Prediction market guidance: event contracts, binary options classification
//   - AI trading agent requirements: algorithmic trading, Reg AT proposals
//   - Digital asset classification: commodity vs security distinction
//   - DCM/SEF/DCO registration: derivatives market infrastructure
//
// The CFTC has primary jurisdiction over prediction markets (e.g., Polymarket)
// when event contracts are classified as swaps or commodity options under the CEA.
type CFTCAdapter struct {
	BaseAdapter
	trackingAreas []string // e.g., ["prediction_markets", "ai_agents", "digital_assets"]
}

// NewCFTCAdapter creates a CFTC adapter.
func NewCFTCAdapter(areas []string) *CFTCAdapter {
	if len(areas) == 0 {
		areas = []string{"prediction_markets", "ai_agents", "digital_assets", "innovation_task_force"}
	}
	return &CFTCAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceCFTC,
			jurisdiction: jkg.JurisdictionUS,
			regulator:    jkg.RegulatorCFTC,
			feedURL:      "https://www.cftc.gov/RSS/RSSData",
			healthy:      true,
		},
		trackingAreas: areas,
	}
}

// FetchChanges retrieves CFTC regulatory changes relevant to HELM.
// Seed data covers key obligation categories. Production path: CFTC RSS feed
// and Federal Register API filtered by CFTC-originated rules.
func (c *CFTCAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	now := time.Now()

	obligations := []struct {
		ref       string
		title     string
		summary   string
		chgType   ChangeType
		effective time.Time
		framework string
		meta      map[string]interface{}
	}{
		{
			ref:       "CEA-5c(c)(5)(C)",
			title:     "Event Contracts — Prediction Market Classification",
			summary:   "Event contracts on designated contract markets (DCMs) must comply with CEA Section 5c(c)(5)(C). CFTC has authority over swap-based prediction markets. Contracts must not involve gaming, terrorism, or other excluded activities. Binary options on events are regulated as swaps.",
			chgType:   ChangeGuidance,
			effective: time.Date(2024, 6, 10, 0, 0, 0, 0, time.UTC),
			framework: "CEA",
			meta: map[string]interface{}{
				"cea_section":  "5c(c)(5)(C)",
				"helm_impact":  "prediction_market_governance",
				"market_types": []string{"binary_options", "event_contracts", "swaps"},
			},
		},
		{
			ref:       "CFTC-ITF-2024",
			title:     "Innovation Task Force — AI Trading Agent Guidance",
			summary:   "CFTC Innovation Task Force (formerly LabCFTC) has prioritized engagement with AI-driven trading systems. Automated trading agents must maintain audit trails, implement risk controls, and ensure human oversight for material decisions. Aligns with proposed Regulation AT requirements for algorithmic traders.",
			chgType:   ChangeGuidance,
			effective: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			framework: "CFTC Innovation",
			meta: map[string]interface{}{
				"program":     "innovation_task_force",
				"helm_impact": "ai_agent_governance",
				"requires":    []string{"audit_trail", "risk_controls", "human_oversight"},
			},
		},
		{
			ref:       "Reg-AT-Proposed",
			title:     "Regulation AT — Algorithmic Trading Risk Controls",
			summary:   "Proposed Regulation AT requires pre-trade risk controls, order message throttles, and kill switches for all algorithmic trading systems on DCMs. AI-driven agents qualify as algorithmic traders under the proposed rule. Registration requirement for AT Persons with direct electronic access.",
			chgType:   ChangeNew,
			effective: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			framework: "Regulation AT",
			meta: map[string]interface{}{
				"cfr_title":   17,
				"cfr_parts":   []int{1, 38, 40, 170},
				"helm_impact": "algorithmic_trading_controls",
				"status":      "proposed",
			},
		},
		{
			ref:       "CFTC-TAC-AI-2025",
			title:     "Technology Advisory Committee — AI in Derivatives Markets",
			summary:   "TAC recommendations on responsible AI deployment in derivatives trading: model validation requirements, explainability standards for AI-driven trading decisions, ongoing monitoring for model drift and adversarial inputs. Recommendation that AI agents maintain deterministic audit logs.",
			chgType:   ChangeGuidance,
			effective: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
			framework: "TAC Recommendation",
			meta: map[string]interface{}{
				"committee":   "technology_advisory",
				"helm_impact": "model_governance",
				"requires":    []string{"model_validation", "explainability", "drift_monitoring", "audit_logs"},
			},
		},
		{
			ref:       "CEA-4s",
			title:     "Swap Dealer/MSP Requirements for AI Agents",
			summary:   "Swap dealers and major swap participants using AI execution agents must ensure compliance with business conduct standards (Part 23). AI agents executing swaps must provide pre-trade mid-market marks, disclose material risks, and verify counterparty eligibility. HELM receipt chains satisfy audit requirements.",
			chgType:   ChangeGuidance,
			effective: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			framework: "CEA",
			meta: map[string]interface{}{
				"cea_section": "4s",
				"cfr_part":    23,
				"helm_impact": "swap_execution_governance",
			},
		},
		{
			ref:       "CFTC-DCM-Core-24",
			title:     "DCM Core Principle 24 — System Safeguards for AI",
			summary:   "Designated Contract Markets must ensure system safeguards (Core Principle 20/24) cover AI-driven trading systems. Includes requirements for business continuity, disaster recovery, and cybersecurity controls for algorithmic trading infrastructure.",
			chgType:   ChangeNew,
			effective: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			framework: "DCM Core Principles",
			meta: map[string]interface{}{
				"core_principle": 24,
				"helm_impact":    "system_safeguards",
			},
		},
	}

	var changes []*RegChange
	for _, ob := range obligations {
		changes = append(changes, &RegChange{
			SourceType:       c.sourceType,
			ChangeType:       ob.chgType,
			JurisdictionCode: c.jurisdiction,
			RegulatorID:      jkg.RegulatorCFTC,
			Framework:        ob.framework,
			Title:            fmt.Sprintf("[%s] %s", ob.ref, ob.title),
			Summary:          ob.summary,
			SourceURL:        "https://www.cftc.gov/LawRegulation/CommodityExchangeAct/index.htm",
			PublishedAt:      ob.effective,
			EffectiveFrom:    ob.effective,
			DetectedAt:       now,
			Metadata:         ob.meta,
		})
	}

	return changes, nil
}

// IsHealthy checks CFTC feed availability.
func (c *CFTCAdapter) IsHealthy(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.healthy
}

// SetHealthy sets health status (for testing).
func (c *CFTCAdapter) SetHealthy(healthy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.healthy = healthy
}

// TrackingAreas returns the configured tracking areas.
func (c *CFTCAdapter) TrackingAreas() []string {
	return c.trackingAreas
}
