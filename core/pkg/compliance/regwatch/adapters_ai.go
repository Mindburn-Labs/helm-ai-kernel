package regwatch

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// NISTAIRMFAdapter monitors NIST AI Risk Management Framework 1.0 updates.
// Maps to enforceable obligations: model governance, training data provenance,
// post-market monitoring, incident reporting, transparency notices, high-risk system controls.
type NISTAIRMFAdapter struct {
	BaseAdapter
}

// NewNISTAIRMFAdapter creates a NIST AI RMF adapter.
func NewNISTAIRMFAdapter() *NISTAIRMFAdapter {
	return &NISTAIRMFAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceNISTAIRMF,
			jurisdiction: jkg.JurisdictionGlobal,
			regulator:    jkg.RegulatorNIST,
			feedURL:      "https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf",
			healthy:      true,
		},
	}
}

func (n *NISTAIRMFAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}

func (n *NISTAIRMFAdapter) IsHealthy(ctx context.Context) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.healthy
}

func (n *NISTAIRMFAdapter) SetHealthy(healthy bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.healthy = healthy
}

// EUAIActAdapter monitors the EU Artificial Intelligence Act (Regulation 2024/1689).
// Uses EUR-Lex bot-aware fetch policy. Tracks implementing acts and delegated acts.
//
// Key enforcement dates:
//
//	2025-02-02: Prohibited practices (Title II) + AI literacy (Art 4)
//	2025-08-02: GPAI transparency (Chapter V) + penalties
//	2026-08-02: High-risk obligations (Title III, Chapter 2-5) + CE marking + EU DB registration
//	2027-08-02: High-risk per Annex I (existing product safety)
//
// HELM relevance: Guardian pipeline decisions may constitute "high-risk AI" under Annex III
// when used in critical infrastructure, safety components, or financial services.
type EUAIActAdapter struct {
	BaseAdapter
}

// NewEUAIActAdapter creates an EU AI Act adapter.
func NewEUAIActAdapter() *EUAIActAdapter {
	return &EUAIActAdapter{
		BaseAdapter: BaseAdapter{
			sourceType:   SourceEUAIAct,
			jurisdiction: jkg.JurisdictionEU,
			regulator:    jkg.RegulatorEURLex,
			feedURL:      "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
			healthy:      true,
		},
	}
}

// FetchChanges returns EU AI Act obligations as RegChange items.
// Seed data covers the key obligation categories that HELM deployments must address.
// Production path: EUR-Lex CELLAR SPARQL for amendments to CELEX:32024R1689.
func (e *EUAIActAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	highRiskDeadline := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	obligations := []struct {
		article   string
		title     string
		summary   string
		chgType   ChangeType
		effective time.Time
		meta      map[string]interface{}
	}{
		{
			article:   "Art.6+AnnexIII",
			title:     "High-Risk AI System Classification",
			summary:   "AI systems in Annex III areas (critical infrastructure, safety components, financial services) must comply with Chapter 2 requirements: risk management, data governance, technical docs, record-keeping, transparency, human oversight, accuracy/robustness/cybersecurity.",
			chgType:   ChangeNew,
			effective: highRiskDeadline,
			meta:      map[string]interface{}{"articles": "6,9-15", "annex": "III", "helm_impact": "guardian_pipeline"},
		},
		{
			article:   "Art.9",
			title:     "Risk Management System (High-Risk)",
			summary:   "Continuous risk management system required: identify risks, estimate/evaluate, adopt management measures, test. HELM Guardian 6-gate pipeline maps to this requirement.",
			chgType:   ChangeNew,
			effective: highRiskDeadline,
			meta:      map[string]interface{}{"articles": "9", "helm_impact": "guardian_risk_management"},
		},
		{
			article:   "Art.14",
			title:     "Human Oversight (High-Risk)",
			summary:   "High-risk AI must enable human oversight: understand capabilities/limitations, monitor operation, intervene/interrupt, decide not to use. HELM intervention gates and escalation ceremonies map here.",
			chgType:   ChangeNew,
			effective: highRiskDeadline,
			meta:      map[string]interface{}{"articles": "14", "helm_impact": "escalation_ceremony"},
		},
		{
			article:   "Art.50",
			title:     "Transparency for GPAI Providers",
			summary:   "General-purpose AI providers must: disclose AI-generated content, publish training data summaries, comply with copyright, publish model capabilities and limitations.",
			chgType:   ChangeNew,
			effective: time.Date(2025, 8, 2, 0, 0, 0, 0, time.UTC),
			meta:      map[string]interface{}{"articles": "50,52,53", "category": "transparency"},
		},
		{
			article:   "Art.62",
			title:     "Serious Incident Reporting (72h)",
			summary:   "Providers/deployers of high-risk AI must report serious incidents to market surveillance authorities within 72 hours of becoming aware. HELM evidence packs provide audit trail.",
			chgType:   ChangeNew,
			effective: highRiskDeadline,
			meta:      map[string]interface{}{"articles": "62", "deadline_hours": 72, "helm_impact": "evidence_pack_reporting"},
		},
		{
			article:   "Art.49",
			title:     "CE Marking and EU Database Registration",
			summary:   "High-risk AI systems require CE marking and registration in EU database before placing on market or putting into service.",
			chgType:   ChangeDeadline,
			effective: highRiskDeadline,
			meta:      map[string]interface{}{"articles": "49,71", "category": "conformity_assessment"},
		},
	}

	now := time.Now()
	var changes []*RegChange
	for _, ob := range obligations {
		changes = append(changes, &RegChange{
			SourceType:       e.sourceType,
			ChangeType:       ob.chgType,
			JurisdictionCode: e.jurisdiction,
			RegulatorID:      jkg.RegulatorEURLex,
			Framework:        "EU AI Act",
			Title:            fmt.Sprintf("[%s] %s", ob.article, ob.title),
			Summary:          ob.summary,
			SourceURL:        "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
			PublishedAt:      time.Date(2024, 7, 12, 0, 0, 0, 0, time.UTC),
			EffectiveFrom:    ob.effective,
			DetectedAt:       now,
			Metadata:         ob.meta,
		})
	}

	return changes, nil
}

func (e *EUAIActAdapter) IsHealthy(ctx context.Context) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthy
}

func (e *EUAIActAdapter) SetHealthy(healthy bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.healthy = healthy
}
