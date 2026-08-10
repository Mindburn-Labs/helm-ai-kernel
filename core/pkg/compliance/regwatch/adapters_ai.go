package regwatch

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/compliance/jkg"
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
//	2025-08-02: GPAI obligations (Chapter V) + penalties
//	2026-08-02: General application, including Arts.48, 49, 50, 71 and 73
//	2026-12-02: Art.50(2) transition for specified pre-existing systems
//	2027-12-02: Chapter III, Sections 1-3 for Annex III systems
//	2028-08-02: Chapter III, Sections 1-3 for Annex I systems
//
// Dates amended by Regulation (EU) 2026/1744 (in force 2026-07-27); verified
// against EUR-Lex. The amended Chapter III dates expressly exclude Article
// 6(5) and do not move obligations outside Sections 1-3.
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
	generalApplication := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	article50PreexistingTransition := time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC)
	highRiskDeadline := time.Date(2027, 12, 2, 0, 0, 0, 0, time.UTC)

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
			summary:   "AI systems in Annex III areas may be high-risk under Article 6. The amended deadline applies only to Chapter III, Sections 1-3 for Annex III systems and expressly excludes Article 6(5).",
			chgType:   ChangeNew,
			effective: highRiskDeadline,
			meta:      map[string]interface{}{"articles": "6,9-15", "annex": "III", "scope": "chapter_iii_sections_1_3", "article_6_5_deferred": false, "helm_impact": "guardian_pipeline"},
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
			title:     "Transparency Duties for Certain AI Systems",
			summary:   "Article 50 covers disclosure and machine-readable marking duties for specified AI systems and deployers. Article 111(4) provides a transition for specified pre-existing Article 50(2) systems.",
			chgType:   ChangeNew,
			effective: generalApplication,
			meta:      map[string]interface{}{"articles": "50", "category": "transparency", "article_50_2_preexisting_transition": article50PreexistingTransition.Format("2006-01-02")},
		},
		{
			article:   "Art.73",
			title:     "Serious Incident Reporting",
			summary:   "Providers of high-risk AI systems must report immediately and no later than the applicable outer deadline: 15 days generally, 2 days for widespread-infringement or Article 3(49)(b) incidents, and 10 days where a person dies.",
			chgType:   ChangeNew,
			effective: generalApplication,
			meta:      map[string]interface{}{"articles": "73", "deadline_days_general": 15, "deadline_days_widespread_or_critical": 2, "deadline_days_death": 10, "helm_impact": "evidence_pack_reporting"},
		},
		{
			article:   "Arts.48,49,71",
			title:     "CE Marking and EU Database Registration",
			summary:   "Articles 48, 49 and 71 govern CE marking and EU database registration outside the amended Chapter III, Sections 1-3 deferral; applicability depends on the system and its transition rules.",
			chgType:   ChangeDeadline,
			effective: generalApplication,
			meta:      map[string]interface{}{"articles": "48,49,71", "category": "conformity_assessment"},
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
