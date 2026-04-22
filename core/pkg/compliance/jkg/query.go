package jkg

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// QueryResult represents a compliance query result.
type QueryResult struct {
	Obligations []*Obligation
	Conflicts   []*ConflictInfo
	Regulators  []*Regulator
	TotalRisk   RiskLevel
	QueryTime   time.Duration
	GraphHash   string
}

// ConflictInfo provides detailed conflict information.
type ConflictInfo struct {
	ObligationA    *Obligation
	ObligationB    *Obligation
	ConflictReason string
	Severity       string
	Recommendation string
}

// Query provides advanced query capabilities for the JKG.
type Query struct {
	graph *Graph
}

// NewQuery creates a new query interface for the graph.
func NewQuery(g *Graph) *Query {
	return &Query{graph: g}
}

// ApplicabilityRequest defines an applicability query.
type ApplicabilityRequest struct {
	EntityID       string
	EntityType     string
	Jurisdictions  []JurisdictionCode
	Frameworks     []string  // e.g., ["MiCA", "EU AI Act"]
	AsOfDate       time.Time // Query as of specific date
	IncludeExpired bool
}

// ApplicabilityResult contains applicable obligations and analysis.
type ApplicabilityResult struct {
	EntityID          string
	Obligations       []*Obligation
	Conflicts         []*ConflictInfo
	RiskSummary       map[RiskLevel]int
	FrameworkCoverage map[string]int
	GraphVersion      string
	QueryTimestamp    time.Time
}

// FindApplicable returns all obligations applicable to an entity.
//
//nolint:gocognit // complexity acceptable
func (q *Query) FindApplicable(req *ApplicabilityRequest) *ApplicabilityResult {
	start := time.Now()

	result := &ApplicabilityResult{
		EntityID:          req.EntityID,
		Obligations:       make([]*Obligation, 0),
		Conflicts:         make([]*ConflictInfo, 0),
		RiskSummary:       make(map[RiskLevel]int),
		FrameworkCoverage: make(map[string]int),
		GraphVersion:      q.graph.Hash(),
		QueryTimestamp:    start,
	}

	// Collect applicable obligations
	seen := make(map[string]bool)

	q.graph.mu.RLock()
	defer q.graph.mu.RUnlock()

	for _, code := range req.Jurisdictions {
		for _, o := range q.graph.obligations {
			if seen[o.ObligationID] {
				continue
			}

			if !q.matchesJurisdiction(o, code) {
				continue
			}

			if len(req.Frameworks) > 0 && !q.matchesFramework(o, req.Frameworks) {
				continue
			}

			if !req.AsOfDate.IsZero() && !q.isEffective(o, req.AsOfDate) {
				continue
			}

			if !req.IncludeExpired && o.isExpired() {
				continue
			}

			seen[o.ObligationID] = true
			result.Obligations = append(result.Obligations, o)
			result.RiskSummary[o.RiskLevel]++
			result.FrameworkCoverage[o.Framework]++
		}
	}

	// Sort by risk level (critical first)
	sort.Slice(result.Obligations, func(i, j int) bool {
		return riskPriority(result.Obligations[i].RiskLevel) > riskPriority(result.Obligations[j].RiskLevel)
	})

	// Detect conflicts
	result.Conflicts = q.detectConflicts(result.Obligations)

	return result
}

// matchesJurisdiction checks if obligation applies to jurisdiction (including parent).
func (q *Query) matchesJurisdiction(o *Obligation, code JurisdictionCode) bool {
	if o.JurisdictionCode == code {
		return true
	}

	// Check if jurisdiction is child of obligation's jurisdiction
	if j, ok := q.graph.jurisdictions[code]; ok {
		if j.ParentCode == o.JurisdictionCode {
			return true
		}
	}

	return false
}

// matchesFramework checks if obligation is in requested frameworks.
func (q *Query) matchesFramework(o *Obligation, frameworks []string) bool {
	for _, f := range frameworks {
		if strings.EqualFold(o.Framework, f) {
			return true
		}
	}
	return false
}

// isEffective checks if obligation was effective at given date.
func (q *Query) isEffective(o *Obligation, asOf time.Time) bool {
	if !o.EffectiveFrom.IsZero() && asOf.Before(o.EffectiveFrom) {
		return false
	}
	if !o.SunsetAt.IsZero() && asOf.After(o.SunsetAt) {
		return false
	}
	return true
}

// detectConflicts finds conflicts between applicable obligations.
func (q *Query) detectConflicts(obligations []*Obligation) []*ConflictInfo {
	conflicts := make([]*ConflictInfo, 0)

	obligMap := make(map[string]*Obligation)
	for _, o := range obligations {
		obligMap[o.ObligationID] = o
	}

	for _, e := range q.graph.edges {
		if e.Type != EdgeConflictsWith {
			continue
		}

		oA, okA := obligMap[e.FromID]
		oB, okB := obligMap[e.ToID]

		if okA && okB {
			reason := ""
			severity := "unknown"
			if e.Properties != nil {
				if r, ok := e.Properties["reason"].(string); ok {
					reason = r
				}
				if s, ok := e.Properties["severity"].(string); ok {
					severity = s
				}
			}

			conflicts = append(conflicts, &ConflictInfo{
				ObligationA:    oA,
				ObligationB:    oB,
				ConflictReason: reason,
				Severity:       severity,
				Recommendation: q.generateRecommendation(oA, oB, severity),
			})
		}
	}

	return conflicts
}

// generateRecommendation produces a recommendation for resolving conflict.
func (q *Query) generateRecommendation(a, b *Obligation, severity string) string {
	if severity == "critical" {
		return fmt.Sprintf("URGENT: Consult legal counsel for %s vs %s conflict", a.Framework, b.Framework)
	}

	// Higher risk takes precedence
	if riskPriority(a.RiskLevel) > riskPriority(b.RiskLevel) {
		return fmt.Sprintf("Prioritize %s compliance (%s) over %s", a.Title, a.Framework, b.Framework)
	}
	if riskPriority(b.RiskLevel) > riskPriority(a.RiskLevel) {
		return fmt.Sprintf("Prioritize %s compliance (%s) over %s", b.Title, b.Framework, a.Framework)
	}

	return "Review both obligations and apply stricter requirement"
}

// riskPriority returns numeric priority for sorting.
func riskPriority(r RiskLevel) int {
	switch r {
	case RiskCritical:
		return 5
	case RiskHigh:
		return 4
	case RiskMedium:
		return 3
	case RiskLow:
		return 2
	case RiskInfo:
		return 1
	default:
		return 0
	}
}

// FrameworkSummary returns summary of obligations by framework.
func (q *Query) FrameworkSummary() map[string]int {
	q.graph.mu.RLock()
	defer q.graph.mu.RUnlock()

	summary := make(map[string]int)
	for _, o := range q.graph.obligations {
		if !o.isExpired() {
			summary[o.Framework]++
		}
	}
	return summary
}

// UpcomingDeadlines returns obligations with deadlines in the next N days.
func (q *Query) UpcomingDeadlines(days int) []*Obligation {
	q.graph.mu.RLock()
	defer q.graph.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(time.Duration(days) * 24 * time.Hour)

	result := make([]*Obligation, 0)
	for _, o := range q.graph.obligations {
		if !o.EffectiveFrom.IsZero() && o.EffectiveFrom.After(now) && o.EffectiveFrom.Before(cutoff) {
			result = append(result, o)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].EffectiveFrom.Before(result[j].EffectiveFrom)
	})

	return result
}

// SearchObligations searches obligations by text.
func (q *Query) SearchObligations(text string) []*Obligation {
	q.graph.mu.RLock()
	defer q.graph.mu.RUnlock()

	text = strings.ToLower(text)
	result := make([]*Obligation, 0)

	for _, o := range q.graph.obligations {
		if strings.Contains(strings.ToLower(o.Title), text) ||
			strings.Contains(strings.ToLower(o.Description), text) ||
			strings.Contains(strings.ToLower(o.Framework), text) {
			result = append(result, o)
		}
	}

	return result
}
