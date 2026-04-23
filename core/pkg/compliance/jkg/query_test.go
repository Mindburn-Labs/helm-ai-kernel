package jkg

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQueryFindApplicable(t *testing.T) {
	g := NewGraphWithDefaults()
	q := NewQuery(g)

	req := &ApplicabilityRequest{
		EntityID:      "test-entity-001",
		EntityType:    "crypto_exchange",
		Jurisdictions: []JurisdictionCode{JurisdictionEU},
		Frameworks:    []string{"MiCA"},
	}

	result := q.FindApplicable(req)
	require.NotEmpty(t, result.Obligations)
	require.Equal(t, "test-entity-001", result.EntityID)
	require.NotEmpty(t, result.GraphVersion)

	// All returned obligations should be MiCA
	for _, o := range result.Obligations {
		require.Equal(t, "MiCA", o.Framework)
	}
}

func TestQueryFindApplicableMultiJurisdiction(t *testing.T) {
	g := NewGraphWithDefaults()
	q := NewQuery(g)

	req := &ApplicabilityRequest{
		EntityID:      "global-entity",
		EntityType:    "financial_institution",
		Jurisdictions: []JurisdictionCode{JurisdictionEU, JurisdictionUS},
	}

	result := q.FindApplicable(req)

	// Should have obligations from both jurisdictions
	hasEU := false
	hasUS := false
	for _, o := range result.Obligations {
		if o.JurisdictionCode == JurisdictionEU {
			hasEU = true
		}
		if o.JurisdictionCode == JurisdictionUS {
			hasUS = true
		}
	}
	require.True(t, hasEU, "should have EU obligations")
	require.True(t, hasUS, "should have US obligations")
}

func TestQueryConflictDetection(t *testing.T) {
	g := NewGraphWithDefaults()
	q := NewQuery(g)

	req := &ApplicabilityRequest{
		EntityID:      "cross-border-entity",
		Jurisdictions: []JurisdictionCode{JurisdictionEU, JurisdictionUS},
	}

	result := q.FindApplicable(req)

	// Should detect conflicts between EU and US obligations
	require.NotEmpty(t, result.Conflicts)
}

func TestQueryRiskSummary(t *testing.T) {
	g := NewGraphWithDefaults()
	q := NewQuery(g)

	req := &ApplicabilityRequest{
		EntityID:      "test-entity",
		Jurisdictions: []JurisdictionCode{JurisdictionEU},
	}

	result := q.FindApplicable(req)

	// Should have risk summary populated
	require.NotEmpty(t, result.RiskSummary)

	// Should have critical obligations (MiCA CASP auth is critical)
	require.Greater(t, result.RiskSummary[RiskCritical], 0)
}

func TestQueryFrameworkSummary(t *testing.T) {
	g := NewGraphWithDefaults()
	q := NewQuery(g)

	summary := q.FrameworkSummary()
	require.NotEmpty(t, summary)
	require.Greater(t, summary["MiCA"], 0)
	require.Greater(t, summary["EU AI Act"], 0)
}

func TestQueryUpcomingDeadlines(t *testing.T) {
	g := NewGraph()
	q := NewQuery(g)

	// Add obligation with future deadline
	future := time.Now().Add(10 * 24 * time.Hour)
	_ = g.AddObligation(&Obligation{
		ObligationID:     "FUTURE-001",
		JurisdictionCode: JurisdictionEU,
		EffectiveFrom:    future,
	})

	// Add obligation with past deadline
	past := time.Now().Add(-10 * 24 * time.Hour)
	_ = g.AddObligation(&Obligation{
		ObligationID:     "PAST-001",
		JurisdictionCode: JurisdictionEU,
		EffectiveFrom:    past,
	})

	upcoming := q.UpcomingDeadlines(30)
	require.Len(t, upcoming, 1)
	require.Equal(t, "FUTURE-001", upcoming[0].ObligationID)
}

func TestQuerySearchObligations(t *testing.T) {
	g := NewGraphWithDefaults()
	q := NewQuery(g)

	results := q.SearchObligations("CASP")
	require.NotEmpty(t, results)

	for _, o := range results {
		require.Contains(t, o.Title+o.Description, "CASP")
	}
}

func TestQueryAsOfDate(t *testing.T) {
	g := NewGraph()
	q := NewQuery(g)

	// Obligation effective from Jan 2025
	_ = g.AddObligation(&Obligation{
		ObligationID:     "NEW-2025",
		JurisdictionCode: JurisdictionEU,
		EffectiveFrom:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	// Query as of Dec 2024 (before effective)
	req := &ApplicabilityRequest{
		EntityID:      "test",
		Jurisdictions: []JurisdictionCode{JurisdictionEU},
		AsOfDate:      time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC),
	}

	result := q.FindApplicable(req)
	require.Empty(t, result.Obligations)

	// Query as of Feb 2025 (after effective)
	req.AsOfDate = time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	result = q.FindApplicable(req)
	require.Len(t, result.Obligations, 1)
}

func TestQueryParentJurisdiction(t *testing.T) {
	g := NewGraphWithDefaults()
	q := NewQuery(g)

	// Query for Bulgaria should include EU obligations
	req := &ApplicabilityRequest{
		EntityID:      "bg-entity",
		Jurisdictions: []JurisdictionCode{JurisdictionBG},
	}

	result := q.FindApplicable(req)

	// Should have EU obligations included due to parent relationship
	hasEU := false
	for _, o := range result.Obligations {
		if o.JurisdictionCode == JurisdictionEU {
			hasEU = true
			break
		}
	}
	require.True(t, hasEU, "Bulgaria should inherit EU obligations")
}

func TestNewGraphWithDefaults(t *testing.T) {
	g := NewGraphWithDefaults()

	m := g.GetMetrics()
	require.Greater(t, m.TotalJurisdictions, 0)
	require.Greater(t, m.TotalRegulators, 0)
	require.Greater(t, m.TotalObligations, 0)
	require.Greater(t, m.TotalEdges, 0)
	require.Greater(t, m.ConflictCount, 0)
}
