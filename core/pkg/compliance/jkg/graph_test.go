package jkg

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewGraph(t *testing.T) {
	g := NewGraph()
	require.NotNil(t, g)
	require.NotNil(t, g.metrics)
	require.Empty(t, g.jurisdictions)
	require.Empty(t, g.regulators)
	require.Empty(t, g.obligations)
}

func TestAddJurisdiction(t *testing.T) {
	g := NewGraph()

	j := &Jurisdiction{
		Code:       JurisdictionEU,
		Name:       "European Union",
		Regulators: []RegulatorID{RegulatorESMA, RegulatorEBA},
		TimeZone:   "CET",
	}

	err := g.AddJurisdiction(j)
	require.NoError(t, err)

	retrieved, ok := g.GetJurisdiction(JurisdictionEU)
	require.True(t, ok)
	require.Equal(t, "European Union", retrieved.Name)
	require.NotZero(t, retrieved.LastUpdated)
}

func TestAddJurisdictionEmpty(t *testing.T) {
	g := NewGraph()

	j := &Jurisdiction{Name: "No Code"}
	err := g.AddJurisdiction(j)
	require.Error(t, err)
	require.Contains(t, err.Error(), "code is required")
}

func TestAddRegulator(t *testing.T) {
	g := NewGraph()

	r := &Regulator{
		ID:           RegulatorESMA,
		Name:         "European Securities and Markets Authority",
		Jurisdiction: JurisdictionEU,
		Scope:        []string{"securities", "crypto"},
		Website:      "https://www.esma.europa.eu",
	}

	err := g.AddRegulator(r)
	require.NoError(t, err)

	retrieved, ok := g.GetRegulator(RegulatorESMA)
	require.True(t, ok)
	require.Equal(t, "European Securities and Markets Authority", retrieved.Name)
}

func TestAddObligation(t *testing.T) {
	g := NewGraph()

	o := &Obligation{
		ObligationID:     "MICA-ART-15-3",
		JurisdictionCode: JurisdictionEU,
		RegulatorID:      RegulatorESMA,
		Framework:        "MiCA",
		ArticleRef:       "Article 15(3)",
		Type:             ObligationRequirement,
		Title:            "CASP Authorization",
		Description:      "Crypto asset service providers must obtain authorization",
		EffectiveFrom:    time.Date(2024, 12, 30, 0, 0, 0, 0, time.UTC),
		RiskLevel:        RiskHigh,
		PenaltyMax:       "€5M or 3% turnover",
	}

	err := g.AddObligation(o)
	require.NoError(t, err)

	retrieved, ok := g.GetObligation("MICA-ART-15-3")
	require.True(t, ok)
	require.Equal(t, "CASP Authorization", retrieved.Title)
	require.Equal(t, "MiCA", retrieved.Framework)
}

func TestGetObligationsForJurisdiction(t *testing.T) {
	g := NewGraph()

	// Add jurisdictions
	_ = g.AddJurisdiction(&Jurisdiction{
		Code: JurisdictionEU,
		Name: "European Union",
	})
	_ = g.AddJurisdiction(&Jurisdiction{
		Code:       JurisdictionBG,
		Name:       "Bulgaria",
		ParentCode: JurisdictionEU,
	})

	// Add EU obligation
	_ = g.AddObligation(&Obligation{
		ObligationID:     "EU-AML5-KYC",
		JurisdictionCode: JurisdictionEU,
		RegulatorID:      RegulatorEBA,
		Framework:        "AML5",
		Type:             ObligationRequirement,
		Title:            "KYC Requirements",
	})

	// Add BG-specific obligation
	_ = g.AddObligation(&Obligation{
		ObligationID:     "BG-FSC-001",
		JurisdictionCode: JurisdictionBG,
		RegulatorID:      RegulatorFSC,
		Framework:        "FSC Ordinance",
		Type:             ObligationReporting,
		Title:            "FSC Reporting",
	})

	// Bulgaria should see both EU and BG obligations
	bgObligs := g.GetObligationsForJurisdiction(JurisdictionBG)
	require.Len(t, bgObligs, 2)

	// EU should only see EU obligations
	euObligs := g.GetObligationsForJurisdiction(JurisdictionEU)
	require.Len(t, euObligs, 1)
}

func TestEdgeCreation(t *testing.T) {
	g := NewGraph()

	o := &Obligation{
		ObligationID:     "TEST-001",
		JurisdictionCode: JurisdictionUS,
		RegulatorID:      RegulatorFinCEN,
		Type:             ObligationRequirement,
	}

	err := g.AddObligation(o)
	require.NoError(t, err)

	// Should auto-create APPLIES_IN and REGULATES edges
	metrics := g.GetMetrics()
	require.Equal(t, 2, metrics.TotalEdges)
}

func TestAddConflictEdge(t *testing.T) {
	g := NewGraph()

	conflict := &Edge{
		Type:     EdgeConflictsWith,
		FromID:   "EU-DATA-001",
		FromType: "obligation",
		ToID:     "US-CLOUD-ACT-001",
		ToType:   "obligation",
		Properties: map[string]interface{}{
			"reason": "Data localization vs foreign subpoena",
		},
	}

	err := g.AddEdge(conflict)
	require.NoError(t, err)

	conflicts := g.GetConflicts()
	require.Len(t, conflicts, 1)
	require.Equal(t, EdgeConflictsWith, conflicts[0].Type)
}

func TestFindApplicableObligations(t *testing.T) {
	g := NewGraph()

	// Setup obligations
	_ = g.AddObligation(&Obligation{
		ObligationID:     "EU-CASP-001",
		JurisdictionCode: JurisdictionEU,
		Type:             ObligationRequirement,
	})
	_ = g.AddObligation(&Obligation{
		ObligationID:     "US-MSB-001",
		JurisdictionCode: JurisdictionUS,
		Type:             ObligationRegistration,
	})
	_ = g.AddObligation(&Obligation{
		ObligationID:     "GB-FCA-001",
		JurisdictionCode: JurisdictionGB,
		Type:             ObligationReporting,
	})

	// Entity operating in EU and US (not GB)
	applicable := g.FindApplicableObligations(
		[]JurisdictionCode{JurisdictionEU, JurisdictionUS},
		"crypto_exchange",
	)

	require.Len(t, applicable, 2)
}

func TestObligationExpiry(t *testing.T) {
	g := NewGraph()

	// Expired obligation
	_ = g.AddObligation(&Obligation{
		ObligationID:     "OLD-001",
		JurisdictionCode: JurisdictionEU,
		Type:             ObligationRequirement,
		SunsetAt:         time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	// Active obligation
	_ = g.AddObligation(&Obligation{
		ObligationID:     "NEW-001",
		JurisdictionCode: JurisdictionEU,
		Type:             ObligationRequirement,
	})

	obligs := g.GetObligationsForJurisdiction(JurisdictionEU)
	require.Len(t, obligs, 1)
	require.Equal(t, "NEW-001", obligs[0].ObligationID)
}

func TestGraphHash(t *testing.T) {
	g1 := NewGraph()
	g2 := NewGraph()

	hash1 := g1.Hash()
	hash2 := g2.Hash()
	require.Equal(t, hash1, hash2)

	_ = g1.AddJurisdiction(&Jurisdiction{Code: JurisdictionEU, Name: "EU"})
	hash3 := g1.Hash()
	require.NotEqual(t, hash1, hash3)
}

func TestGraphMetrics(t *testing.T) {
	g := NewGraph()

	_ = g.AddJurisdiction(&Jurisdiction{Code: JurisdictionEU})
	_ = g.AddJurisdiction(&Jurisdiction{Code: JurisdictionUS})
	_ = g.AddRegulator(&Regulator{ID: RegulatorESMA})
	_ = g.AddObligation(&Obligation{
		ObligationID:     "TEST-001",
		JurisdictionCode: JurisdictionEU,
		RegulatorID:      RegulatorESMA,
	})

	metrics := g.GetMetrics()
	require.Equal(t, 2, metrics.TotalJurisdictions)
	require.Equal(t, 1, metrics.TotalRegulators)
	require.Equal(t, 1, metrics.TotalObligations)
	require.Equal(t, 2, metrics.TotalEdges) // Auto-created
}

func TestConcurrentAccess(t *testing.T) {
	g := NewGraph()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan bool)

	// Concurrent writers
	for i := 0; i < 10; i++ {
		go func(idx int) {
			select {
			case <-ctx.Done():
				return
			default:
				_ = g.AddJurisdiction(&Jurisdiction{
					Code: JurisdictionCode(string(rune('A' + idx))),
					Name: "Test",
				})
				done <- true
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			select {
			case <-ctx.Done():
				return
			default:
				_ = g.GetMetrics()
				_ = g.Hash()
				done <- true
			}
		}()
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}
