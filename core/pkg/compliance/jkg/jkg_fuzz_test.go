package jkg

import (
	"testing"
)

// FuzzJKGParse tests the Jurisdiction Knowledge Graph parsing with fuzzed inputs.
// This ensures robustness when handling potentially malformed jurisdiction data.
func FuzzJKGParse(f *testing.F) {
	// Seed corpus with valid jurisdiction codes
	seedInputs := []string{
		// Standard ISO codes
		"EU", "US", "GB", "BG", "CY", "DE", "FR",
		// Extended codes
		"EU-MiCA", "US-FinCEN", "GB-FCA", "EU-DORA",
		// Edge cases
		"", "   ", "XX", "UNKNOWN",
		// Malformed inputs
		"eu", "e-u", "EU-", "-EU", "EU--DORA",
	}

	for _, input := range seedInputs {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, input string) {
		code := JurisdictionCode(input)

		// Test graph operations with fuzzed jurisdiction
		graph := NewGraph()

		// Try to get jurisdiction - should not panic
		j, exists := graph.GetJurisdiction(code)
		if exists && j == nil {
			t.Error("GetJurisdiction returned exists=true but nil jurisdiction")
		}

		// Try to add fuzzed jurisdiction - should not panic
		jur := &Jurisdiction{
			Code:     code,
			Name:     input,
			TimeZone: "UTC",
		}

		_ = graph.AddJurisdiction(jur)
	})
}

// FuzzObligationOperations tests obligation operations with fuzzed data.
func FuzzObligationOperations(f *testing.F) {
	// Seed with valid obligation IDs
	f.Add("EU-MiCA-Art68", "CASP", "EU")
	f.Add("DORA-Art17-1", "BANK", "EU")
	f.Add("", "", "")
	f.Add(";;;", "unknown", "XX")

	f.Fuzz(func(t *testing.T, oblID, entityType, jurisdiction string) {
		graph := NewGraph()

		// Try to get obligation with fuzzed ID
		obl, exists := graph.GetObligation(oblID)
		if exists && obl == nil {
			t.Error("GetObligation returned exists=true but nil obligation")
		}

		// Try to find applicable obligations
		jurisdictions := []JurisdictionCode{JurisdictionCode(jurisdiction)}
		obligations := graph.FindApplicableObligations(jurisdictions, entityType)
		if obligations == nil {
			t.Error("FindApplicableObligations returned nil")
		}

		// GetObligationsForJurisdiction should not panic
		obls := graph.GetObligationsForJurisdiction(JurisdictionCode(jurisdiction))
		if obls == nil {
			t.Error("GetObligationsForJurisdiction returned nil")
		}
	})
}

// FuzzRegulatorLookup tests regulator lookups with fuzzed data.
func FuzzRegulatorLookup(f *testing.F) {
	f.Add("EU-ESMA")
	f.Add("US-SEC")
	f.Add("UNKNOWN")
	f.Add("")
	f.Add("'; DROP TABLE regulators;--")

	f.Fuzz(func(t *testing.T, input string) {
		graph := NewGraph()

		regID := RegulatorID(input)
		reg, exists := graph.GetRegulator(regID)
		if exists && reg == nil {
			t.Error("GetRegulator returned exists=true but nil regulator")
		}
	})
}

// FuzzGraphOperations tests various graph operations.
func FuzzGraphOperations(f *testing.F) {
	f.Add("node1", "node2", "APPLIES_IN")
	f.Add("", "", "")
	f.Add("test", "jurisdiction", "REGULATES")

	f.Fuzz(func(t *testing.T, fromID, toID, edgeType string) {
		graph := NewGraph()

		// Add an edge - should not panic
		edge := &Edge{
			EdgeID:   "edge-" + fromID,
			Type:     EdgeType(edgeType),
			FromID:   fromID,
			FromType: "test",
			ToID:     toID,
			ToType:   "test",
		}
		_ = graph.AddEdge(edge)

		// Check for conflicts - should not panic
		conflicts := graph.GetConflicts()
		if conflicts == nil {
			t.Error("GetConflicts returned nil")
		}

		// Get metrics - should not panic
		metrics := graph.GetMetrics()
		if metrics == nil {
			t.Error("GetMetrics returned nil")
		}

		// Hash should not panic
		hash := graph.Hash()
		//nolint:staticcheck // acceptable for test logic
		if hash == "" {
			// Empty graph can have empty hash
		}
	})
}
