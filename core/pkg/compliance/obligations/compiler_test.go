package obligations

import (
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

func TestNewCompiler(t *testing.T) {
	c := NewCompiler()
	if c == nil {
		t.Fatal("expected non-nil compiler")
	}
	if len(c.tier1Controls) != 0 {
		t.Errorf("expected 0 tier1 controls, got %d", len(c.tier1Controls))
	}
	if len(c.overlays) != 0 {
		t.Errorf("expected 0 overlays, got %d", len(c.overlays))
	}
}

func TestRegisterTier1Control(t *testing.T) {
	c := NewCompiler()

	ctrl := &ControlLanguagePrimitive{
		ControlID:  "CLT-AC-001",
		Statement:  "Access to production systems must require MFA",
		Family:     "Access Control",
		Severity:   "critical",
		CheckHooks: []string{"check_mfa_enabled"},
	}

	if err := c.RegisterTier1Control(ctrl); err != nil {
		t.Fatalf("RegisterTier1Control failed: %v", err)
	}

	if len(c.tier1Controls) != 1 {
		t.Errorf("expected 1 tier1 control, got %d", len(c.tier1Controls))
	}

	// Nil and empty
	if err := c.RegisterTier1Control(nil); err == nil {
		t.Error("expected error for nil control")
	}
	if err := c.RegisterTier1Control(&ControlLanguagePrimitive{}); err == nil {
		t.Error("expected error for empty control ID")
	}
}

func TestRegisterOverlay(t *testing.T) {
	c := NewCompiler()

	overlay := &JurisdictionOverlay{
		OverlayID:      "OVL-EU-GDPR-001",
		Jurisdiction:   jkg.JurisdictionEU,
		BaseControlIDs: []string{"CLT-AC-001"},
		DeltaRules: []DeltaRule{
			{
				RuleID:         "DR-001",
				BaseControlID:  "CLT-AC-001",
				Modification:   "ADD_REQUIREMENT",
				AdditionalText: "Must implement right to erasure within 30 days",
			},
		},
		ConflictsPolicy: "strictest_wins",
	}

	if err := c.RegisterOverlay(overlay); err != nil {
		t.Fatalf("RegisterOverlay failed: %v", err)
	}

	if len(c.overlays) != 1 {
		t.Errorf("expected 1 overlay, got %d", len(c.overlays))
	}

	// Nil and empty
	if err := c.RegisterOverlay(nil); err == nil {
		t.Error("expected error for nil overlay")
	}
	if err := c.RegisterOverlay(&JurisdictionOverlay{}); err == nil {
		t.Error("expected error for empty overlay ID")
	}
}

func TestCompileSingleJurisdiction(t *testing.T) {
	c := NewCompiler()

	// Register some controls
	controls := []*ControlLanguagePrimitive{
		{ControlID: "CLT-AC-001", Statement: "MFA required", Family: "Access Control", Severity: "critical"},
		{ControlID: "CLT-AU-001", Statement: "Audit logging required", Family: "Audit", Severity: "high"},
		{ControlID: "CLT-EN-001", Statement: "Data-at-rest encryption", Family: "Encryption", Severity: "critical"},
	}
	for _, ctrl := range controls {
		if err := c.RegisterTier1Control(ctrl); err != nil {
			t.Fatalf("RegisterTier1Control failed: %v", err)
		}
	}

	result, err := c.Compile([]jkg.JurisdictionCode{jkg.JurisdictionEU})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if len(result.Obligations) != 1 {
		t.Fatalf("expected 1 obligation, got %d", len(result.Obligations))
	}

	obl := result.Obligations[0]
	if obl.Jurisdiction != jkg.JurisdictionEU {
		t.Errorf("expected EU jurisdiction, got %s", obl.Jurisdiction)
	}
	if len(obl.Controls) != 3 {
		t.Errorf("expected 3 controls, got %d", len(obl.Controls))
	}
	if obl.CompilerVersion != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", obl.CompilerVersion)
	}
}

func TestCompileMultipleJurisdictions(t *testing.T) {
	c := NewCompiler()

	c.RegisterTier1Control(&ControlLanguagePrimitive{
		ControlID: "CLT-AC-001", Statement: "MFA required", Severity: "critical",
	})

	overlay := &JurisdictionOverlay{
		OverlayID:    "OVL-US-001",
		Jurisdiction: jkg.JurisdictionUS,
		DeltaRules: []DeltaRule{
			{RuleID: "DR-001", BaseControlID: "CLT-AC-001", Modification: "RESTRICT"},
		},
		ConflictsPolicy: "strictest_wins",
	}
	c.RegisterOverlay(overlay)

	result, err := c.Compile([]jkg.JurisdictionCode{jkg.JurisdictionEU, jkg.JurisdictionUS})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if len(result.Obligations) != 2 {
		t.Fatalf("expected 2 obligations, got %d", len(result.Obligations))
	}

	// US should have the overlay
	usObl := result.Obligations[1]
	if usObl.Jurisdiction != jkg.JurisdictionUS {
		t.Errorf("expected US jurisdiction, got %s", usObl.Jurisdiction)
	}
	if len(usObl.Overlays) != 1 {
		t.Errorf("expected 1 overlay on US, got %d", len(usObl.Overlays))
	}

	// EU should have no overlays
	euObl := result.Obligations[0]
	if len(euObl.Overlays) != 0 {
		t.Errorf("expected 0 overlays on EU, got %d", len(euObl.Overlays))
	}
}

func TestCompileDeterminism(t *testing.T) {
	buildCompiler := func() *Compiler {
		c := NewCompiler()
		// Register in different orders — output should be sorted
		c.RegisterTier1Control(&ControlLanguagePrimitive{
			ControlID: "CLT-EN-001", Severity: "critical",
		})
		c.RegisterTier1Control(&ControlLanguagePrimitive{
			ControlID: "CLT-AC-001", Severity: "high",
		})
		c.RegisterTier1Control(&ControlLanguagePrimitive{
			ControlID: "CLT-AU-001", Severity: "medium",
		})
		return c
	}

	r1, _ := buildCompiler().Compile([]jkg.JurisdictionCode{jkg.JurisdictionEU})
	r2, _ := buildCompiler().Compile([]jkg.JurisdictionCode{jkg.JurisdictionEU})

	if len(r1.Obligations[0].Controls) != len(r2.Obligations[0].Controls) {
		t.Fatal("non-deterministic control count")
	}

	for i, c1 := range r1.Obligations[0].Controls {
		c2 := r2.Obligations[0].Controls[i]
		if c1.ControlID != c2.ControlID {
			t.Errorf("non-deterministic ordering at index %d: %s vs %s", i, c1.ControlID, c2.ControlID)
		}
	}

	// Verify sorted order
	for i := 1; i < len(r1.Obligations[0].Controls); i++ {
		prev := r1.Obligations[0].Controls[i-1].ControlID
		curr := r1.Obligations[0].Controls[i].ControlID
		if prev >= curr {
			t.Errorf("controls not sorted: %s >= %s", prev, curr)
		}
	}
}

func TestResolveConflictStrictestWins(t *testing.T) {
	controls := []ControlLanguagePrimitive{
		{ControlID: "CLT-AC-001", Severity: "medium"},
		{ControlID: "CLT-AC-002", Severity: "critical"},
		{ControlID: "CLT-AC-003", Severity: "high"},
	}

	resolution := ResolveConflict(controls)

	if resolution.Resolution != "strictest_wins" {
		t.Errorf("expected strictest_wins, got %s", resolution.Resolution)
	}
	if len(resolution.ControlIDs) != 3 {
		t.Errorf("expected 3 control IDs, got %d", len(resolution.ControlIDs))
	}
}

func TestResolveConflictNoConflict(t *testing.T) {
	single := []ControlLanguagePrimitive{
		{ControlID: "CLT-AC-001", Severity: "high"},
	}

	resolution := ResolveConflict(single)

	if resolution.Resolution != "no_conflict" {
		t.Errorf("expected no_conflict, got %s", resolution.Resolution)
	}
}

func TestCompileEmptyJurisdictions(t *testing.T) {
	c := NewCompiler()
	result, err := c.Compile([]jkg.JurisdictionCode{})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if len(result.Obligations) != 0 {
		t.Errorf("expected 0 obligations, got %d", len(result.Obligations))
	}
}
