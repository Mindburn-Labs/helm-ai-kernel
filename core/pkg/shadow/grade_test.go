package shadow

import "testing"

func TestComputeGrade(t *testing.T) {
	cases := []struct {
		name       string
		report     Report
		wantLetter string
	}{
		{
			name:       "boundary present, clean",
			report:     Report{HelmCoverage: HelmCoverage{Present: true}},
			wantLetter: "A",
		},
		{
			name: "boundary present, medium signals",
			report: Report{
				HelmCoverage: HelmCoverage{Present: true},
				Findings: []Finding{
					{Kind: "sdk_import", Vendor: "openai", Severity: "MEDIUM"},
				},
			},
			wantLetter: "B",
		},
		{
			name: "boundary present, high exposure",
			report: Report{
				HelmCoverage: HelmCoverage{Present: true},
				Findings: []Finding{
					{Kind: "api_key", Vendor: "openai", Severity: "HIGH"},
				},
			},
			wantLetter: "C",
		},
		{
			name:       "no boundary, no agent surface",
			report:     Report{},
			wantLetter: "A",
		},
		{
			name: "no boundary, agent surface without high",
			report: Report{
				Findings: []Finding{
					{Kind: "sdk_import", Vendor: "anthropic", Severity: "MEDIUM"},
					{Kind: "mcp_config", Vendor: "mcp", Severity: "MEDIUM"},
				},
			},
			wantLetter: "D",
		},
		{
			name: "no boundary, high exposure",
			report: Report{
				Findings: []Finding{
					{Kind: "sdk_import", Vendor: "openai", Severity: "MEDIUM"},
					{Kind: "api_key", Vendor: "openai", Severity: "HIGH"},
				},
			},
			wantLetter: "F",
		},
		{
			name: "helm sdk import does not count as agent signal",
			report: Report{
				HelmCoverage: HelmCoverage{Present: true},
				Findings: []Finding{
					{Kind: "sdk_import", Vendor: "helm", Severity: "INFO"},
				},
			},
			wantLetter: "A",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := ComputeGrade(&tc.report)
			if g.Letter != tc.wantLetter {
				t.Fatalf("Letter = %q, want %q (reason: %s)", g.Letter, tc.wantLetter, g.Reason)
			}
			if g.Reason == "" {
				t.Fatal("Reason must not be empty")
			}
		})
	}
}

func TestComputeGradeCounts(t *testing.T) {
	r := Report{
		Findings: []Finding{
			{Kind: "sdk_import", Vendor: "openai", Severity: "MEDIUM"},
			{Kind: "helm_absent", Vendor: "anthropic", Severity: "MEDIUM"},
			{Kind: "sdk_import", Vendor: "helm", Severity: "INFO"},
			{Kind: "mcp_config", Vendor: "mcp", Severity: "MEDIUM"},
			{Kind: "api_key", Vendor: "openai", Severity: "HIGH"},
		},
	}
	g := ComputeGrade(&r)
	if g.SDKSignals != 2 {
		t.Errorf("SDKSignals = %d, want 2", g.SDKSignals)
	}
	if g.MCPServersDetected != 1 {
		t.Errorf("MCPServersDetected = %d, want 1", g.MCPServersDetected)
	}
	if g.APIKeyExposures != 1 {
		t.Errorf("APIKeyExposures = %d, want 1", g.APIKeyExposures)
	}
	if g.UngovernedFindings != 4 {
		t.Errorf("UngovernedFindings = %d, want 4", g.UngovernedFindings)
	}
	if g.BoundaryPresent {
		t.Error("BoundaryPresent = true, want false")
	}
}
