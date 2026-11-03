package budget

import ()

func testBudget() *RiskBudget {
	return &RiskBudget{
		TenantID:         "tenant-1",
		ComputeCapMillis: 60000,
		BlastRadiusCap:   100,
		RiskScoreCap:     500.0,
		AutonomyLevel:    80,
		UncertaintyScore: 0.2,
	}
}
