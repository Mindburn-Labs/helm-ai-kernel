package policybundles

import "fmt"

// RetentionBundle returns a pre-defined bundle enforcing 90-day retention with auto-archive.
func RetentionBundle() *PolicyBundle {
	return &PolicyBundle{
		BundleID:     "builtin-retention-90d",
		Name:         "90-Day Retention",
		Description:  "Enforce 90-day data retention with automatic archival.",
		Jurisdiction: "global",
		Category:     "retention",
		Version:      1,
		Status:       BundleStatusActive,
		Rules: []PolicyRule{
			{
				RuleID:      "ret-001",
				Name:        "Auto-archive after 90 days",
				Description: "Evidence packs older than 90 days are archived to cold storage.",
				Condition:   "resource.age_days > 90",
				Action:      "log",
				Priority:    100,
				Parameters: map[string]string{
					"retention_days": "90",
					"archive_tier":   "cold",
				},
			},
			{
				RuleID:      "ret-002",
				Name:        "Block deletion within retention window",
				Description: "Prevent deletion of evidence within the retention period.",
				Condition:   "request.action == 'DELETE' && resource.age_days <= 90",
				Action:      "deny",
				Priority:    200,
			},
		},
	}
}

// ApprovalBundle returns a pre-defined bundle enforcing approval workflows.
func ApprovalBundle() *PolicyBundle {
	return &PolicyBundle{
		BundleID:     "builtin-approval-tiered",
		Name:         "Tiered Approval",
		Description:  "Risk-tiered approval requirements: R2+ requires approval, R3 requires dual control.",
		Jurisdiction: "global",
		Category:     "approval",
		Version:      1,
		Status:       BundleStatusActive,
		Rules: []PolicyRule{
			{
				RuleID:      "appr-001",
				Name:        "R2 requires single approval",
				Description: "Risk class R2 actions require at least one approval.",
				Condition:   "intent.risk_class == 'R2'",
				Action:      "require_approval",
				Priority:    100,
				Parameters: map[string]string{
					"min_approvers": "1",
				},
			},
			{
				RuleID:      "appr-002",
				Name:        "R3 requires dual control",
				Description: "Risk class R3 actions require dual-control approval.",
				Condition:   "intent.risk_class == 'R3'",
				Action:      "require_approval",
				Priority:    200,
				Parameters: map[string]string{
					"min_approvers": "2",
					"dual_control":  "true",
				},
			},
		},
	}
}

// DataResidencyBundle returns a pre-defined bundle enforcing region-locked data processing.
func DataResidencyBundle(region string) *PolicyBundle {
	return &PolicyBundle{
		BundleID:     fmt.Sprintf("builtin-residency-%s", region),
		Name:         fmt.Sprintf("Data Residency (%s)", region),
		Description:  fmt.Sprintf("Enforce data processing within the %s region.", region),
		Jurisdiction: region,
		Category:     "data_residency",
		Version:      1,
		Status:       BundleStatusActive,
		Rules: []PolicyRule{
			{
				RuleID:      fmt.Sprintf("res-%s-001", region),
				Name:        fmt.Sprintf("Block cross-region transfer out of %s", region),
				Description: fmt.Sprintf("Deny any data transfer to regions outside %s.", region),
				Condition:   fmt.Sprintf("effect.target_region != '%s'", region),
				Action:      "deny",
				Priority:    300,
				Parameters: map[string]string{
					"allowed_region": region,
				},
			},
			{
				RuleID:      fmt.Sprintf("res-%s-002", region),
				Name:        "Log all cross-border access",
				Description: "Log access from principals located outside the allowed region.",
				Condition:   fmt.Sprintf("principal.region != '%s'", region),
				Action:      "log",
				Priority:    100,
			},
		},
	}
}
