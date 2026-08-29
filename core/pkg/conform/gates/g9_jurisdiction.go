package gates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	helmconfig "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/config"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
)

// G9Jurisdiction validates jurisdiction compilation per §G9.
type G9Jurisdiction struct{}

func (g *G9Jurisdiction) ID() string   { return "G9" }
func (g *G9Jurisdiction) Name() string { return "Jurisdiction Compilation" }

func (g *G9Jurisdiction) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	jurisdictionsDir := filepath.Join(ctx.EvidenceDir, "04_EXPORTS", "jurisdictions")

	// 1. Check at least 2 jurisdiction packs
	if !dirExists(jurisdictionsDir) {
		result.Pass = false
		result.Reasons = append(result.Reasons, "JURISDICTION_PACKS_MISSING")
		return result
	}

	entries, _ := os.ReadDir(jurisdictionsDir)
	packDirs := 0
	for _, e := range entries {
		if e.IsDir() {
			packDirs++
			// Check each pack has required outputs
			packDir := filepath.Join(jurisdictionsDir, e.Name())
			requiredFiles := []string{"policy_bundle.json", "evidence_requirements.json", "retention_rules.json"}
			for _, reqFile := range requiredFiles {
				if !fileExists(filepath.Join(packDir, reqFile)) {
					result.Pass = false
					result.Reasons = append(result.Reasons, "JURISDICTION_PACK_INCOMPLETE:"+e.Name())
				}
			}
			// Check test suite
			suiteFiles, _ := filepath.Glob(filepath.Join(packDir, "test_suite", "*.json"))
			result.Metrics.Counts["jurisdiction_tests"] += len(suiteFiles)
		}
	}

	result.Metrics.Counts["jurisdiction_packs"] = packDirs
	if packDirs < 2 {
		result.Pass = false
		result.Reasons = append(result.Reasons, "JURISDICTION_PACKS_INSUFFICIENT")
	}

	// 2. Check jurisdiction-specific conformance reports
	for _, e := range entries {
		if e.IsDir() {
			reportPath := filepath.Join(jurisdictionsDir, e.Name(), "conformance_report.json")
			if fileExists(reportPath) {
				data, _ := os.ReadFile(reportPath)
				var report map[string]any
				if json.Unmarshal(data, &report) == nil {
					if pass, ok := report["pass"].(bool); ok && !pass {
						result.Pass = false
						result.Reasons = append(result.Reasons, "JURISDICTION_CONFORMANCE_FAILED:"+e.Name())
					}
				}
			}
		}
	}

	enforceRegionalPrivacyPrerequisites(ctx, result)
	result.EvidencePaths = append(result.EvidencePaths, "04_EXPORTS/jurisdictions/")
	return result
}

// enforceRegionalPrivacyPrerequisites checks declared source configuration
// only. Passing it does not prove provider terms, processing location, or a
// deployed GDPR control; those require separate external and runtime evidence.
func enforceRegionalPrivacyPrerequisites(ctx *conform.RunContext, result *conform.GateResult) {
	definition := conform.Profiles()[ctx.Profile]
	if definition == nil {
		return
	}
	strictErasure, _ := definition.Overrides["privacy_erasure_strict"].(bool)
	requireRetention, _ := definition.Overrides["retention_policy_required"].(bool)
	requireResidency, _ := definition.Overrides["tape_residency_enforced"].(bool)
	if !strictErasure && !requireRetention && !requireResidency {
		return
	}

	deny := func(reason string) {
		result.Pass = false
		result.Reasons = append(result.Reasons, reason)
	}
	jurisdiction := strings.ToLower(strings.TrimSpace(ctx.Jurisdiction))
	if jurisdiction == "" || strings.ContainsAny(jurisdiction, `/\\`) {
		if strictErasure {
			deny(conform.ReasonPrivacyErasureRequired)
		}
		if requireRetention {
			deny(conform.ReasonRetentionPolicyMissing)
		}
		if requireResidency {
			deny(conform.ReasonTapeResidencyViolation)
		}
		return
	}

	profile, err := helmconfig.LoadProfile(filepath.Join(ctx.ProjectRoot, "core", "pkg", "config", "profiles"), jurisdiction)
	if err != nil {
		if strictErasure {
			deny(conform.ReasonPrivacyErasureRequired)
		}
		if requireRetention {
			deny(conform.ReasonRetentionPolicyMissing)
		}
		if requireResidency {
			deny(conform.ReasonTapeResidencyViolation)
		}
		return
	}
	if strictErasure && (!profile.RightToErasure || !profile.Retention.RightToErasure) {
		deny(conform.ReasonPrivacyErasureRequired)
	}
	if requireRetention && (profile.Retention.MaxDays <= 0 || profile.Retention.PIIRetentionDays <= 0) {
		deny(conform.ReasonRetentionPolicyMissing)
	}
	if requireResidency && strings.TrimSpace(profile.DataResidency) == "" {
		deny(conform.ReasonTapeResidencyViolation)
	}
}
