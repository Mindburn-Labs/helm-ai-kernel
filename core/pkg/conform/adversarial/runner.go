package adversarial

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	CampaignPublicKeyEnv = "HELM_BOUNTY_CAMPAIGN_PUBLIC_KEY_HEX"
	CampaignIDEnv        = "HELM_BOUNTY_CAMPAIGN_ID"
	CampaignRunIDEnv     = "HELM_BOUNTY_RUN_ID"
)

// RunAll executes all 10 mandatory adversarial suites against an EvidencePack.
// It preserves the original single-argument API and reads the campaign trust
// root only from the operator-controlled environment. Signature-dependent
// suites fail closed when the variable is absent or invalid; explicit callers
// should use RunAllWithOptions.
func RunAll(evidenceDir string) *AggregateResult {
	return RunAllWithOptions(evidenceDir, VerificationOptions{
		CampaignPublicKeyHex: os.Getenv(CampaignPublicKeyEnv),
		CampaignID:           os.Getenv(CampaignIDEnv),
		RunID:                os.Getenv(CampaignRunIDEnv),
	})
}

// RunAllWithOptions executes every suite against an external campaign trust
// root. Evidence stored inside the candidate pack never establishes trust.
func RunAllWithOptions(evidenceDir string, opts VerificationOptions) *AggregateResult {
	suites := AllSuitesWithOptions(opts)
	workspace, cleanup, workspaceErr := newCoverageMutationWorkspace(evidenceDir)
	defer cleanup()
	coverage := unavailableCoverageResult(opts)
	baselineResults := make(map[string]*SuiteResult, len(suites))
	if workspaceErr == nil {
		coverage, baselineResults = evaluateCoverageInWorkspace(workspace, opts)
	}
	coverageBySuite := make(map[string]CoverageCheck, len(coverage.Checks))
	for _, check := range coverage.Checks {
		coverageBySuite[check.SuiteID] = check
	}
	aggregate := &AggregateResult{
		EvidenceDir: evidenceDir,
		Pass:        true,
		Suites:      make([]*SuiteResult, 0, len(suites)),
	}

	for _, suite := range suites {
		result := baselineResults[suite.ID]
		if result == nil {
			result = &SuiteResult{SuiteID: suite.ID, Name: suite.Name, Pass: true}
		}
		check, covered := coverageBySuite[suite.ID]
		if !covered {
			check = CoverageCheck{SuiteID: suite.ID, Reason: "missing: mandatory coverage check is not registered"}
		}
		if !check.Covered && result.Pass {
			result.Pass = false
			result.TestResults = append(result.TestResults, TestResult{
				TestID: suite.ID + "-COVERAGE",
				Name:   "Positive-control and mutation coverage",
				Pass:   false,
				Reason: check.Reason,
			})
		}
		aggregate.Suites = append(aggregate.Suites, result)
		if !result.Pass {
			aggregate.Pass = false
			aggregate.FailedSuites++
		} else {
			aggregate.PassedSuites++
		}
	}

	return aggregate
}

// AggregateResult is the overall result of all adversarial suites.
type AggregateResult struct {
	EvidenceDir  string         `json:"evidence_dir"`
	Pass         bool           `json:"pass"`
	PassedSuites int            `json:"passed_suites"`
	FailedSuites int            `json:"failed_suites"`
	Suites       []*SuiteResult `json:"suites"`
}

// WriteReport writes the adversarial test results to the EvidencePack.
func WriteReport(evidenceDir string, result *AggregateResult) error {
	reportDir := filepath.Join(evidenceDir, "12_REPORTS")
	if err := os.MkdirAll(reportDir, 0750); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	return os.WriteFile(filepath.Join(reportDir, "adversarial_report.json"), data, 0600)
}
