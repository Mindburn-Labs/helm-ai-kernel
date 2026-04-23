package adversarial

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RunAll executes all 10 mandatory adversarial suites against an EvidencePack.
// Returns an aggregate result. Any single suite failure means overall failure.
func RunAll(evidenceDir string) *AggregateResult {
	suites := AllSuites()
	aggregate := &AggregateResult{
		EvidenceDir: evidenceDir,
		Pass:        true,
		Suites:      make([]*SuiteResult, 0, len(suites)),
	}

	for _, suite := range suites {
		result := suite.Run(evidenceDir)
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
