package pack

import (
	"context"
	"time"
)

// PackGrader assigns maturity grades to packs.
type PackGrader struct {
	// dependencies (e.g. EvidenceStore) would go here
}

// NewPackGrader creates a new grader.
func NewPackGrader() *PackGrader {
	return &PackGrader{}
}

// Grade determines the PackGrade based on evidence.
// This is a compact implementation for the retained OSS baseline.
func (g *PackGrader) Grade(ctx context.Context, pack *Pack) (*GradingReport, error) {
	report := &GradingReport{
		PackID:   pack.PackID,
		ScoredAt: time.Now().UTC(),
		Evidence: []string{},
		Missing:  []string{},
	}

	// 1. Bronze Requirement: Valid Signature
	if pack.Signature != "" {
		report.Evidence = append(report.Evidence, "signature_present")
		report.Grade = GradeBronze
	} else {
		report.Missing = append(report.Missing, "signature_missing")
		// Fallback or error? For now, no grade if not bronze.
		return report, nil
	}

	// 2. Silver requirement: declared automated test evidence.
	if _, ok := pack.Metadata["tested"]; ok {
		report.Evidence = append(report.Evidence, "tests_passed")
		report.Grade = GradeSilver
	} else {
		report.Missing = append(report.Missing, "tests_missing")
		return report, nil
	}

	// 3. Gold requirement: declared production drill evidence.
	if _, ok := pack.Metadata["drilled"]; ok {
		report.Evidence = append(report.Evidence, "drills_passed")
		report.Grade = GradeGold
	} else {
		report.Missing = append(report.Missing, "drills_missing")
	}

	return report, nil
}
