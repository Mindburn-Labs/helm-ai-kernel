package main

import (
	"fmt"
	"io"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

// maxNotRunLines bounds the not-run listing in text output. A pack with many
// host receipts reports several not-run checks per receipt; --json has them all.
const maxNotRunLines = 20

// printVerifyCheckCounts prints how many checks passed, failed and did not
// run, and names each check that did not run with its reason, so a VERIFIED
// headline cannot be read as covering checks that had nothing to read.
func printVerifyCheckCounts(stdout io.Writer, report *verifier.VerifyReport) {
	counts := report.CheckCounts
	line := fmt.Sprintf("checks: %d passed, %d failed, ", counts.Passed, counts.Failed)
	if counts.Unverifiable > 0 {
		line += fmt.Sprintf("%d unverifiable, ", counts.Unverifiable)
	}
	line += fmt.Sprintf("%d not run", counts.NotRun)
	if counts.NotRun > 0 && report.Verified {
		line += "; this result covers only the checks that ran"
	}
	writeText(stdout, "%s\n", line)
	printed := 0
	for _, c := range report.Checks {
		if c.Status != verifier.CheckNotRun {
			continue
		}
		if printed == maxNotRunLines {
			writeText(stdout, "  ... and %d more not run (use --json for all of them)\n", counts.NotRun-printed)
			break
		}
		writeText(stdout, "  not run: %s: %s\n", c.Name, c.Reason)
		printed++
	}
}

// printVerifyIssues lists the checks that ran and did not pass. A check name
// can carry a file name and a reason can quote the pack, so both are printed
// through writeText.
func printVerifyIssues(stdout io.Writer, report *verifier.VerifyReport) {
	for _, c := range report.Checks {
		if c.Status == verifier.CheckFailed || c.Status == verifier.CheckUnverifiable {
			writeText(stdout, "  - %s: %s\n", c.Name, c.Reason)
		}
	}
}

func printCompactVerifyReport(stdout io.Writer, report *verifier.VerifyReport) {
	anchor := "offline"
	if report.AnchorIndex != nil {
		anchor = fmt.Sprintf("#%d", *report.AnchorIndex)
	}
	sealed := report.SealedAt
	if sealed == "" {
		sealed = "unknown"
	}
	sealState := report.SealState
	if sealState == "" {
		sealState = "unknown"
	}
	trust := report.TrustLevel
	if trust == "" {
		trust = string(evidencepkg.EvidenceTrustProfileDevLocal)
	}
	anchorStatus := report.AnchorStatus
	if anchorStatus == "" {
		anchorStatus = anchor
	} else if anchor != "offline" && anchorStatus != anchor {
		anchorStatus = anchor + " (" + anchorStatus + ")"
	}
	storageStatus := report.StorageStatus
	if storageStatus == "" {
		storageStatus = "unknown"
	}
	writeText(stdout, "envelope %s · seal %s · sig %d/%d · trust %s\n", displayEnvelopeID(report), sealState, report.SignatureValidCount, report.SignatureTotalCount, trust)
	writeText(stdout, "VERIFIED · sealed %s · anchor %s · storage %s\n", sealed, anchorStatus, storageStatus)
}

func displayEnvelopeID(report *verifier.VerifyReport) string {
	if report.EnvelopeID != "" {
		return report.EnvelopeID
	}
	return "unknown"
}
