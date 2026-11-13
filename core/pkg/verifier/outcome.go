package verifier

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// CheckStatus is the state one check ended in.
//
// A check that ran ends VERIFIED, FAILED or UNVERIFIABLE, the evidence
// verifier's vocabulary (AGENTS.md R2), so a check reads the same in
// `helm-ai-kernel verify` and on POST /api/v1/evidence/verify. NOT_RUN is the
// state of a check that had nothing to read.
type CheckStatus string

const (
	// CheckVerified means the check read its input and the property held.
	CheckVerified = CheckStatus(receiptverify.VerdictVerified)
	// CheckFailed means the check read its input and the property did not
	// hold, or that input the pack is required to carry is missing.
	CheckFailed = CheckStatus(receiptverify.VerdictFailed)
	// CheckUnverifiable means the material is intact, but no configured trust
	// root vouches for whoever signed it.
	CheckUnverifiable = CheckStatus(receiptverify.VerdictUnverifiable)
	// CheckNotRun means the pack carries nothing for the check to read and
	// nothing requires it to. It is never counted as passed.
	CheckNotRun CheckStatus = "NOT_RUN"
)

// CheckOutcome is one check as Conclude sees it.
type CheckOutcome struct {
	Name   string
	Status CheckStatus
}

// CheckCounts counts checks by the state they ended in.
type CheckCounts struct {
	Passed       int `json:"passed"`
	Failed       int `json:"failed"`
	Unverifiable int `json:"unverifiable"`
	NotRun       int `json:"not_run"`
}

// Ran is the number of checks that read input, whatever they found.
func (c CheckCounts) Ran() int {
	return c.Passed + c.Failed + c.Unverifiable
}

// Conclusion is the verdict over a set of checks.
type Conclusion struct {
	Outcome receiptverify.Verdict
	Counts  CheckCounts
	// RequiredNotRun names the required checks that did not run.
	RequiredNotRun []string
}

// Conclude derives the verdict from check outcomes. It is the single rule
// behind `helm-ai-kernel verify` and POST /api/v1/evidence/verify:
//
//   - any FAILED check fails the result, and so does a result in which no
//     check ran: an empty suite is never a pass;
//   - otherwise any UNVERIFIABLE check, or a required check that did not run,
//     leaves it UNVERIFIABLE;
//   - otherwise it is VERIFIED.
//
// A NOT_RUN check is counted on its own and never as passed. required names
// the checks a VERIFIED outcome cannot do without; a name with no outcome
// counts as not run. A status outside the four known ones is a failure, so a
// misspelled status can never read as a pass.
func Conclude(outcomes []CheckOutcome, required []string) Conclusion {
	var conclusion Conclusion
	ran := make(map[string]bool, len(outcomes))
	for _, outcome := range outcomes {
		switch outcome.Status {
		case CheckVerified:
			conclusion.Counts.Passed++
		case CheckUnverifiable:
			conclusion.Counts.Unverifiable++
		case CheckNotRun:
			conclusion.Counts.NotRun++
			continue
		default:
			conclusion.Counts.Failed++
		}
		ran[outcome.Name] = true
	}
	for _, name := range required {
		if !ran[name] {
			conclusion.RequiredNotRun = append(conclusion.RequiredNotRun, name)
		}
	}
	switch {
	case conclusion.Counts.Failed > 0 || conclusion.Counts.Ran() == 0:
		conclusion.Outcome = receiptverify.VerdictFailed
	case conclusion.Counts.Unverifiable > 0 || len(conclusion.RequiredNotRun) > 0:
		conclusion.Outcome = receiptverify.VerdictUnverifiable
	default:
		conclusion.Outcome = receiptverify.VerdictVerified
	}
	return conclusion
}

func verified(name, detail string) CheckResult {
	return CheckResult{Name: name, Pass: true, Status: CheckVerified, Detail: detail}
}

func failed(name, reason string) CheckResult {
	return CheckResult{Name: name, Status: CheckFailed, Reason: reason}
}

func notRun(name, reason string) CheckResult {
	return CheckResult{Name: name, Status: CheckNotRun, Reason: reason}
}

// normalized makes Status and Pass agree. A result built from Pass alone
// becomes VERIFIED or FAILED. A result whose Status and Pass disagree, or whose
// Status is not a known one, becomes FAILED or keeps its non-passing status:
// no malformed result reads as a pass.
func (c CheckResult) normalized() CheckResult {
	switch c.Status {
	case "":
		c.Status = CheckFailed
		if c.Pass {
			c.Status = CheckVerified
		}
	case CheckVerified:
		if !c.Pass {
			c.Status = CheckFailed
		}
	case CheckFailed, CheckUnverifiable, CheckNotRun:
	default:
		c.Status = CheckFailed
	}
	c.Pass = c.Status == CheckVerified
	return c
}
