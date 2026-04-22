package forge

import (
	"fmt"
	"time"
)

// CanaryEvidence holds the aggregated metrics collected during a canary rollout
// for a skill candidate.  Evidence is append-only — each call to
// CollectEvidence produces a fresh snapshot; mutation of existing evidence
// must be avoided.
type CanaryEvidence struct {
	CandidateID    string          `json:"candidate_id"`
	RolloutPct     int             `json:"rollout_pct"`       // 0-100 inclusive
	Observations   int             `json:"observations"`
	ErrorCount     int             `json:"error_count"`
	LatencyP50Ms   int64           `json:"latency_p50_ms"`
	LatencyP99Ms   int64           `json:"latency_p99_ms"`
	VerdictHistory []CanaryVerdict `json:"verdict_history"`
	CollectedAt    time.Time       `json:"collected_at"`
}

// CanaryVerdict records the pass/warn/fail decision at a single canary phase.
type CanaryVerdict struct {
	Timestamp time.Time `json:"timestamp"`
	Phase     string    `json:"phase"`   // ramp_5, ramp_25, ramp_50, ramp_100
	Verdict   string    `json:"verdict"` // pass, warn, fail
	Reason    string    `json:"reason,omitempty"`
}

// Escalation thresholds — all values are fail-closed.
const (
	// EscalateErrorRatePct is the maximum tolerable error rate (5 %).
	EscalateErrorRatePct = 5.0
	// EscalateP99Ms is the maximum tolerable p99 latency in milliseconds (200 ms).
	EscalateP99Ms = 200
)

// CollectEvidence constructs a CanaryEvidence snapshot from raw metrics.
// rolloutPct must be in [0, 100]; observations must be ≥ 0.
// A verdict for the current phase is appended automatically.
func CollectEvidence(
	candidateID string,
	rolloutPct int,
	observations int,
	errors int,
	p50 int64,
	p99 int64,
) *CanaryEvidence {
	phase := rolloutPhase(rolloutPct)

	verdict, reason := verdictFor(observations, errors, p99)
	now := time.Now()

	return &CanaryEvidence{
		CandidateID:  candidateID,
		RolloutPct:   rolloutPct,
		Observations: observations,
		ErrorCount:   errors,
		LatencyP50Ms: p50,
		LatencyP99Ms: p99,
		VerdictHistory: []CanaryVerdict{
			{
				Timestamp: now,
				Phase:     phase,
				Verdict:   verdict,
				Reason:    reason,
			},
		},
		CollectedAt: now,
	}
}

// ShouldEscalate returns (true, reason) when the canary evidence warrants an
// immediate rollback.  Escalation is triggered when any of the following holds:
//
//   - Error rate > 5 % (ErrorCount / Observations × 100 > 5)
//   - p99 latency > 200 ms
//   - Any verdict in VerdictHistory is "fail"
//
// Returns (false, "") when the canary is healthy.
func ShouldEscalate(evidence *CanaryEvidence) (bool, string) {
	if evidence == nil {
		return true, "forge: nil canary evidence — fail-closed"
	}

	// Check for explicit "fail" verdict.
	for _, v := range evidence.VerdictHistory {
		if v.Verdict == "fail" {
			return true, fmt.Sprintf("forge: canary phase %s verdict=fail: %s", v.Phase, v.Reason)
		}
	}

	// Check p99 latency.
	if evidence.LatencyP99Ms > EscalateP99Ms {
		return true, fmt.Sprintf(
			"forge: p99 latency %d ms exceeds threshold %d ms",
			evidence.LatencyP99Ms,
			EscalateP99Ms,
		)
	}

	// Check error rate — guard against division by zero.
	if evidence.Observations > 0 {
		errorRate := float64(evidence.ErrorCount) / float64(evidence.Observations) * 100.0
		if errorRate > EscalateErrorRatePct {
			return true, fmt.Sprintf(
				"forge: error rate %.2f%% exceeds threshold %.0f%%",
				errorRate,
				EscalateErrorRatePct,
			)
		}
	}

	return false, ""
}

// rolloutPhase maps a rollout percentage to the canonical phase label.
func rolloutPhase(pct int) string {
	switch {
	case pct <= 5:
		return "ramp_5"
	case pct <= 25:
		return "ramp_25"
	case pct <= 50:
		return "ramp_50"
	default:
		return "ramp_100"
	}
}

// verdictFor computes the pass/warn/fail verdict for a set of raw metrics.
func verdictFor(observations, errors int, p99Ms int64) (verdict string, reason string) {
	// p99 latency breach — fail immediately.
	if p99Ms > EscalateP99Ms {
		return "fail", fmt.Sprintf("p99 %d ms > %d ms threshold", p99Ms, EscalateP99Ms)
	}

	// Error rate — fail if above threshold.
	if observations > 0 {
		rate := float64(errors) / float64(observations) * 100.0
		if rate > EscalateErrorRatePct {
			return "fail", fmt.Sprintf("error rate %.2f%% > %.0f%% threshold", rate, EscalateErrorRatePct)
		}
		// Warn if within 2× of the threshold.
		if rate > EscalateErrorRatePct/2 {
			return "warn", fmt.Sprintf("error rate %.2f%% approaching threshold", rate)
		}
	}

	return "pass", ""
}
