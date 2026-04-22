package pack

import (
	"context"
	"time"
)

// PackMetrics captures the runtime telemetry for a specific pack.
// Quantify reliability and trust (install base, failure rate, evidence success).
type PackMetrics struct {
	PackID              string    `json:"pack_id"`
	Version             string    `json:"version"`
	InstallCount        int64     `json:"install_count"`         // Global install base (registry context)
	ActiveInstances     int64     `json:"active_instances"`      // Number of active instances running this pack
	FailureRate         float64   `json:"failure_rate"`          // % of executions resulting in error (last 30d)
	EvidenceSuccessRate float64   `json:"evidence_success_rate"` // % of successful evidence generation (last 30d)
	IncidentRate        float64   `json:"incident_rate"`         // Incidents per 1k executions (last 30d)
	MeanTimeToRecovery  float64   `json:"mttr_seconds"`          // Ave time to resolve incidents (last 30d)
	TrustScore          float64   `json:"trust_score"`           // 0.0 to 1.0, calculated from SLO compliance
	ConfidenceScore     float64   `json:"confidence_score"`      // 0.0 to 1.0, based on sample size (InstallCount)
	LastUpdated         time.Time `json:"last_updated"`
}

// CalculateTrustScore computes a normalized trust score (0.0-1.0) based on metrics and SLOs.
// Quantify trust so users rely on the aggregated data (switching cost).
func CalculateTrustScore(metrics PackMetrics, slos *ServiceLevelObjectives) float64 {
	if slos == nil {
		return 0.5 // Default neutral score if no SLOs defined
	}

	score := 1.0

	// 1. Failure Rate Penalty
	if slos.MaxFailureRate > 0 && metrics.FailureRate > slos.MaxFailureRate {
		// Penalty proportional to violation
		violation := (metrics.FailureRate - slos.MaxFailureRate) / slos.MaxFailureRate
		if violation > 1 {
			violation = 1
		}
		score -= 0.5 * violation
	}

	// 2. Evidence Success Bonus/Penalty
	if slos.MinEvidenceRate > 0 {
		if metrics.EvidenceSuccessRate < slos.MinEvidenceRate {
			violation := (slos.MinEvidenceRate - metrics.EvidenceSuccessRate) / slos.MinEvidenceRate
			if violation > 1 {
				violation = 1
			}
			score -= 0.3 * violation
		}
	}

	// 3. Incident Rate Penalty (High Impact)
	if slos.MaxIncidentRate > 0 && metrics.IncidentRate > slos.MaxIncidentRate {
		violation := (metrics.IncidentRate - slos.MaxIncidentRate) / slos.MaxIncidentRate
		if violation > 1 {
			violation = 1
		}
		score -= 0.5 * violation
	}

	if score < 0 {
		score = 0
	}
	return score
}

// CalculateConfidenceScore returns a score based on the statistical significance of the data.
func CalculateConfidenceScore(installCount int64) float64 {
	// Simple logarithmic scale or threshold
	// 1 install -> low confidence
	// 100 installs -> medium
	// 1000+ -> high
	if installCount >= 1000 {
		return 1.0
	}
	return float64(installCount) / 1000.0
}

// TelemetryHook defines the interface for reporting pack telemetry.
type TelemetryHook interface {
	// RecordExecution records a single execution of a pack capability.
	RecordExecution(ctx context.Context, packID, version string, success bool, duration time.Duration)

	// RecordEvidenceGeneration records the outcome of an evidence generation attempt.
	RecordEvidenceGeneration(ctx context.Context, packID, version string, evidenceClass string, success bool)

	// RecordIncident records a security or reliability incident attributed to a pack.
	RecordIncident(ctx context.Context, packID, version string, severity string)

	// GetMetrics retrieves the aggregated metrics for a pack.
	GetMetrics(ctx context.Context, packID, version string) (*PackMetrics, error)
}
