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
