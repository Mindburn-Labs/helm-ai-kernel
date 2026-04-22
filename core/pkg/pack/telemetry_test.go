package pack_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/pack"
)

type MockTelemetryHook struct {
	Metrics pack.PackMetrics
}

func (m *MockTelemetryHook) RecordExecution(ctx context.Context, packID, version string, success bool, duration time.Duration) {
	if success {
		m.Metrics.InstallCount++ // Just a dummy counter for test
	} else {
		m.Metrics.FailureRate += 1.0
	}
}

func (m *MockTelemetryHook) RecordEvidenceGeneration(ctx context.Context, packID, version string, evidenceClass string, success bool) {
	if success {
		m.Metrics.EvidenceSuccessRate += 1.0
	}
}

func (m *MockTelemetryHook) RecordIncident(ctx context.Context, packID, version string, severity string) {
	m.Metrics.IncidentRate += 1.0
}

func (m *MockTelemetryHook) GetMetrics(ctx context.Context, packID, version string) (*pack.PackMetrics, error) {
	return &m.Metrics, nil
}

func TestPackTelemetry_MockHook(t *testing.T) {
	hook := &MockTelemetryHook{
		Metrics: pack.PackMetrics{
			PackID: "test-pack",
		},
	}

	ctx := context.Background()
	hook.RecordExecution(ctx, "test-pack", "1.0.0", true, 100*time.Millisecond)
	hook.RecordExecution(ctx, "test-pack", "1.0.0", false, 50*time.Millisecond)
	hook.RecordEvidenceGeneration(ctx, "test-pack", "1.0.0", "SOC2", true)
	hook.RecordIncident(ctx, "test-pack", "1.0.0", "CRITICAL")

	metrics, _ := hook.GetMetrics(ctx, "test-pack", "1.0.0")

	if metrics.InstallCount != 1 {
		t.Errorf("Expected 1 successful execution count (mocked as install count), got %d", metrics.InstallCount)
	}
	if metrics.FailureRate != 1.0 {
		t.Errorf("Expected failure rate 1.0 (mocked), got %f", metrics.FailureRate)
	}
	if metrics.EvidenceSuccessRate != 1.0 {
		t.Errorf("Expected evidence success 1.0 (mocked), got %f", metrics.EvidenceSuccessRate)
	}
	if metrics.IncidentRate != 1.0 {
		t.Errorf("Expected incident rate 1.0 (mocked), got %f", metrics.IncidentRate)
	}
}

func TestCalculateTrustScore(t *testing.T) {
	slos := &pack.ServiceLevelObjectives{
		MaxFailureRate:  0.01, // 1%
		MinEvidenceRate: 0.99, // 99%
		MaxIncidentRate: 0.0,  // Zero tolerance
	}

	tests := []struct {
		name          string
		metrics       pack.PackMetrics
		expectedScore float64 // Approximately
	}{
		{
			name: "Perfect Score",
			metrics: pack.PackMetrics{
				FailureRate:         0.0,
				EvidenceSuccessRate: 1.0,
				IncidentRate:        0.0,
			},
			expectedScore: 1.0,
		},
		{
			name: "Failure Rate Violation",
			metrics: pack.PackMetrics{
				FailureRate:         0.02, // 2x max (100% overage -> cap at 100% -> 0.5 deduction)
				EvidenceSuccessRate: 1.0,
				IncidentRate:        0.0,
			},
			expectedScore: 0.5,
		},
		{
			name: "Multiple Violations",
			metrics: pack.PackMetrics{
				FailureRate:         0.02, // -0.5
				EvidenceSuccessRate: 0.90, // ~10% under 99% -> ~0.09 gap -> 9% of 99% is ~9.09% violation -> 0.3 * 0.09 = 0.027 penalty? No wait logic is (Target - Actual)/Target. (0.99 - 0.90)/0.99 = 0.09. 0.3 * 0.09 = 0.027.
				IncidentRate:        0.0,
			},
			expectedScore: 0.47, // 1.0 - 0.5 - 0.027 = 0.473
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := pack.CalculateTrustScore(tt.metrics, slos)
			diff := score - tt.expectedScore
			if diff < -0.05 || diff > 0.05 {
				t.Errorf("Expected score ~%f, got %f", tt.expectedScore, score)
			}
		})
	}
}
