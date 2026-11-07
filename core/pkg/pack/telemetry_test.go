package pack_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pack"
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
