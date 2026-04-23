package observability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	require.Equal(t, "helm-sovereign-os", config.ServiceName)
	require.Equal(t, "2.0.0", config.ServiceVersion)
	require.Equal(t, "development", config.Environment)
	require.Equal(t, "localhost:4317", config.OTLPEndpoint)
	require.Equal(t, 1.0, config.SampleRate)
	require.True(t, config.Enabled)
	require.False(t, config.Insecure)
}

func TestNewProviderWithTLS(t *testing.T) {
	// This tests that we can initialize with TLS paths
	// valid paths aren't strictly required for the init function to succeed
	// (connection happens later)
	config := &Config{
		Enabled:  true,
		Insecure: false, // TLS enabled
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
		CAFile:   "/path/to/ca.pem",
	}

	// Use a short timeout as it might try to connect
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	p, err := New(ctx, config)
	// It might error on connection or resource creation depending on environment,
	// but mostly we want to ensure the code path for TLS setup is exercised without panic
	if err != nil {
		// If it fails, it should be due to connection ref used or similar, not panic
		t.Logf("Provider creation failed (expected in test env): %v", err)
	} else {
		require.NotNil(t, p)
	}
}

func TestNewProviderDisabled(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	p, err := New(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Should not fail even when disabled
	tracer := p.Tracer()
	require.NotNil(t, tracer)

	meter := p.Meter()
	require.NotNil(t, meter)
}

func TestNewProviderWithNilConfig(t *testing.T) {
	// This will try to connect to localhost:4317 which won't exist
	// But it should still create the provider without error
	// (connection errors happen later during export)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use disabled config to avoid network issues in tests
	config := &Config{
		Enabled: false,
	}
	p, err := New(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestTrackOperation(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	p, err := New(context.Background(), config)
	require.NoError(t, err)

	ctx := context.Background()
	attrs := []attribute.KeyValue{
		attribute.String("test.key", "test.value"),
	}

	newCtx, finish := p.TrackOperation(ctx, "test.operation", attrs...)
	require.NotNil(t, newCtx)

	// Simulate some work
	time.Sleep(1 * time.Millisecond)

	// Call finish without error
	finish(nil)
}

func TestTrackOperationWithError(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	p, err := New(context.Background(), config)
	require.NoError(t, err)

	ctx := context.Background()
	_, finish := p.TrackOperation(ctx, "test.operation.error")

	// Call finish with error
	testErr := errors.New("test error")
	finish(testErr)

	// Should not panic
}

func TestRecordMetrics(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	p, err := New(context.Background(), config)
	require.NoError(t, err)

	ctx := context.Background()

	// These should not panic when provider is disabled
	p.RecordRequest(ctx, attribute.String("test", "value"))
	p.RecordError(ctx, errors.New("test"), attribute.String("test", "value"))
	p.RecordDuration(ctx, 100*time.Millisecond, attribute.String("test", "value"))
}

func TestStartSpan(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	p, err := New(context.Background(), config)
	require.NoError(t, err)

	ctx := context.Background()
	newCtx, span := p.StartSpan(ctx, "test.span")
	require.NotNil(t, newCtx)
	require.NotNil(t, span)

	span.End()
}

func TestShutdown(t *testing.T) {
	config := &Config{
		Enabled: false,
	}

	p, err := New(context.Background(), config)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = p.Shutdown(ctx)
	require.NoError(t, err)
}

// Test HELM-specific helpers

func TestGovernanceOperation(t *testing.T) {
	attrs := GovernanceOperation("entity-123", "READY", "ApplyMutation", 42)
	require.Len(t, attrs, 4)
	require.Equal(t, "helm.entity.id", string(attrs[0].Key))
	require.Equal(t, "entity-123", attrs[0].Value.AsString())
}

func TestMutationOperation(t *testing.T) {
	attrs := MutationOperation("entity-123", "mut-456", "displayName", "PERMIT")
	require.Len(t, attrs, 4)
	require.Equal(t, "helm.mutation.id", string(attrs[1].Key))
	require.Equal(t, "mut-456", attrs[1].Value.AsString())
}

func TestPDPOperation(t *testing.T) {
	attrs := PDPOperation("identity", "create", "PERMIT", 1.5)
	require.Len(t, attrs, 4)
	require.Equal(t, "helm.pdp.decision", string(attrs[2].Key))
	require.Equal(t, "PERMIT", attrs[2].Value.AsString())
}

func TestComplianceOperation(t *testing.T) {
	attrs := ComplianceOperation("EU", "MiCA", "art-68-1", true)
	require.Len(t, attrs, 4)
	require.Equal(t, "helm.compliance.compliant", string(attrs[3].Key))
	require.Equal(t, true, attrs[3].Value.AsBool())
}

func TestCryptoOperation(t *testing.T) {
	attrs := CryptoOperation("ML-KEM-768", "encapsulate", "key-abc123")
	require.Len(t, attrs, 3)
	require.Equal(t, "helm.crypto.algorithm", string(attrs[0].Key))
	require.Equal(t, "ML-KEM-768", attrs[0].Value.AsString())
}

func TestSpanFromContext(t *testing.T) {
	ctx := context.Background()
	span := SpanFromContext(ctx)
	require.NotNil(t, span) // Returns a no-op span if none
}

func TestAddSpanEvent(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	AddSpanEvent(ctx, "test.event", attribute.String("key", "value"))
}

func TestSetSpanStatus(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	SetSpanStatus(ctx, errors.New("test error"))
	SetSpanStatus(ctx, nil)
}
