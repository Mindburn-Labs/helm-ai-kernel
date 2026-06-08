package observability

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestCoverageProviderInProcessMetricBranches(t *testing.T) {
	ctx := context.Background()
	meterProvider := sdkmetric.NewMeterProvider()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = meterProvider.Shutdown(shutdownCtx)
	}()

	provider := &Provider{
		tracer: otel.Tracer("observability-coverage"),
		meter:  meterProvider.Meter("observability-coverage"),
		logger: slog.Default(),
	}
	if err := provider.initREDMetrics(); err != nil {
		t.Fatalf("initREDMetrics() error = %v", err)
	}

	attrs := []attribute.KeyValue{attribute.String("operation", "coverage")}
	provider.RecordRequest(ctx, attrs...)
	provider.RecordError(ctx, errors.New("coverage error"), attrs...)
	provider.RecordDuration(ctx, 25*time.Millisecond, attrs...)

	trackedCtx, finish := provider.TrackOperation(ctx, "coverage.operation", attrs...)
	if trackedCtx == nil {
		t.Fatal("TrackOperation returned nil context")
	}
	finish(errors.New("finished with error"))
}

func TestCoverageProviderAccessorsAndShutdownWithProviders(t *testing.T) {
	tracerProvider := sdktrace.NewTracerProvider()
	meterProvider := sdkmetric.NewMeterProvider()
	provider := &Provider{
		tracerProvider: tracerProvider,
		meterProvider:  meterProvider,
		tracer:         tracerProvider.Tracer("configured-tracer"),
		meter:          meterProvider.Meter("configured-meter"),
		logger:         slog.Default(),
	}

	if provider.Tracer() == nil {
		t.Fatal("configured tracer should be returned")
	}
	if provider.Meter() == nil {
		t.Fatal("configured meter should be returned")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := provider.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func TestCoverageInitExportProviders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res := resource.Empty()

	for _, tc := range []struct {
		name string
		rate float64
	}{
		{name: "always", rate: 1},
		{name: "never", rate: 0},
		{name: "ratio", rate: 0.25},
	} {
		t.Run("trace sampler "+tc.name, func(t *testing.T) {
			provider := &Provider{
				config: &Config{
					ServiceVersion: "coverage",
					OTLPEndpoint:   "localhost:4317",
					SampleRate:     tc.rate,
					BatchTimeout:   time.Millisecond,
					Insecure:       true,
				},
				logger: slog.Default(),
			}
			if err := provider.initTraceProvider(ctx, res); err != nil {
				t.Fatalf("initTraceProvider(%v) error = %v", tc.rate, err)
			}
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
			defer shutdownCancel()
			_ = provider.tracerProvider.Shutdown(shutdownCtx)
		})
	}

	t.Run("trace tls path logging", func(t *testing.T) {
		provider := &Provider{
			config: &Config{
				ServiceVersion: "coverage",
				OTLPEndpoint:   "localhost:4317",
				SampleRate:     1,
				BatchTimeout:   time.Millisecond,
				CertFile:       "client.pem",
				KeyFile:        "client-key.pem",
				CAFile:         "ca.pem",
			},
			logger: slog.Default(),
		}
		if err := provider.initTraceProvider(ctx, res); err != nil {
			t.Fatalf("initTraceProvider TLS path error = %v", err)
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = provider.tracerProvider.Shutdown(shutdownCtx)
	})

	t.Run("metric provider", func(t *testing.T) {
		provider := &Provider{
			config: &Config{
				OTLPEndpoint: "localhost:4317",
				Insecure:     true,
			},
			logger: slog.Default(),
		}
		if err := provider.initMetricProvider(ctx, res); err != nil {
			t.Fatalf("initMetricProvider() error = %v", err)
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = provider.meterProvider.Shutdown(shutdownCtx)
	})
}
