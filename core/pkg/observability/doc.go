// Package observability provides OpenTelemetry tracing and Prometheus metrics
// for HELM services. It implements production-ready observability following
// cloud-native best practices.
//
// # Tracing
//
// Initialize tracing at application startup:
//
//	tp, err := observability.InitTracer(ctx, observability.TracerConfig{
//		ServiceName:  "helm-core",
//		OTLPEndpoint: "otel-collector:4317",
//		SampleRate:   0.1, // 10% sampling in production
//	})
//	defer tp.Shutdown(ctx)
//
// Use the HTTP middleware to trace requests:
//
//	http.Handle("/", tp.HTTPMiddleware(yourHandler))
//
// Create spans manually:
//
//	ctx, span := tp.StartSpan(ctx, "operation_name")
//	defer span.End()
//
// # Metrics
//
// Initialize metrics at application startup:
//
//	metrics := observability.NewMetrics("helm")
//	metrics.StartMetricsUpdater(ctx, 15*time.Second)
//
// Expose the /metrics endpoint:
//
//	http.Handle("/metrics", metrics.Handler())
//
// Use the HTTP middleware to record request metrics:
//
//	http.Handle("/", metrics.HTTPMiddleware(yourHandler))
//
// Record business metrics:
//
//	metrics.RecordArtifactStored("s3", true)
//	metrics.RecordDecision("PASS")
//	metrics.RecordEffectExecution("file_write", "success")
package observability
