package main

import (
	"context"

	helmmetrics "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/metrics"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
)

// verificationMetrics is the process-wide collector for the north-star
// adoption metric: EvidencePack verifications run against this binary, whether
// over the HTTP verify endpoint or the `verify` CLI command.
var verificationMetrics = helmmetrics.NewGovernanceMetrics()

// verificationTracer emits verifier spans. A NoopTracer is the safe default
// when no OTLP endpoint is configured; spans are still constructed so the code
// path is exercised identically with or without an exporter.
var verificationTracer = helmotel.NoopTracer()

// recordVerification reports one EvidencePack verification run to both the
// Prometheus-compatible counter and the OTel verifier span.
func recordVerification(ctx context.Context, event helmotel.VerificationEvent) {
	verificationMetrics.RecordVerification()
	verificationTracer.TraceVerification(ctx, event)
}
