package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func testCapabilitySpan(t *testing.T) trace.Span {
	t.Helper()
	_, span := noop.NewTracerProvider().Tracer("capability-test").Start(context.Background(), "gate")
	t.Cleanup(func() { span.End() })
	return span
}

func TestCapabilityRegistryReasonCodesAreCanonical(t *testing.T) {
	for _, code := range []string{"CAPABILITY_UNKNOWN", "CAPABILITY_MANIFEST_DRIFT"} {
		assert.True(t, contracts.IsCanonicalReasonCode(code), "%s must be registered canonical", code)
	}
}
