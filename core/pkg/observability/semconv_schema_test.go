package observability

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

func TestSemconvResourceSchemaMatchesDefaultResource(t *testing.T) {
	_, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("helm-ai-kernel"),
			semconv.DeploymentEnvironmentName("test"),
		),
	)
	if err != nil {
		t.Fatalf("semantic convention schema must merge with the OTel default resource: %v", err)
	}

	_, err = resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String("helm-ai-kernel"),
		),
	)
	if err != nil {
		t.Fatalf("semantic convention service attributes must build a resource: %v", err)
	}
}
