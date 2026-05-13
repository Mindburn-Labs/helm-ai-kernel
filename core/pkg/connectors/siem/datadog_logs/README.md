# Datadog Logs SIEM exporter

OpenTelemetry `SpanExporter` that translates helm-ai-kernel governance spans into
Datadog Logs Intake events posted to `https://http-intake.logs.<site>/api/v2/logs`.
The OTel GenAI semconv keys (`gen_ai.system`, `gen_ai.request.model`,
`gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.usage.input_tokens`,
`gen_ai.usage.output_tokens`) and the helm.* governance keys (`helm.verdict`,
`helm.policy_id`, `helm.proof_node_id`, `helm.correlation_id`) become Datadog
log facets.

## Install

```go
import (
    "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/siem/datadog_logs"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

exp, err := datadog_logs.New(datadog_logs.Config{
    Site:   os.Getenv("DD_SITE"),    // "datadoghq.com" | "datadoghq.eu" | ...
    APIKey: os.Getenv("DD_API_KEY"),
    Env:    os.Getenv("DD_ENV"),     // optional — populates env: tag
})
if err != nil { panic(err) }

tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
otel.SetTracerProvider(tp)
```

## Environment variables

| Variable     | Purpose                                                                  |
|--------------|--------------------------------------------------------------------------|
| `DD_API_KEY` | Datadog API key, sent as `DD-API-KEY` header.                            |
| `DD_SITE`    | Datadog site (`datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com`, ...).|
| `DD_ENV`     | Optional. Adds `env:<value>` to `ddtags`.                                |

## OpenTelemetry collector configuration (alternative)

```yaml
exporters:
  datadog:
    api:
      site: ${DD_SITE}
      key: ${DD_API_KEY}
    logs:
      endpoint: https://http-intake.logs.${DD_SITE}/api/v2/logs

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [datadog]
```

## Dashboard import

1. In the Datadog UI, navigate to **Dashboards -> New Dashboard -> Import**.
2. Upload [`dashboards/helm.json`](dashboards/helm.json).
3. The dashboard expects logs filterable by `service:helm-governance` and
   pivots on `@verdict`, `@gen_ai.tool.name`, `@helm.policy_id`,
   `@correlation_id`.

## Cross-reference to receipts

`@correlation_id` mirrors the helm receipt `correlation_id`. A single
log-search query joins denials to their upstream model invocations and to
the receipt store:

```
service:helm-governance @verdict:DENY @correlation_id:abc-123
```

## See also

- [`examples/otel-genai/README.md`](../../../../../examples/otel-genai/README.md)
  — GenAI semconv example and telemetry contract.
- [`exporter.go`](exporter.go) — wire-shape source.
