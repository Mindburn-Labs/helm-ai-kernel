# Elastic ECS SIEM exporter

OpenTelemetry `SpanExporter` that translates helm-ai-kernel governance spans into
ECS-shaped documents posted to the Elasticsearch `_bulk` API. The OTel GenAI
semconv keys (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.tool.name`,
`gen_ai.tool.call.id`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`)
and the helm.* governance keys (`helm.verdict`, `helm.policy_id`,
`helm.proof_node_id`, `helm.correlation_id`) are preserved verbatim alongside
the canonical ECS fields (`@timestamp`, `event.dataset`, `event.outcome`,
`service.name`, `trace.id`, `span.id`).

## Install

```go
import (
    "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/siem/elastic_ecs"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

exp, err := elastic_ecs.New(elastic_ecs.Config{
    URL:    os.Getenv("ELASTIC_URL"),     // https://es.example.com:9200
    Index:  os.Getenv("ELASTIC_INDEX"),   // helm-governance
    APIKey: os.Getenv("ELASTIC_API_KEY"), // ApiKey-style auth (preferred)
})
if err != nil { panic(err) }

tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
otel.SetTracerProvider(tp)
```

## Environment variables

| Variable           | Purpose                                                  |
|--------------------|----------------------------------------------------------|
| `ELASTIC_URL`      | Elasticsearch base URL, e.g. `https://es.example.com:9200`. |
| `ELASTIC_INDEX`    | Destination index, e.g. `helm-governance`.               |
| `ELASTIC_API_KEY`  | Elasticsearch API key (sent as `Authorization: ApiKey`). |
| `ELASTIC_USERNAME` | Optional. HTTP Basic alternative to API key.             |
| `ELASTIC_PASSWORD` | Optional. HTTP Basic alternative to API key.             |

## OpenTelemetry collector configuration (alternative)

```yaml
exporters:
  elasticsearch:
    endpoints: ["${ELASTIC_URL}"]
    api_key: "${ELASTIC_API_KEY}"
    logs_index: "${ELASTIC_INDEX}"
    mapping:
      mode: ecs

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [elasticsearch]
```

## Kibana saved-objects import

1. In Kibana, navigate to **Stack Management -> Saved Objects -> Import**.
2. Upload [`kibana/helm.ndjson`](kibana/helm.ndjson). It contains:
   - an `index-pattern` matching `helm-governance*`,
   - a `search` of `event.dataset : "helm.governance"`,
   - a `dashboard` titled **HELM Governance**.
3. Open **Analytics -> Dashboard -> HELM Governance**.

## Cross-reference to receipts

`labels.correlation_id` mirrors `helm.correlation_id`, which equals the
helm receipt `correlation_id`. KQL example to scope a denial to a single
receipt:

```
event.dataset : "helm.governance" and labels.verdict : "DENY" and labels.correlation_id : "abc-123"
```

## See also

- [`examples/otel-genai/README.md`](../../../../../examples/otel-genai/README.md)
  — GenAI semconv example and telemetry contract.
- [`exporter.go`](exporter.go) — wire-shape source.
