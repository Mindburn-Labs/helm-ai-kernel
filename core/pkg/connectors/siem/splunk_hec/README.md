# Splunk HEC SIEM exporter

OpenTelemetry `SpanExporter` that translates helm-oss governance spans into
Splunk HTTP Event Collector (HEC) events. The full OTel GenAI semconv attribute
set (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.tool.name`,
`gen_ai.tool.call.id`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
`gen_ai.response.finish_reason`) is preserved alongside the helm governance
namespace (`helm.verdict`, `helm.policy_id`, `helm.proof_node_id`,
`helm.correlation_id`).

## Install

```go
import (
    "github.com/Mindburn-Labs/helm-oss/core/pkg/connectors/siem/splunk_hec"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

exp, err := splunk_hec.New(splunk_hec.Config{
    URL:   os.Getenv("SPLUNK_HEC_URL"),   // https://splunk.example.com:8088/services/collector/event
    Token: os.Getenv("SPLUNK_HEC_TOKEN"), // HEC token
    Index: os.Getenv("SPLUNK_HEC_INDEX"), // optional; defaults to HEC default index
})
if err != nil { panic(err) }

tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
otel.SetTracerProvider(tp)
```

## Environment variables

| Variable            | Purpose                                                       |
|---------------------|---------------------------------------------------------------|
| `SPLUNK_HEC_URL`    | HEC event endpoint (`/services/collector/event`).             |
| `SPLUNK_HEC_TOKEN`  | HEC bearer token (passed as `Authorization: Splunk <token>`). |
| `SPLUNK_HEC_INDEX`  | Optional. Pin events to a specific Splunk index.              |
| `SPLUNK_HEC_SOURCE` | Optional. Override `source` (default `helm-oss`).             |

## OpenTelemetry collector configuration (alternative)

If you prefer to route through the OTel collector, the equivalent
`splunkhec` exporter from `opentelemetry-collector-contrib` consumes the
same wire shape:

```yaml
exporters:
  splunk_hec:
    token: ${SPLUNK_HEC_TOKEN}
    endpoint: ${SPLUNK_HEC_URL}
    source: helm-oss
    sourcetype: helm:governance
    index: ${SPLUNK_HEC_INDEX}

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [splunk_hec]
```

## Dashboard import

1. In Splunk Web, navigate to **Settings -> User Interface -> Views**.
2. Click **New View** and paste the contents of
   [`dashboards/helm.xml`](dashboards/helm.xml).
3. Save and visit the new view; the panels expect events under
   `sourcetype=helm:governance` and pivot on
   `attributes.gen_ai.tool.name`, `verdict`, and `helm.policy_id`.

## Cross-reference to receipts

`gen_ai.tool.call.id` mirrors `helm.correlation_id`, which equals
`receipt.correlation_id`. Splunk searches can join the OTel trace to the
helm receipt 1:1:

```spl
index=* sourcetype=helm:governance verdict=DENY
| join correlation_id [ search index=helm_receipts ]
| table _time correlation_id helm.policy_id receipt_id
```

## See also

- [`examples/otel-genai/README.md`](../../../../../examples/otel-genai/README.md)
  — GenAI semconv example and telemetry contract.
- [`exporter.go`](exporter.go) — wire-shape source.
