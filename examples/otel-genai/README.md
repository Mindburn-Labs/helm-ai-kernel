# OTel GenAI semantic conventions example

This example demonstrates that helm-ai-kernel governance traces conform to the
OpenTelemetry Generative AI semantic convention (semconv).

## What this proves

1. helm-ai-kernel governance spans carry the stable OTel GenAI keys:
   - `gen_ai.system`
   - `gen_ai.request.model`
   - `gen_ai.operation.name`
   - `gen_ai.tool.name`
   - `gen_ai.tool.call.id`
   - `gen_ai.usage.input_tokens`
   - `gen_ai.usage.output_tokens`
   - `gen_ai.response.finish_reason`
   - `gen_ai.response.model`
   - `gen_ai.response.id`
2. The helm `correlation_id` is mirrored into `gen_ai.tool.call.id`, so OTel
   traces and helm-ai-kernel receipts cross-reference 1:1.
3. helm-specific governance attributes live under the `helm.*` namespace
   alongside the `gen_ai.*` keys on the same span:
   - `helm.verdict`
   - `helm.policy_id`
   - `helm.proof_node_id`
   - `helm.reason_code`
   - `helm.correlation_id`
   - `helm.receipt_id`
   - `helm.tenant_id`

The single source of truth for the attribute keys lives in
`core/pkg/observability/genai_attrs.go`.

## Run

```bash
cd examples/otel-genai
go run .
```

You should see the recorded span attributes printed plus a final line of the
form:

```
helm correlation_id == gen_ai.tool.call.id: <uuid>
```

## Smoke test

```bash
cd examples/otel-genai
go test ./...
```

The test asserts every required OTel GenAI key and helm.* key appears on the
emitted span, and that the span name is `gen_ai.tool_call`.

## See also

- `core/pkg/otel/governance_tracer.go` - the GovernanceTracer implementation
  that emits the spans.
- `core/cmd/helm-ai-kernel/proxy_cmd.go` - the helm OpenAI-compatible proxy that injects
  GenAI attributes and `traceparent` on every governed call.
- `docs/architecture/otel-genai.md` - full architecture: attribute mapping,
  receipt correlation, and SIEM exporter packs.
