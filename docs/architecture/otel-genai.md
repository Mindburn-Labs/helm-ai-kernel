---
title: OTel GenAI attribute contract
last_reviewed: 2026-09-15
---

<!-- quantum_posture: this page describes telemetry attribute names only. It
specifies no cryptographic control, classical or post-quantum, and the spans it
describes carry no key material. -->

# OTel GenAI attribute contract

## Audience

Operators who join HELM governance traces to model traffic in a SIEM or OTel
backend, and anyone changing `core/pkg/observability/genai_attrs.go`.

## Source truth

- Upstream conventions: <https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md>.
  The `gen_ai.*` conventions were moved out of the main semantic-conventions
  repository in its v1.42.0 release; upstream status is Development, not Stable.
- Attribute keys: `core/pkg/observability/genai_attrs.go` — the single source of
  truth. Stable keys there are a major-version contract.
- Emitters: `core/pkg/otel/governance_tracer.go`.
- Exporters: `core/pkg/connectors/siem/loki/exporter.go`,
  `core/pkg/connectors/siem/datadog_logs/exporter.go`.

## Which spans carry GenAI attributes

Three, and all three follow the same rules:

| Span | Emitter | When |
| --- | --- | --- |
| decision | `TraceDecision` | a governed call is evaluated |
| denial | `TraceDenial` | a governed call is refused |
| tool invocation | `TraceGenAIToolCall` | a model invokes a tool |

## The provider key, and why there are two of them

Upstream replaced `gen_ai.system` with `gen_ai.provider.name`, which it marks
**Required** on inference and `execute_tool` spans. `gen_ai.system` does not
appear in the current conventions at all.

HELM emits **both**, on every span that carries either. A dashboard or SIEM join
written against the old key keeps working; a backend that validates against the
current conventions sees the key it expects. Anything that sets `gen_ai.system`
must set `gen_ai.provider.name` alongside it — `GenAIProviderNameFor` does the
mapping and `TestGenAIProviderNameAccompaniesEverySystem` enforces the pairing.

Three of HELM's five provider values were already spelled the upstream way. Two
were not:

| `gen_ai.system` (legacy) | `gen_ai.provider.name` (current) |
| --- | --- |
| `openai` | `openai` |
| `anthropic` | `anthropic` |
| `aws.bedrock` | `aws.bedrock` |
| `azure.openai` | `azure.ai.openai` |
| `google.gemini` | `gcp.gemini` |

A provider value HELM does not recognise — an operator's own gateway, say — is
passed through unchanged rather than dropped. An absent Required attribute is
worse than an unfamiliar value.

## The tool span rename, which is a hard cut

Upstream names a tool span `{gen_ai.operation.name} {gen_ai.tool.name}` and names
the operation `execute_tool`. HELM previously named the span `gen_ai.tool_call`
and set the operation to `tool_call`, neither of which is an upstream value.

Both now follow upstream. The operation value is mapped at emission, so callers
that still pass `tool_call` need no change.

**A span carries one name.** Unlike the attribute keys above, this rename cannot
be emitted both ways, so there is no compatibility window for it: collector
rules, saved searches and dashboards that match `gen_ai.tool_call` stop matching
the moment this ships and must be updated to `execute_tool`. Spans with no tool
name are named `execute_tool` alone rather than left with a dangling separator.

## SIEM exporters

Both provider keys travel through the exporters, so a monitor written against
either keeps matching:

- **Loki** adds the `gen_ai_provider_name` stream label beside `gen_ai_system`.
  Both carry the same small value set, so label cardinality does not grow.
- **Datadog** adds the `gen_ai.provider.name:` tag beside `gen_ai.system:`.

## Open decision: when the legacy key is removed

`gen_ai.system` is emitted for **one major version**. The release that drops it
is **not yet decided** — it is the owner's call, tracked in HELM-712. Until that
decision is recorded here, treat `gen_ai.system` as present and do not build
anything that assumes its removal date.

The tool span name is not covered by that window; see above.
