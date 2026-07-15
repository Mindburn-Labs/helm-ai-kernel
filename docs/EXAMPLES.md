---
title: HELM AI Kernel Examples Matrix
last_reviewed: 2026-07-10
---

# HELM AI Kernel Examples Matrix

This page is for developers choosing the shortest source-backed example for a language, framework, receipt, MCP, OpenTelemetry, or policy workflow. The outcome is a runnable example path, the server mode it expects, and the validation command that proves the public docs claim.

## Audience

This page is for developers who need to pick a runnable source-backed example for HELM AI Kernel rather than infer support from a language name or integration slogan.

## Outcome

After this page you should know which example to run, which HELM server mode it expects, what output proves success, and which command validates the claim.

## Source Truth

Example source lives under [`examples`](../examples). SDK package docs live under [`sdk`](../sdk). Deployment examples are separated into [`deploy`](../deploy) and the Kubernetes chart at [`deploy/helm-chart`](../deploy/helm-chart).

## Example Flow

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Context Plane"]
        Reader["developer"]
        Pick["choose example"]
        Server["start helm-ai-kernel serve or helm-ai-kernel proxy"]
    end

    subgraph Evaluation["2. Evaluation & Policy Plane"]
        Gate["docs and example validation"]
    end

    subgraph Execution["3. Execution & Verdict Plane"]
        Run["run language/framework code"]
    end

    subgraph Ledger["4. Tamper-Evident Ledger Plane"]
        Receipt["capture receipt or decision"]
        Verify["verify receipt/EvidencePack"]
    end

    %% Operational Flow Edges
    Reader --> Pick
    Pick --> Server
    Server --> Run
    Run --> Receipt
    Receipt --> Verify
    Verify --> Gate

    %% Premium Styling Rules
    style Run fill:#3182ce,stroke:#2b6cb0,stroke-width:2px,color:#fff
    style Receipt fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
    style Verify fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
    style Gate fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff
```


## Runnable Matrix

| Example | Server mode | What it proves | Source | Validation |
| --- | --- | --- | --- | --- |
| Python SDK | `helm-ai-kernel serve --policy examples/launch/policies/agent_tool_call_boundary.toml` | ALLOW, DENY, MCP fail-closed denial, receipt verification, sandbox preflight, and evidence verification | [`examples/python_sdk`](../examples/python_sdk) | `make sdk-examples-smoke` |
| TypeScript SDK | `helm-ai-kernel serve --policy examples/launch/policies/agent_tool_call_boundary.toml` | ALLOW, DENY, MCP fail-closed denial, receipt verification, sandbox preflight, and evidence verification | [`examples/ts_sdk`](../examples/ts_sdk) | `make sdk-examples-smoke` |
| Python governed chat | `helm-ai-kernel serve --policy <LLM_INFERENCE policy>` plus `HELM_UPSTREAM_URL` and server-owned `HELM_UPSTREAM_API_KEY` | Authenticated OpenAI-compatible chat, receipt headers, evidence, and conformance | [`examples/python_openai_baseurl`](../examples/python_openai_baseurl) | `make test-sdk-py` |
| TypeScript governed chat | `helm-ai-kernel serve --policy <LLM_INFERENCE policy>` plus `HELM_UPSTREAM_URL` and server-owned `HELM_UPSTREAM_API_KEY` | Authenticated OpenAI-compatible chat, receipt headers, evidence, and conformance | [`examples/ts_openai_baseurl`](../examples/ts_openai_baseurl) | `make test-sdk-ts` |
| JavaScript governed fetch | `helm-ai-kernel serve --policy <LLM_INFERENCE policy>` plus `HELM_UPSTREAM_URL` and server-owned `HELM_UPSTREAM_API_KEY` | Authenticated raw OpenAI-compatible chat and receipt extraction | [`examples/js_openai_baseurl`](../examples/js_openai_baseurl) | `make docs-truth` |
| Go client | `helm-ai-kernel serve --policy <file>` | typed client request, decision, receipt handling | [`examples/go_client`](../examples/go_client) | `go test ./examples/go_client/... -run '^$'` |
| Rust client | `helm-ai-kernel serve --policy <file>` | Rust client and verifier-facing types | [`examples/rust_client`](../examples/rust_client) | `make test-sdk-rust` |
| Java client | `helm-ai-kernel serve --policy <file>` | JVM client request and error handling | [`examples/java_client`](../examples/java_client) | `make test-sdk-java` |
| MCP client | `helm-ai-kernel mcp serve` or `/mcp` runtime | docs/tool boundary and MCP authorization path | [`examples/mcp_client`](../examples/mcp_client) | `make docs-truth` |
| Receipt verification | existing receipt/EvidencePack | offline verification path | [`examples/receipt_verification`](../examples/receipt_verification) | `make docs-truth` |
| Golden evidence | fixture evidence | stable conformance material | [`examples/golden`](../examples/golden) | `make docs-coverage` |
| OpenTelemetry GenAI | `helm-ai-kernel proxy` with telemetry enabled | telemetry export shape | [`examples/otel-genai`](../examples/otel-genai) | `go test ./examples/otel-genai/...` |
| OpenCLAW | local example harness | compatibility with OpenCLAW-style policy material | [`examples/openclaw`](../examples/openclaw) | `make docs-truth` |
| Policy examples | `helm-ai-kernel bundle build <source>` | CEL, Rego, Cedar bundle inputs | [`examples/policies`](../examples/policies) | `make docs-truth` |
| Policy-pack examples | `helm-ai-kernel serve --policy examples/policy-packs/<pack>.toml` | runnable allow/deny reference packs, including destructive operation deny/escalate guidance | [`examples/policy-packs`](../examples/policy-packs) | `cd core/cmd/helm-ai-kernel && go test . -run TestPolicyPackExamplesLoad -count=1` |
| Starters | selected starter README | scaffolded integrations only where source exists | [`examples/starters`](../examples/starters) | `make docs-truth` |

## Common Environment

```bash
export HELM_URL=http://127.0.0.1:7714
export HELM_ADMIN_API_KEY="${HELM_ADMIN_API_KEY:?set runtime admin key}"
export HELM_TENANT_ID=default
export HELM_PRINCIPAL_ID=example-agent
export HELM_SESSION_ID=example-session
```

The runtime's tenant and principal configuration must match the client values.
Examples may also use framework-native `baseURL` or `base_url` options. Prefer
the variable names used inside the example README or code; do not invent a new
variable in public docs without adding it to the example. The separate proxy
sidecar uses `OPENAI_BASE_URL=http://127.0.0.1:9090/v1`; it is not the
tenant-scoped runtime API.

## Expected Output

Every runnable example should produce at least one of these observable outputs:

- an HTTP response from HELM instead of the upstream provider;
- a receipt header or receipt file under the configured receipts directory;
- a deny decision and denial receipt for the blocked-path test;
- a verifier or conformance command that exits zero.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| example reaches the upstream provider directly | base URL bypassed HELM | follow the example's declared surface: governed examples use `HELM_URL=http://127.0.0.1:7714`; only an explicitly standalone sidecar integration uses `http://127.0.0.1:9090/v1` |
| receipt is missing | wrong server mode, missing governed scope, or receipt persistence failure | use `helm-ai-kernel serve` with matching admin, tenant, principal, and session bindings plus a configured server-owned upstream key; the standalone proxy is a different surface |
| Java package cannot be fetched from Maven Central | registry freshness or local Maven cache issue | verify `io.github.mindburnlabs:helm-sdk:0.7.2` against repo1 or `version-status.json`; build from `sdk/java` only when testing local source changes |

## Not Covered

This page does not claim support for languages or frameworks that lack source, an example, or an SDK README. Planned examples must remain out of public support tables until code and validation exist.
