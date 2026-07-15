# Rust Client Example

Shows HELM integration with the Rust SDK.

## Prerequisites

- Rust 1.75+
- A governed `helm-ai-kernel serve` runtime with a permitted `LLM_INFERENCE`
  policy and an OpenAI-compatible upstream. This example does not target the
  standalone `helm-ai-kernel proxy` sidecar.

Use matching runtime and client bindings:

```bash
# Runtime: HELM_UPSTREAM_URL may include /v1 or omit it. The provider key is
# server-owned and must be distinct from the runtime admin key.
HELM_ADMIN_API_KEY=local-admin-key \
HELM_RUNTIME_TENANT_ID=default \
HELM_RUNTIME_PRINCIPAL_ID=example-agent \
HELM_UPSTREAM_URL=http://127.0.0.1:19090 \
HELM_UPSTREAM_API_KEY=local-upstream-key \
./bin/helm-ai-kernel serve --policy <policy-that-permits-LLM_INFERENCE>

# Client:
export HELM_URL=http://127.0.0.1:7714
export HELM_ADMIN_API_KEY=local-admin-key
export HELM_TENANT_ID=default
export HELM_PRINCIPAL_ID=example-agent
export HELM_SESSION_ID=example-session
```

Start `python3 scripts/launch/mock-openai-upstream.py --port 19090` first for
a local upstream. If the emergency-stop fence is enabled, configure matching
`HELM_RUNTIME_WORKSPACE_ID` and `HELM_WORKSPACE_ID` values as well.

## Source Example

`main.rs` is a small integration source file that imports `helm_sdk`. This
directory does not carry its own `Cargo.toml`; use it as source material for a
Rust service crate or run the SDK package gate below.

## Expected Output

The example prints chat-completion, conformance, and health sections. The exact
verdict, reason code, and gate count depend on the policy and HELM server you
run locally.

## Validation

The Rust SDK package is validated from the repository root with:

```bash
make test-sdk-rust
```
