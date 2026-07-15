# HELM SDK - Rust

Typed Rust client for the retained HELM kernel API.

## Install

```bash
cargo add helm-sdk
```

Package metadata declares crate version `0.7.2` in `Cargo.toml`; verify registry
state before publishing a pinned install claim.

## Local Development

```bash
cargo test
```

## Generated Sources

`src/types_gen.rs` is generated from `api/openapi/helm.openapi.yaml`.
Protobuf bindings under `src/generated/` are generated from
`protocols/proto/`; the `codegen` feature can rebuild them with
`tonic-build`.

## Usage

```rust
use helm_sdk::{ChatCompletionRequest, ChatCompletionRequestMessagesInner, HelmClient, Role};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HelmClient::new("http://127.0.0.1:7714")
        .with_api_key("...")
        .with_identity("tenant-a", "example-agent")
        .with_session_id("session-a");
    let result = client.chat_completions(&ChatCompletionRequest::new(
        "gpt-4".to_string(),
        vec![ChatCompletionRequestMessagesInner::new(
            Role::User,
            "hello".to_string(),
        )],
    ))?;
    println!("{:?}", result);
    Ok(())
}
```

`chat_completions` is a governed, tenant-scoped proxy call. It requires an API
key plus tenant, principal, and session bindings; add `with_workspace_id()`
when the runtime requires workspace scope.

## Scoped decision evaluation

`POST /api/v1/evaluate` accepts only `action`, `resource`, optional `context`,
and optional `session_history` in JSON. Bind identity through `EvaluationScope`:

```rust
use helm_sdk::{DecisionRequest, EvaluationScope, HelmClient};

let client = HelmClient::new("http://127.0.0.1:7714")
    .with_api_key("...")
    .with_identity("tenant-a", "example-agent")
    .with_session_id("session-a");
let result = client.evaluate_decision_with_scope(
    &DecisionRequest::new("read-ticket".into(), "ticket:123".into()),
    &EvaluationScope::new("tenant-a", "example-agent", "session-a"),
    Some("evaluate-ticket-123"),
)?;
println!("{:?}", result.decision.verdict);
```

`with_identity()` and optional `with_workspace_id()` bind other protected
runtime calls. `evaluate_decision()` remains only as a deprecated
source-compatibility shim and fails locally with a migration error.

## Execution Boundary Methods

`HelmClient` includes calls for evidence envelope manifests, boundary records
and checkpoints, conformance vectors, MCP quarantine and authorization
profiles, sandbox profiles and grants, authz snapshots, approvals, budgets,
telemetry export, and coexistence capabilities. `SandboxGrantInspection`
returns either backend profiles or a sealed grant depending on whether a
runtime query is provided.

## Release Notes

`0.7.2` is the release-hardening patch with the retained OpenAPI client surface and optional protobuf codegen.
