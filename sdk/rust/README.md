# HELM SDK - Rust

Typed Rust client for the retained HELM kernel API.

## Install

```bash
cargo add helm-sdk
```

Package metadata identifies source target `0.8.2`; verify registry state
before publishing a pinned install claim.

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
    let client = HelmClient::new("http://127.0.0.1:7714");
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

For a protected tenant-scoped route, construct the client with the API key and
explicit server-bound tenant and principal IDs. `HelmClient::new` remains
available for public routes.

```rust
let client = HelmClient::with_auth(
    "http://127.0.0.1:7714",
    Some("api-key"),
    Some("tenant-id"),
    Some("principal-id"),
);
```

## Execution Boundary Methods

`HelmClient` includes calls for evidence envelope manifests, boundary records
and checkpoints, conformance vectors, MCP quarantine and authorization
profiles, sandbox profiles and grants, authz snapshots, approvals, budgets,
telemetry export, and coexistence capabilities. `SandboxGrantInspection`
returns either backend profiles or a sealed grant depending on whether a
runtime query is provided.

`evaluate_decision` accepts only `EvaluateRequest`, whose `tool`,
`effect_level`, and `session_id` must be non-blank. The returned value is the
receipt-bearing `EvaluateResponse`.

## Source target

The client uses the canonical typed evaluation contract and receipt-bearing V5
responses. Registry availability remains a post-publication check.
