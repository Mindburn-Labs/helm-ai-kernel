# HELM SDK — Rust

Typed Rust client for the retained HELM kernel API.

## Install

```toml
helm-sdk = "0.4.0"
```

Published crate version is `0.4.0` and is declared in `Cargo.toml`.

## Local Development

```bash
cargo test
```

## Generated Sources

`src/types_gen.rs` is generated from `api/openapi/helm.openapi.yaml`. Protobuf bindings under `src/generated/` are generated from `protocols/proto/`; the `codegen` feature can rebuild them with `tonic-build`.

## Usage

```rust
use helm_sdk::{ChatCompletionRequest, ChatCompletionRequestMessagesInner, HelmClient, Role};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HelmClient::new("http://localhost:8080");
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

## Execution Boundary Methods

`HelmClient` includes typed calls for `create_evidence_envelope_manifest`, `list_negative_conformance_vectors`, `list_mcp_registry`, `discover_mcp_server`, `approve_mcp_server`, and `inspect_sandbox_grants`. `SandboxGrantInspection` returns either backend profiles or a sealed grant depending on whether a runtime query is provided.

## Release Notes

`0.4.0` is the cleaned OSS kernel baseline with the retained OpenAPI client surface and optional protobuf codegen.
