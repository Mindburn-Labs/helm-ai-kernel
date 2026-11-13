# HELM SDK - Rust

Typed Rust client for the retained HELM kernel API.

## Install

```bash
cargo add helm-sdk
```

Package metadata identifies source target `0.12.0`; verify registry state
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
use helm_sdk::{EvaluateRequest, HelmClient};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HelmClient::with_auth(
        "http://127.0.0.1:7714",
        std::env::var("HELM_ADMIN_API_KEY").ok().as_deref(),
        Some("tenant-a"),
        Some("operator-a"),
    );
    let mut request = EvaluateRequest::new();
    request.tool = Some("read-ticket".to_string());
    request.effect_level = Some("ticket:123".to_string());
    request.session_id = Some("example-session".to_string());

    let decision = client.evaluate_decision_v5(&request)?;
    println!("{} {}", decision.verdict, decision.receipt_id); // ALLOW, DENY or ESCALATE
    Ok(())
}
```

`/api/v1/evaluate` is a protected tenant-scoped route: `with_auth` takes the API
key and the tenant and principal the server is configured for. `HelmClient::new`
sends no credentials and remains available for public routes.

`chat_completions` posts to `/v1/chat/completions`. `helm-ai-kernel serve`
answers that route with 403 before any upstream is called, because its Guardian
allows no egress destination (`controls.yaml` CTL-047).

## Execution Boundary Methods

`HelmClient` includes calls for evidence envelope manifests, boundary records
and checkpoints, conformance vectors, MCP quarantine and authorization
profiles, sandbox profiles and grants, authz snapshots, approvals, budgets,
telemetry export, and coexistence capabilities. `SandboxGrantInspection`
returns either backend profiles or a sealed grant depending on whether a
runtime query is provided.

`evaluate_decision_v5` accepts only `EvaluateRequest`, whose `tool`,
`effect_level`, and `session_id` must be non-blank. The returned value is the
receipt-bearing `EvaluateResponse`. `evaluate_decision` remains for dynamic
callers: it sends any serializable body and returns untyped JSON.

## Source target

The client uses the canonical typed evaluation contract and receipt-bearing V5
responses. Registry availability remains a post-publication check.
