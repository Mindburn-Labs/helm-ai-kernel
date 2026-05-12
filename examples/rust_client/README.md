# Rust Client Example

Shows HELM integration with the Rust SDK.

## Prerequisites

- HELM running at `http://127.0.0.1:7714` (`docker compose up -d`)
- Rust 1.75+

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
