---
title: SDKs
last_reviewed: 2026-07-15
---

# SDKs

Use an SDK for typed access to a local HELM AI Kernel HTTP surface. Use the
OpenAI-compatible proxy when an existing application can set `base_url` or
`baseURL`.

This guide publishes no hosted HELM API base URL.

## Local Base URLs

| Runtime mode | Base URL | Use |
| --- | --- | --- |
| `quickstart` or `serve` | `http://127.0.0.1:7714` | Local boundary and proof loop |
| `server` | `http://127.0.0.1:8080` | Generic API server |
| OpenAI proxy | `http://127.0.0.1:9090/v1` | OpenAI-compatible calls |
| HTTP MCP transport | `http://localhost:9100/mcp` | Selected MCP runtime only |

Pin the mode and base URL together. Do not move an example between ports without
starting the corresponding runtime.

## Verified v0.7.2 Coordinates

Run a clean registry check before copying these into a managed client estate.
The following four coordinates were available for the v0.7.2 release:

Source version claims are tied to the repository `VERSION` (`0.7.2` for this release).
The matching Go subdirectory tag is `sdk/go/v0.7.2`.

```bash
npm install @mindburn/helm-ai-kernel@0.7.2
python -m pip install helm-sdk==0.7.2
go get github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v0.7.2
```

The matching Java coordinate is `io.github.mindburnlabs:helm-sdk:0.7.2`:

```xml
<dependency>
  <groupId>io.github.mindburnlabs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>0.7.2</version>
</dependency>
```

Rust source and a v0.7.2 crate artifact exist under `sdk/rust/`, but public
registry discovery was inconsistent at the last review. Recheck the target
registry before publishing `cargo add` as a supported install path.

Use `version-status.json` and `make version-drift-published` before changing a
pinned version claim.

## Clients In This Repository

| Language | Source | Local check |
| --- | --- | --- |
| Python | `sdk/python/` | `make test-sdk-py` |
| TypeScript / JavaScript | `sdk/ts/` | `make test-sdk-ts` |
| Go | `sdk/go/` | `cd sdk/go && go test ./...` |
| Rust | `sdk/rust/` | `make test-sdk-rust` |
| Java | `sdk/java/` | `make test-sdk-java` |

## Authentication Coverage

Protected routes require `Authorization: Bearer $HELM_ADMIN_API_KEY`. Tenant-
scoped routes also bind tenant and principal headers. A scoped emergency fence
can additionally require `X-Helm-Workspace-ID`.

| Client | API key | Tenant | Principal | Workspace |
| --- | --- | --- | --- | --- |
| Go | yes | yes | yes | no helper |
| TypeScript | yes | yes | no helper | no helper |
| Python | yes | yes | no helper | no helper |
| Java | yes | no helper | no helper | no helper |
| Rust | no helper | no helper | no helper | no helper |

When the chosen client lacks a required header, use the documented HTTP route or
generate a client from the [public OpenAPI](/openapi.yaml). Do not silently omit
server-required identity scope.

## Public TypeScript Sandbox

The public demo route is the shortest no-admin-key SDK proof. It is a sandbox
example, not a protected action sample:

```ts
import { HelmClient } from "@mindburn/helm-ai-kernel";

const helm = new HelmClient({ baseUrl: "http://127.0.0.1:7714" });
const demo = await helm.runPublicDemo("dangerous_shell");
const verification = await helm.verifyPublicDemoReceipt(
  demo.receipt,
  demo.proof_refs.receipt_hash,
);

console.log(demo, verification);
```

## Client Behavior

| Condition | Do this |
| --- | --- |
| `ALLOW` | Continue only through the wrapper or executor that requested the decision |
| `DENY` | Stop and show the reason code |
| `ESCALATE` | Keep the call blocked; show the scoped approval hint |
| Missing receipt | Confirm the application called HELM instead of the upstream directly |
| Required header missing | Stop and use a client path that can send the server-required scope |

SDK helpers are clients for local Kernel contracts. Source availability alone
does not prove registry availability, native-client loading, hosted service
availability, or interception of calls that bypass HELM.
