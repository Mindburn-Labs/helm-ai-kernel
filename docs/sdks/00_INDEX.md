---
title: SDKs
last_reviewed: 2026-07-10
---

# SDKs

Use an SDK when you want typed access to the local HELM HTTP API. The governed
chat route served by the runtime requires an admin bearer key plus matching
tenant, principal, and session bindings. The standalone OpenAI-compatible
proxy is a separate local sidecar for apps that can set `base_url` or `baseURL`.

## Local Base URLs

| Surface | Base URL |
| --- | --- |
| `serve` runtime | `http://127.0.0.1:7714` |
| `server` runtime | `http://127.0.0.1:8080` |
| Standalone OpenAI proxy sidecar | `http://127.0.0.1:9090/v1` |

## Clients In This Repository

| Language | Source | Local check |
| --- | --- | --- |
| Python | `sdk/python/` | `make test-sdk-py` |
| TypeScript / JavaScript | `sdk/ts/` | `make test-sdk-ts` |
| Go | `sdk/go/` | `cd sdk/go && go test ./...` |
| Rust | `sdk/rust/` | `make test-sdk-rust` |
| Java | `sdk/java/` | `make test-sdk-java` |

Registry package availability can differ from source availability. Verify the
target package registry before publishing pinned install instructions.
Use `version-status.json` or `make version-drift-published` before making a
pinned package claim.

Current source identity includes the Java coordinate
`io.github.mindburnlabs:helm-sdk:0.7.2`; verify registry availability before
presenting it as an install path.

Source version claims are tied to the repository `VERSION` (`0.7.2` for this release). Current source package coordinates include:

- Go module: `github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v0.7.2`
- Go subdirectory tag: `sdk/go/v0.7.2`
- Java dependency:

```xml
<dependency>
  <groupId>io.github.mindburnlabs</groupId>
  <artifactId>helm-sdk</artifactId>
  <version>0.7.2</version>
</dependency>
```

## Python

```python
from helm_sdk import HelmClient

client = HelmClient(base_url="http://127.0.0.1:7714")
```

## TypeScript

```ts
import { HelmClient } from "@mindburn/helm-ai-kernel";

const client = new HelmClient({ baseUrl: "http://127.0.0.1:7714" });
```

## Go

```go
client := helm.New("http://127.0.0.1:7714")
```

## Rust

```rust
let client = HelmClient::new("http://127.0.0.1:7714");
```

## Java

```java
HelmClient client = new HelmClient("http://127.0.0.1:7714");
```

## Client Behavior

| Condition | Do this |
| --- | --- |
| `ALLOW` | Continue with the governed result |
| `DENY` | Stop and show the reason code |
| `ESCALATE` | Show the approval hint; do not continue automatically |
| Missing receipt | Confirm the app called HELM instead of the upstream directly |

SDK helpers are local clients for the Kernel boundary.
