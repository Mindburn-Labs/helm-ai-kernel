# HELM SDK — Go

Typed Go client for the HELM kernel API. Zero external dependencies.

## Install

```bash
go get github.com/Mindburn-Labs/helm-oss/sdk/go
```

Version truth is the repository `VERSION` file (`0.4.0` for this reset). Go consumers pin by module commit or release tag.

## Local Test

```bash
go test ./...
```

## Generated Sources

The Go SDK is a hand-maintained HTTP client over the OpenAPI contract. It does not currently ship generated protobuf bindings.

## Quick Example

```go
package main

import (
    "fmt"
    "log"

    helm "github.com/Mindburn-Labs/helm-oss/sdk/go/client"
)

func main() {
    c := helm.New("http://localhost:8080")

    // Chat completions via HELM proxy
    res, err := c.ChatCompletions(helm.ChatCompletionRequest{
        Model:    "gpt-4",
        Messages: []helm.ChatMessage{{Role: "user", Content: "List files in /tmp"}},
    })
    if err != nil {
        if apiErr, ok := err.(*helm.HelmApiError); ok {
            fmt.Println("Denied:", apiErr.ReasonCode)
            return
        }
        log.Fatal(err)
    }
    fmt.Println(res.Choices[0].Message.Content)

    // Conformance
    conf, _ := c.ConformanceRun(helm.ConformanceRequest{Level: "L2"})
    fmt.Println(conf.Verdict, conf.Gates, "gates")
}
```

## API

| Method | Endpoint |
|--------|----------|
| `ChatCompletions(req)` | `POST /v1/chat/completions` |
| `ApproveIntent(req)` | `POST /api/v1/kernel/approve` |
| `ListSessions(limit, offset)` | `GET /api/v1/proofgraph/sessions` |
| `GetReceipts(sessionID)` | `GET /api/v1/proofgraph/sessions/{id}/receipts` |
| `ExportEvidence(sessionID)` | `POST /api/v1/evidence/export` |
| `VerifyEvidence(bundle)` | `POST /api/v1/evidence/verify` |
| `ConformanceRun(req)` | `POST /api/v1/conformance/run` |
| `Health()` | `GET /healthz` |
| `Version()` | `GET /version` |

## Release Notes

`0.4.0` is the cleaned OSS kernel baseline with the public HTTP client surface, conformance entrypoints, and evidence verification helpers.
