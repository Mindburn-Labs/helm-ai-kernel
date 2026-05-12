# HELM SDK - Go

Typed Go client for the HELM kernel HTTP API.

## Install

```bash
go get github.com/Mindburn-Labs/helm-oss/sdk/go@main
```

Version truth is the repository `VERSION` file (`0.5.0` for this reset).
Go consumers should pin by commit or `@main` until SDK module release tags are
realigned with the repository release version.

## Local Test

```bash
cd sdk/go
GOWORK=off go test ./...
```

## Source Layout

- `client/client.go` is the hand-maintained HTTP wrapper over the OpenAPI
  routes.
- `client/types_gen.go` contains OpenAPI-derived model types.
- `client/execution_boundary.go` contains the May 2026 execution-boundary
  helper methods.
- `gen/` contains protobuf bindings generated from `protocols/proto/`.

The HTTP wrapper itself uses Go standard-library `net/http` and
`encoding/json`. The module also declares protobuf and gRPC dependencies for
the generated bindings in `gen/`.

## Quick Example

```go
package main

import (
    "fmt"
    "log"

    helm "github.com/Mindburn-Labs/helm-oss/sdk/go/client"
)

func main() {
    c := helm.New("http://port 3000")

    // Chat completions via the HELM boundary.
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
| --- | --- |
| `ChatCompletions(req)` | `POST /v1/chat/completions` |
| `ApproveIntent(req)` | `POST /api/v1/kernel/approve` |
| `ListSessions(limit, offset)` | `GET /api/v1/proofgraph/sessions` |
| `GetReceipts(sessionID)` | `GET /api/v1/proofgraph/sessions/{id}/receipts` |
| `ExportEvidence(sessionID)` | `POST /api/v1/evidence/export` |
| `VerifyEvidence(bundle)` | `POST /api/v1/evidence/verify` |
| `CreateEvidenceEnvelopeManifest(req)` | `POST /api/v1/evidence/envelopes` |
| `ConformanceRun(req)` | `POST /api/v1/conformance/run` |
| `ListNegativeConformanceVectors()` | `GET /api/v1/conformance/negative` |
| `ListConformanceVectors()` | `GET /api/v1/conformance/vectors` |
| `ListMCPRegistry()` | `GET /api/v1/mcp/registry` |
| `DiscoverMCPServer(req)` | `POST /api/v1/mcp/registry` |
| `ApproveMCPServer(req)` | `POST /api/v1/mcp/registry/approve` |
| `GetBoundaryStatus()` | `GET /api/v1/boundary/status` |
| `ListBoundaryCapabilities()` | `GET /api/v1/boundary/capabilities` |
| `ListBoundaryRecords(query)` | `GET /api/v1/boundary/records` |
| `VerifyBoundaryRecord(recordID)` | `POST /api/v1/boundary/records/{id}/verify` |
| `ListSandboxBackendProfiles()` | `GET /api/v1/sandbox/grants/inspect` |
| `InspectSandboxGrant(runtime, profile, policyEpoch)` | `GET /api/v1/sandbox/grants/inspect` |
| `Health()` | `GET /healthz` |
| `Version()` | `GET /version` |

## Release Notes

`0.5.0` is the cleaned OSS kernel baseline with the public HTTP client surface, conformance entrypoints, and evidence verification helpers.
