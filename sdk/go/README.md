# HELM SDK - Go

Typed Go client for the HELM kernel HTTP API.

## Install

After the `sdk/go/v0.7.2` subdirectory tag is published and verified:

```bash
go get github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v0.7.2
```

Version truth is the repository `VERSION` file (`0.7.2` for this source target).
Tagged Go module releases use the subdirectory tag form `sdk/go/v0.7.2`; this
source target does not claim that the tag already exists.

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
    "os"

    helm "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/client"
)

func main() {
    c := helm.New(
        "http://127.0.0.1:7714",
        helm.WithAPIKey(os.Getenv("HELM_ADMIN_API_KEY")),
        helm.WithTenantID("tenant-a"),
        helm.WithPrincipalID("operator-a"),
    )

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

    // Canonical evaluator body; identity is configured above, not in JSON.
    decision, err := c.EvaluateDecision(helm.DecisionRequest{
        Action:   "EXECUTE_TOOL",
        Resource: "local.echo",
        Context:  map[string]interface{}{"request_id": "request-123"},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(decision.Verdict)
}
```

`EvaluateDecision` requires API key, tenant ID, and principal ID. Set
`WithWorkspaceID` as well when a scoped emergency-stop fence is active. The
body never accepts principal, tenant, workspace, or legacy evaluator fields.

## API

| Method | Endpoint |
| --- | --- |
| `ChatCompletions(req)` | `POST /v1/chat/completions` |
| `ChatCompletionsWithReceipt(req)` | `POST /v1/chat/completions` plus `X-Helm-*` governance headers |
| `EvaluateDecision(req)` | `POST /api/v1/evaluate` |
| `RunPublicDemo(actionID, args)` | `POST /api/demo/run` |
| `VerifyPublicDemoReceipt(receipt, expectedHash)` | `POST /api/demo/verify` |
| `ApproveIntent(req)` | `POST /api/v1/kernel/approve` |
| `ListSessions(limit, offset)` | `GET /api/v1/proofgraph/sessions` |
| `GetReceipts(sessionID)` | `GET /api/v1/proofgraph/sessions/{id}/receipts` |
| `GetReceipt(receiptHash)` | `GET /api/v1/proofgraph/receipts/{hash}` |
| `ExportEvidence(sessionID)` | `POST /api/v1/evidence/export` |
| `VerifyEvidence(bundle)` | `POST /api/v1/evidence/verify` |
| `ReplayVerify(bundle)` | `POST /api/v1/replay/verify` |
| `CreateEvidenceEnvelopeManifest(req)` | `POST /api/v1/evidence/envelopes` |
| `ConformanceRun(req)` | `POST /api/v1/conformance/run` |
| `GetConformanceReport(reportID)` | `GET /api/v1/conformance/reports/{id}` |
| `ListConformanceReports()` | `GET /api/v1/conformance/reports` |
| `ListNegativeConformanceVectors()` | `GET /api/v1/conformance/negative` |
| `ListConformanceVectors()` | `GET /api/v1/conformance/vectors` |
| `ListMCPRegistry()` | `GET /api/v1/mcp/registry` |
| `DiscoverMCPServer(req)` | `POST /api/v1/mcp/registry` |
| `ApproveMCPServer(req)` | `POST /api/v1/mcp/registry/approve` |
| `GetBoundaryStatus()` | `GET /api/v1/boundary/status` |
| `ListBoundaryCapabilities()` | `GET /api/v1/boundary/capabilities` |
| `ListBoundaryRecords(query)` | `GET /api/v1/boundary/records` |
| `VerifyBoundaryRecord(recordID)` | `POST /api/v1/boundary/records/{id}/verify` |
| `ListBoundaryCheckpoints()` | `GET /api/v1/boundary/checkpoints` |
| `CreateBoundaryCheckpoint()` | `POST /api/v1/boundary/checkpoints` |
| `VerifyBoundaryCheckpoint(checkpointID)` | `POST /api/v1/boundary/checkpoints/{id}/verify` |
| `ListSandboxBackendProfiles()` | `GET /api/v1/sandbox/grants/inspect` |
| `InspectSandboxGrant(runtime, profile, policyEpoch)` | `GET /api/v1/sandbox/grants/inspect` |
| `Health()` | `GET /healthz` |
| `Version()` | `GET /version` |

## Release Notes

`0.7.2` is the release-hardening patch with the public HTTP client surface, conformance entrypoints, and evidence verification helpers.
