<!-- quantum_posture: offline receipt.v5 verification is classical Ed25519 only; no post-quantum protection is claimed. -->

# HELM SDK - Go

Typed Go client for the HELM kernel HTTP API.

## Install

After the `sdk/go/v0.12.0` subdirectory tag is published and verified:

```bash
go get github.com/Mindburn-Labs/helm-ai-kernel/sdk/go@v0.12.0
```

Version truth is the repository `VERSION` file (`0.12.0` for this source target).
Tagged Go module releases use the subdirectory tag form shown above; this
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

    req := helm.NewEvaluateRequest()
    req.SetTool("read-ticket")
    req.SetEffectLevel("ticket:123")
    req.SetSessionId("example-session")

    decision, err := c.EvaluateDecisionV5(*req)
    if err != nil {
        if apiErr, ok := err.(*helm.HelmApiError); ok {
            log.Fatalf("refused: %d %s", apiErr.Status, apiErr.ReasonCode)
        }
        log.Fatal(err)
    }
    fmt.Println(decision.Verdict, decision.ReceiptId) // ALLOW, DENY or ESCALATE
}
```

`/api/v1/evaluate` needs the API key and the tenant and principal the server is
configured for; without them the call returns 401.

`ChatCompletions` posts to `/v1/chat/completions`. `helm-ai-kernel serve`
answers that route with 403 before any upstream is called, because its Guardian
allows no egress destination (`controls.yaml` CTL-047). Send OpenAI-shaped
traffic through `helm-ai-kernel proxy` instead.

## API

| Method | Endpoint |
| --- | --- |
| `ChatCompletions(req)` | `POST /v1/chat/completions` |
| `ChatCompletionsWithReceipt(req)` | `POST /v1/chat/completions` plus `X-Helm-*` governance headers |
| `EvaluateDecision(req)` | Legacy dynamic `POST /api/v1/evaluate` request/response; deprecated for new integrations |
| `EvaluateDecisionV5(EvaluateRequest)` | Typed `POST /api/v1/evaluate`; requires non-blank `tool`, `effect_level`, and `session_id` |
| `RunPublicDemo(actionID, args)` | `POST /api/demo/run` |
| `VerifyPublicDemoReceipt(receipt, expectedHash)` | `POST /api/demo/verify` |
| `ListSessions(limit, offset)` | `GET /api/v1/proofgraph/sessions` |
| `GetReceipts(sessionID)` | `GET /api/v1/proofgraph/sessions/{id}/receipts` |
| `GetReceipt(receiptHash)` | `GET /api/v1/proofgraph/receipts/{hash}` |
| `ExportEvidence(sessionID)` | `POST /api/v1/evidence/export` |
| `VerifyEvidence(bundle)` | `POST /api/v1/evidence/verify` |
| `CreateEvidenceEnvelopeManifest(req)` | `POST /api/v1/evidence/envelopes` |
| `ListNegativeConformanceVectors()` | `GET /api/v1/conformance/negative` |
| `ListConformanceVectors()` | `GET /api/v1/conformance/vectors` |
| `ListMCPRegistry()` | `GET /api/v1/mcp/registry` |
| `DiscoverMCPServer(req)` | `POST /api/v1/mcp/registry` |
| `GetBoundaryStatus()` | `GET /api/v1/boundary/status` |
| `ListBoundaryCapabilities()` | `GET /api/v1/boundary/capabilities` |
| `ListBoundaryRecords(query)` | `GET /api/v1/boundary/records` |
| `ListBoundaryCheckpoints()` | `GET /api/v1/boundary/checkpoints` |
| `CreateBoundaryCheckpoint()` | `POST /api/v1/boundary/checkpoints` |
| `ListSandboxBackendProfiles()` | `GET /api/v1/sandbox/grants/inspect` |
| `InspectSandboxGrant(runtime, profile, policyEpoch)` | `GET /api/v1/sandbox/grants/inspect` |
| `Health()` | `GET /healthz` |
| `Version()` | `GET /version` |

## Offline receipt verification

```go
raw, err := helm.GetReceiptJSON(receiptID)
if err != nil { return err }
result := client.VerifyReceipt(raw, trustedPublicKeyHex)
if !result.Valid { return fmt.Errorf("receipt: %s", result.Detail) }
fmt.Println(result.Verdict, result.Signed)
```

The verifier checks the classical Ed25519 signature of one `receipt.v5`
envelope using public keys supplied by the caller. It makes no network request.
Pass the original JSON bytes: decoding and re-encoding can hide duplicate members
and change number spellings. Invalid UTF-8, duplicate names, typed member-name
case aliases, nesting beyond 64 containers and non-interoperable clock values
are refused. Legacy, hybrid and post-quantum signatures are not supported.

Only the thirteen members returned in the signed-field map are authenticated.
`key_id`, timestamps, tool names and other metadata are unsigned claims; their
schemas are not validated by this function. A successful result does not establish
chain closure, permits or gateway bindings. Use `receipt_verify` for those
additional checks. Neither verifier attests that an external effect actually
executed. Obtain trusted public keys independently of the
receipt; an embedded key or a key fetched from its producer is not a trust root.

## Source target

This source target includes the canonical typed evaluation contract and signed
receipt v5 fields. Verify the tag and registry evidence before treating its
module coordinate as published.
