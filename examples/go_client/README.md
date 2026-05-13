# Go Client Example

Shows HELM integration with the Go SDK.

## Prerequisites

- HELM running at `http://127.0.0.1:7714` (`docker compose up -d`)
- Go 1.25+

## Source Example

`main.go` is a small integration source file that imports
`github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/client`. This directory does not
carry its own `go.mod`; use it as source material for a service module or run
the SDK package gate below.

## Expected Output

The example prints sections for chat completions, evidence export,
conformance, and health. The exact verdict, reason code, byte count, and
version depend on the policy and HELM server you run locally.

## Validation

The Go SDK package is validated from the repository root with:

```bash
make test-sdk-go-standalone
```
