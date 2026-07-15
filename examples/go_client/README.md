# Go Client Example

Shows HELM integration with the Go SDK.

## Prerequisites

- Go 1.25+
- A governed `helm-ai-kernel serve` runtime with a permitted `LLM_INFERENCE`
  policy and an OpenAI-compatible upstream. This is not the standalone
  `helm-ai-kernel proxy` sidecar.

For a local mock upstream, run this in one terminal:

```bash
python3 scripts/launch/mock-openai-upstream.py --port 19090
```

Then start the governed runtime in another terminal. `HELM_UPSTREAM_URL` may
be a provider base URL with or without `/v1`. `HELM_UPSTREAM_API_KEY` is a
server-owned provider credential and must be distinct from the runtime admin key.

```bash
HELM_ADMIN_API_KEY=local-admin-key \
HELM_RUNTIME_TENANT_ID=default \
HELM_RUNTIME_PRINCIPAL_ID=example-agent \
HELM_UPSTREAM_URL=http://127.0.0.1:19090 \
HELM_UPSTREAM_API_KEY=local-upstream-key \
./bin/helm-ai-kernel serve --policy <policy-that-permits-LLM_INFERENCE>
```

Set matching client bindings before running the example:

```bash
export HELM_URL=http://127.0.0.1:7714
export HELM_ADMIN_API_KEY=local-admin-key
export HELM_TENANT_ID=default
export HELM_PRINCIPAL_ID=example-agent
export HELM_SESSION_ID=example-session
```

If the emergency-stop fence is enabled, also set matching server and client
workspace bindings with `HELM_RUNTIME_WORKSPACE_ID` and `HELM_WORKSPACE_ID`.

## Source Example

`main.go` is a small integration source file that imports
`github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/client`. The local `go.mod`
pins the example to the repository SDK module through a local `replace`, so
tooling can build the example without publishing an SDK release first.

Run it from this directory after configuring the environment above:

```bash
go run .
```

## Expected Output

The example prints sections for chat completions, evidence export,
conformance, and health. The exact verdict, reason code, byte count, and
version depend on the policy and HELM server you run locally.

## Validation

The Go SDK package is validated from the repository root with:

```bash
make test-sdk-go-standalone
```

The example module can also be compiled directly:

```bash
go test ./examples/go_client/... -run '^$'
```
