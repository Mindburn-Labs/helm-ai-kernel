# Governed Local Inference

Put HELM in front of a local model server so every inference and tool call is
allowed, denied, or escalated — and each decision leaves a signed, hash-chained
receipt. This is the integration for a sealed or air-gapped host, where the
appliance routes all agent traffic through one boundary.

The example uses a local mock model server so it runs anywhere. Point it at a
real runtime with `HELM_UPSTREAM` (Ollama, vLLM, llama.cpp, LM Studio, …).

## Prerequisites

- Go toolchain (the script runs `make build`)
- Python 3 and `curl`

## Run

```bash
examples/governed_local_inference/run.sh
```

Against a real local runtime:

```bash
HELM_UPSTREAM=http://127.0.0.1:11434/v1 examples/governed_local_inference/run.sh   # Ollama
HELM_UPSTREAM=http://127.0.0.1:8000/v1  examples/governed_local_inference/run.sh   # vLLM
```

## What It Does

1. Builds the kernel and starts a local OpenAI-compatible model server.
2. Starts `helm-ai-kernel proxy` in front of it with receipt signing on.
3. Sends a safe chat request — HELM allows it and records an `APPROVED` receipt.
4. Sends a request whose upstream reply asks to call a tool — HELM returns `403`
   with `X-Helm-Status: DENIED`, redacts the `tool_calls` from the body so the
   caller cannot act on them, and records a `DENIED` receipt.
5. Verifies the receipt chain offline with `verify_chain.py` — no HELM binary
   and no network — by re-linking each receipt's `prev_hash` to the SHA-256 of
   the previous line and confirming the signatures are present.

## Expected Output

- The safe request returns the upstream reply.
- The tool-call request returns HTTP `403` with `X-Helm-Status: DENIED`.
- Two receipts: one `APPROVED`, one `DENIED`.
- `verify_chain.py` reports the chain intact with every receipt signed.

For a full, exportable proof, export an EvidencePack and check it with
`helm-ai-kernel verify <pack>` — see
[Export And Verify EvidencePacks](../../docs/guides/export-verify-evidencepacks.md)
and the [sealed / air-gapped host guide](../../docs/guides/air-gap-appliance.md).

## Source

- `run.sh` — the end-to-end flow
- `verify_chain.py` — offline receipt-chain integrity check
- `core/cmd/helm-ai-kernel/proxy_cmd.go` — the governed proxy and receipt store
- `scripts/launch/mock-openai-upstream.py` — the local mock model server
