# spend-proxy example

<!-- quantum_posture: describes the classical Ed25519 verdict-signing flow
implemented in core/pkg/spendproxy; this document adds no cryptographic
surface of its own. -->

Reference configuration for `helm-ai-kernel spend-proxy`, the locally runnable
governed inference proxy: OpenAI-compatible routes over the SPEND3 RouteQuote
engine with a real cloud provider dispatch, Ed25519-signed BudgetVerdict
receipts, and durable JSONL receipt persistence.

## Files

- `dogfood.config.json` — the HELM-615 dogfood price book and envelope set.
  The sha256 of the raw file bytes is the price-source hash bound into every
  quote and receipt, so the exact prices behind a capture window are provable
  from this file alone. Prices were captured manually from
  <https://openrouter.ai/models> on 2026-08-17; re-capture and update this file
  (the hash changes with it) when prices move.

## Run

```bash
export OPENROUTER_API_KEY=sk-or-...
helm-ai-kernel spend-proxy \
  --config examples/spend-proxy/dogfood.config.json \
  --receipts-dir ./helm-spend-receipts
```

Point any OpenAI-compatible client at the proxy:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9095/v1
```

Requests without `X-HELM-*` headers are governed under the config's
`request_defaults` envelope. To capture the paired baseline-vs-substitute run,
send the same task with explicit headers against each envelope:

```bash
# Baseline route: requested model dispatches as-is.
curl -X POST http://127.0.0.1:9095/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-HELM-Agent: agent-live-traffic' \
  -H 'X-HELM-Spend-Envelope: env-baseline' \
  -H 'X-HELM-Idempotency-Key: task-001-baseline' \
  -d '{"model":"openai/gpt-4o","messages":[{"role":"user","content":"..."}]}'

# Substitute route: same requested model, envelope substitutes and the
# RouteQuote records model_substituted=true.
curl -X POST http://127.0.0.1:9095/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-HELM-Agent: agent-paired-replay' \
  -H 'X-HELM-Spend-Envelope: env-substitute' \
  -H 'X-HELM-Idempotency-Key: task-001-substitute' \
  -d '{"model":"openai/gpt-4o","messages":[{"role":"user","content":"..."}]}'
```

Streaming (`"stream": true`) is supported on `/v1/chat/completions`; the SSE
bytes pass through verbatim and settlement uses the final usage chunk.

## Evidence

Every dispatch appends RouteQuote / BudgetVerdict / Usage / Settlement lines to
`<receipts-dir>/spend-receipts.jsonl` (the quote is fsynced before the provider
is called; a store failure refuses dispatch). Export offline-verifiable spend
EvidencePacks:

```bash
helm-ai-kernel spend-proxy export \
  --receipts-dir ./helm-spend-receipts \
  --out ./helm-spend-evidence
```

Each pack re-verifies offline (canonical content hashes, financial invariants,
prompt-body-off-graph) and the BudgetVerdict signature is checked against the
trusted-key registry at `<receipts-dir>/trusted_keys.json`.
