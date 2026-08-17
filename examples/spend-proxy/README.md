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
- `dogfood.do-gradient.config.json` — the HELM-618 DigitalOcean Gradient
  serverless-inference price book and paired-replay envelope set (baseline
  `openai-gpt-oss-120b` plus three substitute-candidate envelopes). Prices from
  <https://docs.digitalocean.com/products/inference/details/pricing/> (page
  updated 2026-08-15, captured 2026-08-17). Run against
  `--upstream https://inference.do-ai.run/v1` with a DigitalOcean model access
  key in `HELM_SPEND_PROXY_UPSTREAM_KEY`.
- `paired-replay/` — the standalone HELM-618 capture runner and its committed
  task set (`tasks.json`, selection/holdout split fixed in-repo). It drives
  each task through the proxy once per envelope with deterministic
  `X-HELM-Idempotency-Key`s and records `task_results.json` /
  `parity_prerun.json` for `spend-proxy savings-export`. Responses are stored
  as SHA-256 only — no prompt or answer bodies leave the capture machine.

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

## Savings EvidencePack (HELM-614 methodology)

A paired capture (parity pre-run on the selection set, a committed selection
freeze, then the holdout set through the baseline and the frozen substitute)
exports as ONE savings EvidencePack with a recomputable
`views/savings_view.json` — cost-per-successful-task per route, the strict
parity bar, and the savings claim bound to capture-window prices:

```bash
helm-ai-kernel spend-proxy savings-export \
  --receipts-dir ./helm-spend-receipts \
  --capture ./capture \
  --config examples/spend-proxy/dogfood.do-gradient.config.json \
  --out ./helm-spend-evidence
```

`--capture` holds `task_split_manifest.json` (task ids, selection/holdout
assignment, the frozen substitute choice), `task_results.json`, and
`parity_prerun.json` — the paired-replay runner produces the latter two. The
export refuses unattributed settled spend on the capture envelopes and
offline-verifies the pack before writing it. A skeptic re-verifies with no
receipts dir, ledger, or network:

```bash
helm-ai-kernel spend-proxy savings-verify --pack ./helm-spend-evidence/savingspack-<run-id>
```
