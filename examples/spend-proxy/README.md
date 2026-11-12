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
  from this file alone. The `openai/gpt-4o*` rows were captured manually from
  <https://openrouter.ai/models> on 2026-08-17; the `openai/gpt-6-sol` and
  `openai/gpt-6-luna` rows, which the envelopes now route to, come from
  <https://developers.openai.com/api/docs/pricing> on 2026-09-25. Re-capture and
  update this file (the hash changes with it) when prices move.
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

The proxy listens on `127.0.0.1:9095`. `--addr` takes a loopback address only:
the proxy serves plain HTTP and spends the upstream key, so it refuses to start
on a non-loopback address, with or without caller credentials (`controls.yaml`
CTL-026).

Point any OpenAI-compatible client at the proxy:

```bash
export OPENAI_BASE_URL=http://127.0.0.1:9095/v1
```

### Who a request acts for

Without caller credentials the proxy serves exactly one principal: every
envelope in the config must name the same `principal_id` (a config with more
does not load), the `X-HELM-*` headers pick among its envelopes, and the only
`X-HELM-Workspace` a request may name is `request_defaults.workspace_id`
(another gets 403, so a header value never reaches a signed quote).

To serve several principals, bind each caller to its identity with `callers`
(and leave `request_defaults` out). The config holds the SHA-256 of each
caller's token, never the token; a caller presents the token as its bearer
(`OPENAI_API_KEY=<token>` in an OpenAI SDK):

```json
"callers": [
  {"id": "ci", "token_sha256": "<sha256 hex of the token>", "agent_id": "agent-live-traffic",
   "envelopes": ["env-baseline"], "workspaces": ["ws-dogfood"]}
]
```

```bash
printf %s "$TOKEN" | shasum -a 256   # the token_sha256 value
```

A request without a configured token gets 401 (`helm_caller_credential`). An
`X-HELM-Agent`, `X-HELM-Spend-Envelope` or `X-HELM-Workspace` its caller does
not cover gets 403 (`helm_caller_scope`); an absent one takes the caller's
agent, its first envelope and its first workspace. `/v1/models` needs the
token too; `/helm/spend/health` does not.

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
  -d '{"model":"openai/gpt-6-sol","max_tokens":512,"messages":[{"role":"user","content":"..."}]}'

# Substitute route: same requested model, envelope substitutes and the
# RouteQuote records model_substituted=true.
curl -X POST http://127.0.0.1:9095/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-HELM-Agent: agent-paired-replay' \
  -H 'X-HELM-Spend-Envelope: env-substitute' \
  -H 'X-HELM-Idempotency-Key: task-001-substitute' \
  -d '{"model":"openai/gpt-6-sol","max_tokens":512,"messages":[{"role":"user","content":"..."}]}'
```

Every chat request must set `max_tokens` (or `max_completion_tokens`), and
`/v1/responses` must set `max_output_tokens`; requests without one get 400.
A request is read against the model gateway's closed list for its route
(`core/pkg/gateway/modelbound`, listed in `docs/architecture/model-gateway.md`):
stored state (`previous_response_id`, `conversation`, a stored `prompt`,
`store: true`, a reasoning item without `encrypted_content`, an input item
named by its id alone), remote or uploaded media, a data URL that is not an
image, hosted tools, `web_search_options`, `background: true`, `n` other than
1, the routing members `models`, `provider`, `plugins` and `route`, a
`service_tier` other than `default` or `flex` (`auto` too: its meaning is the
upstream account's), a repeated key and any member the list does not name are
refused with 400, naming it. A Responses request that names no `store` is sent
with `store: false`.

The hold counts one input token per byte of the forwarded request, plus a
floor for each inline image and each tool definition the provider adds, and
the output ceiling. The proxy lowers the ceiling to what the envelope can still
pay for, reserves the hold against the envelope's `max_amount_cents` for the
day and the balance in one step, and forwards the ceiling to the provider; a
request the envelope can no longer cover gets 403 `ERR_BALANCE_INSUFFICIENT`.
A provider that bills above the hold anyway is debited what it billed: the
usage receipt says `ESCALATE` / `ERR_SPEND_PER_REQUEST_LIMIT` with
`overage_cents` and `envelope_closed`, an `ALERT` is logged, and the envelope
refuses further requests (403 `ERR_SPEND_ENVELOPE_INACTIVE`) until the next UTC
day, also across a restart.

An answer is priced by the model it names: the quoted model, or its id with a
dated suffix (`-2024-07-18`, `-20250514`), at its usage; no model, or the quoted
id with another suffix, at its usage too, recording `model_mismatch`
(`no_model`, `version_suffix`); another model at the dearer of the two prices,
or at least the hold when the price book does not have it, recording
`response_model` and `model_mismatch: true`.

A dispatch that may have reached the provider is never released: a transport
error after the connection opened, a timeout, an error status, a body cut after
the status line or usage the proxy cannot read is debited at its whole hold
(`settled_at_hold` on the usage receipt). A client that disconnects does not
cancel the provider call; it settles on what the provider reports. Only a
failure before any request byte left the proxy frees the hold. A dispatch
journalled before its provider call and never settled, because the process
stopped (or whose usage line never reached the log), is held again on the next
start, pending reconciliation, and the start banner prints `pending:` with an
`ALERT` naming its intent.

To clear a pending hold, stop the proxy, check the provider's console for the
call, and reconcile it with the proxy's own signing seed:

```bash
helm-ai-kernel spend-proxy reconcile --config <config> --receipts-dir <dir>   # lists pending intents
helm-ai-kernel spend-proxy reconcile --config <config> --receipts-dir <dir> \
  --intent <si-...> --settle-cents 3 --reason "provider console shows the call"
helm-ai-kernel spend-proxy reconcile --config <config> --receipts-dir <dir> \
  --intent <si-...> --release --reason "the provider has no such request"
```

`--settle-cents` settles the dispatch at that provider cost (the platform fee
is added), as usage and settlement lines whose usage receipt carries
`reconciled_by` and `reconcile_reason`; `--release` frees the hold with a
`dispatch_released` line whose route quote carries `release_reason`. Both are
signed by the issuer key, which must be the one that signed the dispatch
(`--sign` or `HELM_SPEND_PROXY_SIGNING_SEED`), and the next start replays them.
Exit 0 on success, 2 on a usage or config error, 1 when the intent is not
pending or a line cannot be signed and appended.

An `X-HELM-Idempotency-Key` that already settled, or is held, is never sent
upstream again: an identical retry gets the original response while the proxy
still holds it, and any other reuse (or a replay after a restart) gets 409.

The principal a spend receipt names is the envelope's `principal_id`. An
`X-HELM-Principal` header may repeat it; a request that names another principal
is refused with 403.

Streaming is not served: a request with `"stream": true` is refused with 403
(`helm_data_egress_blocked`); the proxy returns buffered responses only.

## Evidence

Every dispatch appends RouteQuote / BudgetVerdict / Usage / Settlement lines to
`<receipts-dir>/spend-receipts.jsonl` (the quote is fsynced before the provider
is called; a store failure refuses dispatch). Export offline-verifiable spend
EvidencePacks:

```bash
helm-ai-kernel spend-proxy export \
  --receipts-dir ./helm-spend-receipts \
  --out ./helm-spend-evidence \
  --public-key ed25519:<hex printed by spend-proxy at start>
```

Each pack re-verifies offline (canonical content hashes, financial invariants,
prompt-body-off-graph). With `--public-key`, export also verifies every
signature of each intent against that key: the detached signature of each
receipt line and the BudgetVerdict seal, listed in `signatures_checked`; an
unsigned line, another key or a signature that does not verify fails the
export. Take the key from the proxy's start banner or its
`/helm/spend/health` (`signing_public_key`), not from the receipts directory:
`<receipts-dir>/trusted_keys.json` is written by the process whose receipts it
would vouch for. Without `--public-key` no signature is checked and the summary
says so (`signature_verified: false`).

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
helm-ai-kernel spend-proxy savings-verify --pack ./helm-spend-evidence/savingspack-<run-id> \
  --issuer-key-id <issuer-key-id> --issuer-public-key <issuer-public-key-hex>
```

Pin the issuer key out of band. Without the issuer flags the result is
`UNVERIFIABLE (self-attested)` and the command exits 1, because the pack's
own key registry cannot vouch for the pack.
