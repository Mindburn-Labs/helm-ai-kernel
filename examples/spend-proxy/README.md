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
TOKEN=$(openssl rand -hex 32)          # 32 random bytes, as 64 hex digits
printf %s "$TOKEN" | shasum -a 256     # the token_sha256 value
```

A token must be at least 32 bytes; generate it as above, from a random
source, never from a word or a name. The config holds its unsalted SHA-256:
for a random 32-byte token that is out of reach of a guess, so a keyed hash
would add nothing but a key to keep beside the config. A shorter token gets
401 at its first use, so a config that hashed one shows at once.

A request without a configured token gets 401 (`helm_caller_credential`); the
`Bearer` scheme is matched in any case. An `X-HELM-Agent`,
`X-HELM-Spend-Envelope` or `X-HELM-Workspace` its caller does not cover gets
403 (`helm_caller_scope`); an absent one takes the caller's agent, its first
envelope and its first workspace, so a stock OpenAI client with the token as
its API key and no `X-HELM-*` header is served. `/v1/models` and
`/helm/spend/health` (which shows the balance, the upstream, the receipt log
path and the signing key) need the token too. An `X-HELM-Idempotency-Key` is
the caller's own: two callers may use the same key, and neither learns the
other did.

Requests without `X-HELM-*` headers are governed under the config's
`request_defaults` envelope. A request without `X-HELM-Idempotency-Key`, or
with one that is only whitespace, gets a fresh key, in either mode, so each
such request is a new spend and a retry of it is another one. To capture the
paired baseline-vs-substitute run,
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
upstream account's), a repeated key, a `stream` that is not a boolean,
Responses `instructions` that are not a string, and any member of the request,
of a message, an input item or a content part that the list does not name are
refused with 400, naming it. `cache_control` is refused at any depth: the price
book has no cache-write price, and a prompt-cache write bills above the input
price. A Responses request that names no `store` is sent with `store: false`.

The hold counts one input token per byte of the forwarded request, plus a
floor for each inline image and each tool definition the provider adds, and
the output ceiling, at the configured price, with the `platform_fee_bps` fee on
it rounded up. The proxy lowers the ceiling to what the envelope can still pay
for, fee included, reserves the hold against the envelope's `max_amount_cents`
for the day and the balance in one step, and forwards the ceiling to the
provider; a request the envelope can no longer cover gets 403
`ERR_BALANCE_INSUFFICIENT`. A dispatch is debited the usage the provider
reports, priced at the configured price, and the fee; a provider that reported
no more than its part of the hold is debited no more than the hold. One that
reports more is debited all of it: the usage receipt says `ESCALATE` /
`ERR_SPEND_PER_REQUEST_LIMIT` with `overage_cents` (the debit above the hold,
fee included), `envelope_closed` and `envelope_closed_windows`, an `ALERT` is
logged, and the envelope refuses
further requests (403 `ERR_SPEND_ENVELOPE_INACTIVE`) in the UTC day of the
reservation and the day of the settlement, until the day after. That holds when
the balance cannot cover the bill and the settlement fails too (the
`settle_failed` line records the actual cost, the overage and the closed days,
signed), and across a restart, which closes the days the receipts name, also
when the usage line or the settlement line of the overage never reached the
log: the settlement line names the closed days too, and a line whose debit
exceeds its hold closes the day its dispatch was journalled.

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
stopped (or whose usage or settlement line never reached the log), is held
again on the next start, pending reconciliation, at its hold or at the actual
cost the log records when that is more, and the start banner prints
`pending:` with an `ALERT` naming its intent.

To clear a pending hold, stop the proxy (reconcile takes the receipts
directory's lock, which a running proxy holds, and refuses while it is held;
a second proxy on the same directory refuses to start for the same reason),
check the provider's console for the call, and reconcile it with the proxy's
own signing seed:

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
`dispatch_released` line whose signed route quote carries `release_reason`
and `release_action: dispatch_released/v1`. The outer tenant and intent must
match that signed quote. A journal relabeled as a release, a redirected
release, or an unversioned/unknown release action is refused by startup and
export; a payload signature alone does not authorize those actions. Both are
signed by the key of the seed (`--sign` or `HELM_SPEND_PROXY_SIGNING_SEED`, or
without either the seed the proxy generated in the receipts directory), and
the next start replays them. That key should be the one that signed the
dispatch. When another key signed it, because the seed was lost or changed or
an earlier version run without `--sign` signed each run with a new key, start
the proxy once under the current seed, which registers its key in
`trusted_keys.json`, stop it and reconcile with that seed: reconcile signs for
the dispatch when `trusted_keys.json` registers both keys and the journal line
verifies against the old one, or, when the registry no longer has the old key
and that key signed only journal lines, with `--journal-key-reason "<why>"`. A
log in which the old key also signed usage, settlement, release or
settle_failed lines does not start without it: restore the old public key to
`trusted_keys.json` (it is in the old start banner and in `/helm/spend/health`)
first. The line records the old key as
`reconcile_journal_key_id`, and the reason as `reconcile_journal_key_reason`;
a start logs a `WARNING` for each pending dispatch another key journalled.
When the log records that the provider billed the dispatch (a `settle_failed`
line, or a usage or settlement line without its pair), `--release` is
refused, and `--settle-cents` must debit at least the actual cost recorded
unless `--override-reason` says why; the override is recorded and signed on
the usage receipt as `reconcile_override_reason`. A settlement above the
balance fails as any debit does: raise `balance.opening_cents` in the config
first. A failed settlement retains its known actual liability against the
balance and envelope, both live and after restart, even when neither a usage
nor a settlement line was committed. An unfunded recovery hold permits no
debit beyond the balance remaining after other holds; it does not create funds.
Exit 0 on success, 2 on a usage or config error, 1 when the intent is
not pending, the seed is missing, not a regular file or readable by others,
the dispatch's key is one reconcile may not sign for, a proxy holds the
directory (the list form, without `--intent`, runs beside a proxy), the log's
record of the bill refuses the action, or a line cannot be signed and
appended. `--json` prints
`spend_intent_id`, `action`, `hold_cents`, `debited_cents`, `reason`, and
`recorded_actual_cents` and `override_reason` when they apply.

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
is called; a store failure refuses dispatch). Each line is signed with the
issuer key: the `--sign` seed, or without one a seed the proxy generates on
its first start in `<receipts-dir>/signing-seed` (mode 0600, printed in the
start banner as `signing seed:`), so restarts and reconcile sign with one key.
Whoever can read that file can sign receipt lines; pass `--sign` to keep the
seed elsewhere; the file must be a regular file, not a link. A start refuses a
log whose usage, settlement, `dispatch_released` or `settle_failed` line is
unsigned, or signed by a key that is neither the proxy's nor one the
directory's `trusted_keys.json` registered, or whose signature does not
verify, naming the line. Export offline-verifiable spend
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
export. Repeat `--public-key` for a log signed by more than one key, as after
a reconcile under a new seed: each signature is checked against the key its
key id names, and `signature_key_ids` lists the keys that signed an intent.
Take the key from the proxy's start banner or its
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
