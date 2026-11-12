# Model gateway (HELM-752)

<!-- quantum_posture: this note describes request digests (SHA-256) and bearer
tokens verified by the gateway's existing identity configuration. It adds no
cryptographic control and makes no post-quantum claim. -->

Status: served by `helm-gateway serve` when `HELM_GATEWAY_MODEL_ROUTES_FILE` is
set. One gateway for every model call, beside the effect gateway it is built on
([Gateway effect API](gateway-effect-api.md)). Unmodified clients (the OpenAI
and Anthropic SDKs, Claude Code and the Claude Agent SDK, the OpenAI Agents SDK,
Codex) point their base URL at it and speak their own API. Code:
`core/pkg/gateway/modelgw`, `core/pkg/gateway/custody/providerkeys.go`,
`core/pkg/gateway/runtime/runtime.go`.

## Endpoints

| Endpoint | Client | Rules |
|---|---|---|
| `POST /v1/responses` | OpenAI Responses: Codex, the OpenAI Agents SDK | HTTP and server-sent events. Tool types `function`, `custom`, `local_shell` and `apply_patch` only. |
| `POST /v1/chat/completions` | OpenAI Chat Completions: LangGraph's `ChatOpenAI`, any OpenAI-compatible client | Function tools only; `n` must be 1. A stream asks the provider for a usage chunk, which the gateway strips before the client sees it when the client did not ask for it. |
| `POST /v1/messages` (also `?beta=true`) | Anthropic Messages: Claude Code, the Claude Agent SDK, `ChatAnthropic` | Custom tools and the schema-less client tools (`bash_*`, `text_editor_*`, `computer_*`, `memory_*`). `anthropic-version` and `anthropic-beta` are forwarded on this API only (a default version is set when absent); errors come back in Anthropic's shape. |
| `POST /v1/messages/count_tokens` | discovery | 404: clients estimate their own tokens. |
| `GET /v1/models` | discovery | The routes the caller may use. |

A request must be `application/json`. Each API's native request and response
pass through unchanged, except the maximum output tokens: the gateway injects the
route's default when the request names none and clamps a larger value. A request
that asks for something the provider would run on its own account is refused
with 400 before any attempt exists: a tool type outside the lists above (web
search and fetch, file search, code interpreter, image generation, code
execution, an MCP toolset and the rest), a `tool_choice` that names one,
`web_search_options`, `mcp_servers`, a code execution container and
`background: true`. A tool the agent runs itself is allowed: its calls take
effect only through the gateway's own tools, which the sandbox's network rules
enforce.

A request is also read against a closed list of what the quote understands
(`core/pkg/gateway/modelbound`, which the spend proxy's governed gateway reads
requests through too); anything outside it is refused with 400 before any
attempt exists, and the error names it:

| API | Members the quote understands | Content the quote understands |
|---|---|---|
| Responses | `model`, `input`, `instructions` (a string), `max_output_tokens`, `stream` (a boolean), `stream_options`, `temperature`, `top_p`, `top_logprobs`, `tools`, `tool_choice`, `parallel_tool_calls`, `max_tool_calls`, `reasoning` (`effort`, `summary`, `generate_summary`), `text` (`verbosity`, `format` of type `text`, `json_object` or `json_schema`), `include`, `metadata`, `user`, `safety_identifier`, `prompt_cache_key`, `prompt_cache_retention`, `service_tier` (`default`, `flex`, `auto`), `truncation`, `store` (`false`), `background` (`false`) | input items, each with only its members (`type` and `id` on every one): `message` (`role`, `content`, `status`), `function_call` (`call_id`, `name`, `arguments`, `status`), `function_call_output` (`call_id`, `output`, `status`), `custom_tool_call` (`call_id`, `name`, `input`, `status`), `custom_tool_call_output` (`call_id`, `output`), `local_shell_call` (`call_id`, `action`, `status`), `local_shell_call_output` (`output`, `status`), `apply_patch_call` (`call_id`, `operation`, `status`), `apply_patch_call_output` (`call_id`, `output`, `status`), and `reasoning` (`summary`, `content`, `status`) with its `encrypted_content`; an item that names an `id` must carry its content (a message its `content`, a call its `call_id`, `name` and arguments or input, an output its `output`); parts, each with only its members (`type` on every one): `input_text`, `summary_text` and `reasoning_text` (`text`), `output_text` (`text`, `annotations`, `logprobs`), `refusal` (`refusal`), and `input_image` (`image_url`, an inline `data:image/` URL, and `detail`) |
| Chat Completions | `model`, `messages`, `max_tokens`, `max_completion_tokens`, `stream` (a boolean), `stream_options`, `temperature`, `top_p`, `n` (1), `stop`, `presence_penalty`, `frequency_penalty`, `logit_bias`, `logprobs`, `top_logprobs`, `seed`, `user`, `safety_identifier`, `prompt_cache_key`, `prompt_cache_retention`, `response_format`, `tools`, `tool_choice`, `parallel_tool_calls`, `functions`, `function_call`, `reasoning_effort`, `verbosity`, `metadata`, `store` (`false`), `service_tier` (`default`, `flex`, `auto`), `modalities` (`text` only) | message members `role`, `content`, `name`, `tool_calls`, `tool_call_id`, `function_call`, `refusal`; parts, each with only its members (`type` on every one): `text` (`text`, `cache_control`), `refusal` (`refusal`), and `image_url` (`image_url`, a string or an object of `url`, an inline `data:image/` URL, and `detail`; `cache_control`) |
| Messages | `model`, `messages`, `max_tokens`, `system`, `stream` (a boolean), `temperature`, `top_p`, `top_k`, `stop_sequences`, `metadata`, `tools`, `tool_choice`, `thinking` (`type` `enabled`, `disabled` or `adaptive`; `budget_tokens`; `display`), `context_management` (`edits` of type `clear_tool_uses_*` or `clear_thinking_*` only, with `trigger`, `keep`, `clear_at_least`, `exclude_tools`, `clear_tool_inputs`), `service_tier` (`standard_only`, `auto`), `output_config` (`effort`, `format` of type `json_schema`), `output_format` (type `json_schema`) | message members `role`, `content`; blocks, in a message and in `system`, each with only its members (`type` on every one): `text` (`text`, `cache_control`, `citations`), `tool_use` (`id`, `name`, `input`, `cache_control`), `tool_result` (`tool_use_id`, `content`, `is_error`, `cache_control`), `thinking` (`thinking`, `signature`), `redacted_thinking` (`data`), `image` (`source`, `cache_control`) with a `base64` source (`media_type`, `data`), `document` (`source`, `title`, `context`, `citations`, `cache_control`) with a `text` source (`media_type`, `data`) or a `content` source (`content`) and no `citations` enabled |
| Embeddings (spend proxy only) | `model`, `input`, `encoding_format`, `dimensions`, `user` | `input` a string, a list of strings, a list of token ids or a list of token-id lists |

So `previous_response_id`, `conversation`, a stored `prompt`, `store: true`, an
`item_reference`, a reasoning item without `encrypted_content`, an input item
that names an `id` without carrying its content, a chat message's stored
`audio`, remote or uploaded media in every spelling (an image or file URL, a
`file_id`, `input_file`, a chat `file` part, a `url` or `file` source), a data
URL that is not an image (video and audio bill by duration), PDFs
(`input_file`, a chat `file`, a `base64` document), a document with citations
enabled (Anthropic bills tokens for chunking it), audio input and output,
predicted outputs, the routing members `models`, `provider`, `plugins` and
`route`, priority and scale service tiers, Anthropic's `speed` and
`inference_geo`, a compaction edit and any other `context_management` edit that
does not remove content, server tool blocks, a key repeated at any depth, a
`stream` that is not a boolean, Responses `instructions` that are not a
string, and any member the lists do not name are refused. The lists close
the members of the request, of its messages, input items, content parts,
blocks, block sources and Chat `image_url` objects, and of `reasoning`,
`text`, `thinking`, `output_config`, `output_format` and `context_management`
(and its edits). What a request
carries inside those is counted by its bytes and not read further: tool
definitions beyond their type, `tool_calls` and `tool_choice` beyond their
type, JSON schemas, `metadata`, `stream_options`, `include`, a reasoning
item's `summary` and `content`, a call's `arguments`, `input`, `action` or
`operation`, a block's `citations` and an edit's parameters. The spend proxy's
governed gateway prices no prompt-cache write, so it also refuses any request
that names `cache_control` at any depth; the model gateway prices the write
(step 3).

Two members are set by the gateway rather than left to the provider's account:

- A Responses request that names no `store` is sent with `store: false`:
  OpenAI stores a response by default, and a stored item can be billed again
  by reference.
- On a route whose provider is the vendor's own API (`kind` `openai` or
  `anthropic`), a request that names no `service_tier`, or `auto`, is sent with
  the standard tier, `default` (OpenAI) or `standard_only` (Anthropic): an
  absent or auto tier bills at the tier the account defaults to, which can be
  priority. On an `openai-compatible` route the tier's meaning is the
  upstream's, so `auto` is refused and an absent tier is left absent.

On the Messages API only these `anthropic-beta` values are forwarded; any
other is refused with 400, naming it (so `context-1m-*`, compaction, the
Files API, MCP servers, code execution and betas the gateway does not know):
`claude-code-20250219`,
`oauth-2025-04-20`, `interleaved-thinking-2025-05-14`,
`fine-grained-tool-streaming-2025-05-14`, `token-efficient-tools-2025-02-19`,
`context-management-2025-06-27`, `prompt-caching-2024-07-31`,
`extended-cache-ttl-2025-04-11`, `output-128k-2025-02-19`,
`computer-use-2024-10-22`, `computer-use-2025-01-24`,
`computer-use-2025-11-24`, `structured-outputs-2025-11-13`,
`effort-2025-11-24`, `model-context-window-exceeded-2025-08-26`. On the
OpenAI APIs the gateway forwards no `anthropic-beta` and no
`anthropic-version`: they are not checked there, and an upstream that passes
them to Anthropic could bill a premium.

## One call, one `model.inference` attempt

The effect type is `model.inference`; its target is the priced route id and its
arguments are `model.inference.v1` (`api` one of `openai-responses`,
`openai-chat`, `anthropic-messages`; `route`; `request_sha256`; `input_bytes`;
`max_output_tokens`; `stream`). The request body is never carried: an attempt's
content holds a digest and a size, never a prompt.

1. Authenticate the token (scope `helm.gateway.propose`). Tenant, workspace and
   principal come from the token alone. A human principal is refused; the
   worker listener serves agent principals only.
2. Resolve the route from the request's model, refuse provider-executed tools,
   clamp or inject the maximum output tokens.
3. Price the quote in `usd_micros`: every input byte counts as a token at
   the input price, and the clamped maximum output is generated in full at the
   output price, rounded up once to whole micros. Bytes bound the tokens of
   text the request carries; what the closed list keeps but bytes do not bound
   is added as a token floor: 48,169 tokens for each inline image on the OpenAI
   APIs (a high-detail image on gpt-4o-mini, OpenAI's dearest documented image)
   and 8,000 on Anthropic's (five times the about 1,600 tokens Anthropic scales
   an image to); 600 tokens for Anthropic's tool-use system prompt when a
   request declares tools; and 2,000 tokens for each client tool whose
   definition the provider supplies (`bash_*`, `text_editor_*`, `computer_*`,
   `memory_*`, `local_shell`, `apply_patch`). Everything else is refused, so
   the quote bounds the call's bill at the route's price under the assumptions
   listed below. When the request may write a
   prompt cache (any decoded JSON key of it is `cache_control`, so an escaped
   spelling cannot avoid this), the input rate is the dearest of the input and
   cache-write prices; on an `anthropic` or `openai-compatible` route that
   names no cache-write price, those are Anthropic's published premium, 1.25
   times the input price for a 5-minute write and 2 times for a 1-hour
   write. The quote names a zero amount for every other unit the mandate
   chain sums.
4. Propose the attempt under the key `mi:<scope>:<request sha256>:<n>`. The
   mandates, limits, stops and idempotency of any other effect apply. `DENIED`
   answers 403 with the HELM reason code; `ESCALATED` is cancelled and answers
   403, because no approval exists for a model call.
5. Claim the permit, inject the provider key (only the gateway holds it), send
   the request, stream the response back while keeping a copy, and settle the
   usage the provider reports against the reservation.

### The bound and what it rests on

The hold is an upper bound of what the provider can bill for the call, at the
route's price, when each of these holds; a request that breaks none of them
and bills above its hold is a bug:

- The provider's tokenizer emits at most one token per byte of the text a
  request carries, and the provider bills no input the request does not
  carry beyond the floors (the closed list refuses every form known to make
  it do so). Chat templates, tool definitions rendered from their JSON and
  the JSON a request carries around its text are assumed to cost no more
  tokens than their bytes.
- An inline image costs at most its floor: 48,169 tokens on the OpenAI APIs
  and 8,000 on Anthropic's. A model that bills more for one image is not
  bounded.
- A hidden tool definition costs at most 2,000 tokens, and Anthropic's
  tool-use system prompt at most 600.
- The provider honours the output maximum the gateway forwards, reasoning and
  thinking tokens included. On an `openai-compatible` upstream such as
  OpenRouter, the reasoning budget `reasoning_effort` asks for is assumed to
  stay within that maximum; an upstream whose budget floor exceeds it can bill
  above the hold.
- Encrypted reasoning (`encrypted_content`), thinking `signature`s and
  `redacted_thinking` `data` carried back in a request are assumed to cost no
  more input tokens than their bytes; the gateway cannot read what they
  decrypt to.
- A prompt-cache write bills at most the route's cache-write price: the
  configured one, or on an `anthropic` or `openai-compatible` route that names
  none, 1.25 times input for a 5-minute write and 2 times for a 1-hour write.
  On an `openai-compatible` route the gateway reads no cache-write count from
  the usage, so a write is settled at the input price; the hold still covers
  it.
- The route's price is the provider's highest for a request of
  `max_request_bytes` on the tier the gateway sends or leaves: a provider that
  charges more above a context length needs that price on the route, and on
  an `openai-compatible` route an absent service tier is assumed to bill at
  the route's price.
- An input item that carries its content is billed for that content, not for
  a stored item of the same id.
- Headers other than `anthropic-beta` change nothing the provider bills;
  `anthropic-beta` is checked against the allowlist and forwarded on the
  Messages API only.

A provider that bills above the hold anyway is recorded: the confirmed amount
stays on the budget counter and billable is capped at the hold.

Settlement is recorded in `authority_model_calls` and returned as
`EffectAttempt.model_call` (`ModelCallSettlement`: route, state, currency,
held, estimated, confirmed and billable micros). The billable amount never
exceeds the amount held; an overage is recorded as reported. A call cut before
the provider reported usage, or whose transport was lost after the provider
accepted it, is `UNKNOWN` with its hold kept as an estimate until it is
resolved. The same request in the same scope is answered from the stored
response (`authority_model_replays`, bounded by `max_replay_bytes` and
`replay_ttl`) and never reaches the provider twice; a request that changes the
stream flag, the route or any byte has another digest and is another call.

The scope is, on the main listener, `X-Helm-Idempotency-Scope` (the Control
Plane's workload may name it, and `X-Helm-Case-Id`) and otherwise the token's
id; on the worker listener it is the episode id and the case is the work item,
both from the token and never from the request.

## Listeners

- **Main listener** (`--listen`, default `:8443`): TLS, optionally with client
  certificates. The Control Plane's workload calls here with its existing token
  profile (audience `helm-gateway:<env>`).
- **Worker listener** (`--worker-listen`, default off): the model endpoints and
  the MCP endpoint (`/mcp`, see [gateway-mcp.md](gateway-mcp.md)), for episode
  workers. It serves no effect API. Server TLS without a client certificate (unmodified
  frameworks cannot present one), so the listener authenticates by token alone
  and the deployment's network policy admits only the workers' namespace. With
  `--dev-insecure-listen` it is plain HTTP on a loopback address. Its token
  profile:
  - audience `HELM_GATEWAY_WORKER_AUDIENCE` (`helm-gateway-worker:<env>`), which
    must differ from the main audience: a token minted for one listener is
    invalid on the other;
  - lifetime (`exp - iat`) at most `HELM_GATEWAY_WORKER_MAX_TTL`, itself at most
    3600 seconds (an episode runs at most 60 minutes);
  - the same issuer and signing keys as the main profile, no certificate
    binding, an optional actor;
  - a `helm_episode` claim (`episode_id`, `work_item_id`, optional
    `organization_version_id`, each of `[A-Za-z0-9._:-]{1,128}`) is required;
  - agent principals only.

## Configuration

`HELM_GATEWAY_MODEL_ROUTES_FILE` names one closed JSON file (an unknown field is
a refusal; at most 1 MiB):

```json
{"version": 1,
 "providers": [{"id": "anthropic", "kind": "anthropic", "base_url": "https://api.anthropic.com",
                "key_file": "/var/run/secrets/helm-gateway-model/anthropic"}],
 "routes": [{"id": "anthropic/claude-sonnet-5-5", "provider": "anthropic", "model": "claude-sonnet-5-5",
             "apis": ["anthropic-messages"],
             "price": {"unit": "usd_micros_per_million_tokens", "input": 3000000, "output": 15000000},
             "default_max_output_tokens": 4096, "max_output_tokens": 8192}],
 "limits": {"max_request_bytes": 8388608, "call_timeout": "20m", "idle_timeout": "10m"}}
```

- Provider `kind` is `anthropic`, `openai` or `openai-compatible` (any upstream
  that speaks OpenAI's wire format, such as OpenRouter). `base_url` is https
  (http on a loopback address, for development only). `auth` overrides how the
  key is presented: `x-api-key` (the default for anthropic) or `bearer`.
- A route id is what a mandate's targets name; a request's model may be the id
  or the provider's own model id. Prices are integer
  `usd_micros_per_million_tokens`, so no tariff is rounded; an unpriced route is
  refused. `cache_read` defaults to the input price. `cache_write_5m` and
  `cache_write_1h` default, on an `anthropic` or `openai-compatible` route, to
  Anthropic's published premium (1.25 times the input price, rounded up, and 2
  times), because the provider or an upstream that passes Anthropic's tariff
  through bills a write above the input price; on an `openai` route they
  default to the input price, as OpenAI bills no write.
- Provider keys are files the deployment mounts into the gateway Pod only (rule
  R8): the file is read when the gateway starts and again when it changes, and
  the gateway refuses to start on a missing, empty or unusable one. A key never
  appears in a log, an error or a response.
- `limits` bound what the gateway buffers and how long a call runs:
  `max_request_bytes` (default 8 MiB), `max_replay_bytes` (default 8 MiB, at
  most 64 MiB), `replay_ttl` (default 2 hours), `call_timeout` (default 20
  minutes) and `idle_timeout` (default 10 minutes of silence in a stream).

Environment of the serve command beyond the effect gateway's:

| Variable or flag | Meaning |
|---|---|
| `HELM_GATEWAY_MODEL_ROUTES_FILE` | The routes file above. Without it no model endpoint is served. |
| `--worker-listen :8444` | The worker listener. Needs the routes file and the audience. |
| `HELM_GATEWAY_WORKER_AUDIENCE` | The worker listener's token audience. Required with `--worker-listen`; refused without it. |
| `HELM_GATEWAY_WORKER_MAX_TTL` | The longest worker token lifetime, at most `3600s` (the default). |

## What this does and does not establish

- Every provider call has an attempt, and every attempt has a settlement: the
  gateway, not the client, reports the spend (rule R4, ADR-0003).
- The synthetic proofs run against stubbed providers. Hosted provider accuracy,
  billing reconciliation and deployed worker episodes are not established by this
  note or its tests.
- `model.inference` has no published argument schema: the gateway proposes the
  call itself, so no client constructs these arguments.
- An attempt proposed on the worker listener records its token's verified
  `helm_episode` claim, model calls and the effects of the MCP endpoint alike
  (`EffectAttempt.episode`, schema version 8); see
  [gateway-effect-api.md](gateway-effect-api.md#episode-attempts). The MCP
  endpoint is described in [gateway-mcp.md](gateway-mcp.md).
