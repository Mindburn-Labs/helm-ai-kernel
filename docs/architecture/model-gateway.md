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
| `POST /v1/messages` (also `?beta=true`) | Anthropic Messages: Claude Code, the Claude Agent SDK, `ChatAnthropic` | Custom tools and the schema-less client tools (`bash_*`, `text_editor_*`, `computer_*`, `memory_*`). `anthropic-version` and `anthropic-beta` are forwarded (a default version is set when absent); errors come back in Anthropic's shape. |
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
3. Price the worst case in `usd_micros`: every input byte counts as a token at
   the input price, an upper bound for byte-level tokenizers, and the clamped
   maximum output is generated in full at the output price, rounded up once to
   whole micros. When the request may write a prompt cache (any decoded JSON key
   of it is `cache_control`, so an escaped spelling cannot avoid this), the input
   rate is the dearest of the input and cache-write prices. The quote names a
   zero amount for every other unit the mandate chain sums.
4. Propose the attempt under the key `mi:<scope>:<request sha256>:<n>`. The
   mandates, limits, stops and idempotency of any other effect apply. `DENIED`
   answers 403 with the HELM reason code; `ESCALATED` is cancelled and answers
   403, because no approval exists for a model call.
5. Claim the permit, inject the provider key (only the gateway holds it), send
   the request, stream the response back while keeping a copy, and settle the
   usage the provider reports against the reservation.

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
- **Worker listener** (`--worker-listen`, default off): the model endpoints only,
  for episode workers. Server TLS without a client certificate (unmodified
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
  refused. The cache prices (`cache_read`, `cache_write_5m`, `cache_write_1h`)
  default to the input price.
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
- The MCP endpoint of the worker listener, and persisting the verified
  `helm_episode` claim onto the attempts of other effects, are separate work.
