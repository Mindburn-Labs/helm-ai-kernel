# Self-host ChatGPT credential custody

`helm-gateway chatgpt login|status|models|logout` manages a public OIDC + PKCE
registration in `HELM_DEPLOYMENT_MODE=selfhost`. Login prints a browser URL
after starting a literal loopback callback. `--account` selects an existing
registration; `--store` selects its private local directory. Credentials are
never printed by these commands. Logout clears local tokens and reports when
remote revocation cannot be confirmed.

`models --account ID` fetches that account's current catalog directly from
`https://api.openai.com/v1/models`. It returns only visible model slugs and
display names, in provider order, without printing credentials. It requires an
explicit account, rejects a stale account generation, and does not perform
inference or grant permission to a seat. Network errors do not fall back to a
cached catalog, a different account or an API key.

Each new store generates a stable canonical UUIDv4 URN (`urn:uuid:...`) for
the documented `host_id` option. It persists across login and refresh. Older
development stores with a raw base64 host ID are rejected without rewriting
their identity, registration or credentials. Preserve that store and choose a
new private `--store` directory for a fresh registration. Disconnect any old
registration in ChatGPT Settings; a new store does not revoke it.

The runtime account reference pins the local host, registration and generation.
It does not prove HELM tenant membership, ownership, consent or a mandate. A
model-gateway consumer must first resolve the current CP Connection authority
and admit the inference effect before requesting a token. This custody
checkpoint does not yet wire plan inference or accounting into model routes.
The hosted deployment remains BYOK.

`Store.Responses(ctx, client, reference, body)` is the custody transport for an
already admitted local inference. It checks the selected account's live model
catalog, sends one request to `https://api.openai.com/v1/responses`, and returns
only the full terminal response after `response.completed`, bounded stream EOF
and a final account generation check. Completion is staged so a failed,
incomplete, contradictory or interrupted suffix cannot publish output. Its
response contains model output, not an accepted business
result or a money receipt. The next request must include the required history
in its `input` array. Partial output, failed/incomplete responses, malformed
streams, interrupted requests and account changes return no completed result.

The body must already contain `store:false` and `stream:true`. Unsupported
preview fields, including `max_output_tokens` and `previous_response_id`, are
rejected before inference egress; they are never silently removed or treated
as enforced cost bounds. The stream and each event have finite byte limits.
An omitted response media type is allowed only if the body parses as valid SSE;
HTTP 200 alone never counts as completion. There is no inference CLI or served
model-route composition at this source checkpoint; the gateway owner retains
the admission, budget and boot integration.

`ResponseFailure` exposes bounded machine codes, field names and request IDs,
with a typed recovery hint and a conservative `may_have_dispatched` flag.
It never returns provider error messages, credentials or partial model output.
The caller must preserve unknown attempts for reconciliation. A usage-limit
error pauses new plan requests and points the user to
[ChatGPT Usage](https://chatgpt.com/settings/usage); it does not prove that the
whole plan is exhausted or specify a reset time. Availability errors retain
credentials and suggest a later bounded retry. Authorization errors require
diagnosis; they do not erase tokens or automatically restart OAuth. No failure
selects another account, resets a limit or falls back to an API key.

Protocol sources:

- [Public-client sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- [Token lifecycle](https://developers.openai.com/siwc/token-sharing-open-source/token-reference)
- [Account profiles](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)
- [Account model catalog](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
- [Inference errors and recovery](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery)
- [Preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations)

Tests use a local TLS identity provider and runtime-generated signing keys;
they never use an account credential or call a model provider.
