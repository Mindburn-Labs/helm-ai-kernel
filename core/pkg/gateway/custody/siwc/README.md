# Self-host ChatGPT credential custody

`helm-gateway chatgpt login|status|logout` manages a public OIDC + PKCE
registration in `HELM_DEPLOYMENT_MODE=selfhost`. Login prints a browser URL
after starting a literal loopback callback. `--account` selects an existing
registration; `--store` selects its private local directory. Credentials are
never printed by these commands. Logout clears local tokens and reports when
remote revocation cannot be confirmed.

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

Protocol sources:

- [Public-client sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- [Token lifecycle](https://developers.openai.com/siwc/token-sharing-open-source/token-reference)
- [Account profiles](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)

Tests use a local TLS identity provider and runtime-generated signing keys;
they never use an account credential or call a model provider.
