# Self-host ChatGPT credential custody

`helm-gateway chatgpt login|status|logout` manages a public OIDC + PKCE
registration in `HELM_DEPLOYMENT_MODE=selfhost`. Login prints a browser URL
after starting a literal loopback callback. `--account` selects an existing
registration; `--store` selects its private local directory. Credentials are
never printed by these commands. Logout clears local tokens and reports when
remote revocation cannot be confirmed.

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
