<!-- quantum_posture: historical evidence uses classical Ed25519 signatures and SHA-256 hashes; no post-quantum claim. -->

# Historical spend evidence

The live `helm-ai-kernel spend-proxy` command and its local `reconcile` writes
are retired. Live model calls use [helm-gateway](../../docs/architecture/model-gateway.md),
whose admission, reservations, consumption, idempotency and recovery are
transactional Postgres state. A local receipt log is evidence, not authority.

## Move live clients to helm-gateway

Configure the gateway database, identity, signing keys and provider routes as
specified in the [gateway setup](../../docs/architecture/gateway-effect-api.md)
and [model gateway configuration](../../docs/architecture/model-gateway.md#configuration).
Apply its migrations with `helm-gateway migrate`, then run `helm-gateway serve`
with the appropriate listener configuration. Set `HELM_GATEWAY_MODEL_ROUTES_FILE`
to the gateway routes file; provider credentials stay with that gateway.

Point the client's API base URL at the gateway listener and authenticate with
a Control Plane-issued workload or episode token. Provision its mandates and
limits through the existing authority flow. The legacy `--config`, `--api-key`,
`--receipts-dir`, caller-token hashes and envelope headers do not provision
Postgres authority. Do not turn a historical opening balance into a fresh grant.

The gateway supports Responses, Chat Completions and Anthropic Messages. The
retired proxy's embeddings endpoint has no replacement on this listener.
Existing pending local dispatches require operator investigation of the provider
bill; exporting their evidence does not release a hold or authorize a retry.

## Export existing receipts

Receipt exports and savings verification remain offline operations. Obtain the
issuer public key independently of the receipt directory:

```sh
helm-ai-kernel spend-proxy export \
  --receipts-dir ./historical-receipts --out ./evidence \
  --public-key 'ed25519:<issuer-public-key-hex>'
```

Repeat `--public-key` for logs signed by multiple issuers. Every record's type
and identity must agree with its signed payload. A settlement's signed usage
reference must resolve within the exported intent.

Historical paired-capture savings packs can still be built with
`spend-proxy savings-export --receipts-dir ... --capture ... --config ... --out ... --sign ...`
and verified with `spend-proxy savings-verify --pack ... --issuer-key-id ... --issuer-public-key ...`. The signing seed is
only for the historical pack manifest and does not grant spending authority.
The configs and paired-replay runner in this directory describe the retired
capture format; they are not a live gateway setup.
