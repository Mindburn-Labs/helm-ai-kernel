# Launchpad SubstrateSpec

Status: implemented as YAML registry plus validator.

Substrate specs live under `registry/launchpad/substrates/`.

Current substrates:

- `local-container`: GA baseline local-container app launcher for trusted
  developer workloads.
- `docker-sandbox-microvm`: experimental stronger local substrate placeholder.
- `e2b`, `daytona`, `modal`: experimental hosted sandbox placeholders.
- `digitalocean`: opt-in cloud beta, dry-run by default.
- `hetzner`: opt-in cloud beta, dry-run by default.

Substrate specs must declare a known kind, a policy ref that exists and parses,
deny-by-default network posture, a valid isolation policy, teardown
requirements, and capability metadata.

Capability metadata is mandatory:

- `isolation_strength`;
- `network_enforcement`;
- `secret_mode`;
- `receipt_support`;
- `teardown_proof`;
- `status`;
- lifecycle verbs: `plan`, `preflight`, `launch`, `healthcheck`, `execute`,
  `evidence_export`, `reconcile`, `delete`, and `post_delete_verify`.

A substrate cannot use `availability: supported` unless `status: ga`,
`receipt_support: required`, and `teardown_proof: required`. Substrates that
cannot emit receipts, enforce network policy, or prove teardown remain
experimental or beta.
