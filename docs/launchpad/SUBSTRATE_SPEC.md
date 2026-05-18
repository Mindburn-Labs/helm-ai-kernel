# Launchpad SubstrateSpec

Status: implemented as initial YAML registry plus validator.

Substrate specs live under `registry/launchpad/substrates/`.

Current substrates:

- `local-container`: default local substrate.
- `digitalocean`: dry-run/stub cloud substrate.
- `hetzner`: dry-run/stub cloud substrate.

Substrate specs must declare a known kind, a policy ref that exists and parses, deny-by-default network posture unless explicitly justified, teardown requirements, and evidence requirements.
