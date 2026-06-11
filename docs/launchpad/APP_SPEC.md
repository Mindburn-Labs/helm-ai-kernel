# Launchpad AppSpec

Status: implemented as YAML registry plus validator.

App specs live under `registry/launchpad/apps/`. The validator enforces unique
IDs, known availability labels, existing policy refs, policy TOML parseability,
deny-by-default network posture, MCP quarantine defaults, signed MCP manifest
refs, model gateway metadata when a logical secret is required,
`framework_contract`, and full conformance before `oss_supported`.

Required semantics:

- `oss_candidate`: visible as experimental, not launchable as Available.
- `oss_supported`: allowed only after full conformance evidence, signed supply
  chain refs, MCP manifest refs, model gateway evidence, teardown proof, and
  offline EvidencePack verification.
- `verify_only`: contract and smoke evidence only; not live-agent F2 coverage.
- `agent_live`: live command evidence exists and F2 may run only after
  `f2_contract_preflight` passes.
- `external_proprietary_adapter`: BYO account/tool; HELM governs only the adapter boundary.
- `blocked_*`: not launchable.

Promotion is an explicit governed step. `helm-ai-kernel launch promote --manifest <manifest.json> --app <app>` validates the CI artifact manifest before it can emit or write an `oss_supported` spec. The manifest must contain immutable `image@sha256`, matching digest, cosign signature ref, syft SBOM ref, grype or trivy scan ref, pinned upstream identity, license/redistribution evidence, live e2e run ID, EvidencePack ref, and teardown receipt ref.

External/proprietary apps must not expose an OSS install strategy and their policy pack must set `permission_bypass_forbidden = true`.

## Market-Best Support Bar

Supported means all of the following are present and registry-validated:

- immutable signed artifact digest;
- cosign signature ref;
- syft SBOM ref;
- grype or trivy vulnerability scan ref;
- license and redistribution proof;
- deny-by-default filesystem and network policy pack;
- signed MCP server manifest refs with pinned command/package digest/schema
  hashes/tool effects;
- logical model gateway secret metadata;
- runtime e2e and healthcheck evidence;
- teardown receipt;
- hash-chained EvidencePack graph;
- offline `helm-ai-kernel verify --bundle <pack>` pass.
- `f2_contract_preflight` proof covering image digest parity, command parity,
  sandbox, egress proxy, writable HOME/cache/state paths, scoped secret
  projection, MCP manifests, healthcheck, EvidencePack export, and offline
  verify.

OpenClaw and Hermes are the current live local-container set. OpenCode and Kilo
Code are `verify_only`; `--version` smoke checks do not count as live-agent F2
coverage. Any additional app remains non-supported until it meets the same
registry-validated evidence bar.
