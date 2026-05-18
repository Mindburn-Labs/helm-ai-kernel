# Launchpad AppSpec

Status: implemented as initial YAML registry plus validator.

App specs live under `registry/launchpad/apps/`. The validator enforces unique IDs, known availability labels, existing policy refs, policy TOML parseability, deny-by-default network posture, MCP quarantine defaults, and full conformance before `oss_supported`.

Required semantics:

- `oss_candidate`: visible as experimental, not launchable as Available.
- `oss_supported`: allowed only after full conformance evidence.
- `external_proprietary_adapter`: BYO account/tool; HELM governs only the adapter boundary.
- `blocked_*`: not launchable.

Promotion is an explicit governed step. `helm-ai-kernel launch promote --manifest <manifest.json> --app <app>` validates the CI artifact manifest before it can emit or write an `oss_supported` spec. The manifest must contain immutable `image@sha256`, matching digest, cosign signature ref, syft SBOM ref, grype or trivy scan ref, pinned upstream identity, license/redistribution evidence, live e2e run ID, EvidencePack ref, and teardown receipt ref.

External/proprietary apps must not expose an OSS install strategy and their policy pack must set `permission_bypass_forbidden = true`.
