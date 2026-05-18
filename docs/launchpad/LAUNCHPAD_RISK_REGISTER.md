# Launchpad Risk Register

- [REBUILD] Upstream app license/release ambiguity can cause proprietary or unverified software to be mislabeled as OSS. Mitigation: license audit before `oss_supported`.
- [REBUILD] Runtime side effects can bypass PEP/CPI if launch code calls Docker/cloud APIs directly. Mitigation: launch remains ESCALATE until boundary integration exists.
- [REBUILD] MCP schema drift can dispatch unknown tools. Mitigation: require schema pin and quarantine defaults.
- [REBUILD] Cloud ambiguous outcomes can double-provision. Mitigation: idempotency keys and reconcile-before-retry tests.
- [REBUILD] Secret leakage through logs/env projection. Mitigation: scoped env and redaction tests.
- [DEFER] Enterprise route drift between facade, registry, and OpenAPI. Mitigation: parity tests before enterprise Launchpad routes merge.
- [DEFER] Local Codex CLI is broken in this environment. Mitigation: classify Codex as BYO/external until e2e can run.
