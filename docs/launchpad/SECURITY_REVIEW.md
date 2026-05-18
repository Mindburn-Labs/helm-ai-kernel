# Launchpad Security Review

Status: fail-closed implementation review. This is not a production security sign-off because no third-party app has completed live local-container e2e.

## Results

- [KEEP] Registry validator blocks `oss_supported` apps unless license, redistribution, artifact/build, policy, sandbox, healthcheck, e2e, teardown, receipt, and EvidencePack evidence are present.
- [KEEP] `helm-ai-kernel launch promote` blocks app promotion unless the CI artifact manifest records immutable image digest, cosign signature, syft SBOM, grype/trivy scan, provenance, live e2e, EvidencePack, and teardown refs.
- [KEEP] OpenClaw, Hermes, OpenCode, and Kilo Code remain `oss_candidate`.
- [KEEP] Codex, Claude Code, Cursor, and Junie remain external/BYO adapters; no proprietary redistribution claim is made.
- [KEEP] CLI/API launch path returns `ESCALATE` for missing required secrets and does not crash.
- [KEEP] Installer tests reject missing digest, host `curl | bash`, `git pull`, `git stash`, and package-manager mutation inside the current worktree.
- [KEEP] Policy validation requires `permission_bypass_forbidden = true`, `recursive_launch_forbidden = true`, and network default `deny`.
- [KEEP] Runtime preflight tests block host filesystem escape, non-deny network defaults, privileged mode, privilege-escalation flags, recursive launch, and secret leakage through projected env handles.
- [KEEP] Local-container OpenRouter egress is fail-closed: non-OpenRouter allowlists are rejected and any OpenRouter allowlist requires a launch-scoped egress proxy receipt before runtime start.
- [KEEP] MCP governance tests quarantine unknown servers/tools, require schema pins, deny schema drift, require approval receipts for side-effect tools, and block revoked tools.
- [KEEP] Session store tests reject unknown verdicts, reject side-effect states without `ALLOW`, reject `RUNNING` without launch/healthcheck/sandbox refs, and reject `DELETED` without teardown receipt.
- [KEEP] Generated and static Launchpad EvidencePacks verify offline through `helm-ai-kernel verify --bundle`.
- [KEEP] OSS and Enterprise Console teardown controls require a second explicit confirmation.
- [KEEP] Enterprise Launchpad route tests keep launch requests in `ESCALATED` state without approval and require proof refs.
- [KEEP] Enterprise Playwright Launchpad spec verifies matrix render, missing model-key escalation, MCP quarantine visibility, EvidencePack visibility, and teardown receipt visibility across the configured browser matrix.

## Remaining Red-Team Work

- [REBUILD] Prompt injection through app metadata needs a dedicated malicious metadata fixture.
- [REBUILD] Malicious AppSpec/SubstrateSpec schema attacks need fuzz or adversarial corpus coverage beyond strict schema validation.
- [REBUILD] License spoofing needs tests against forged SPDX/license metadata and upstream-source mismatch.
- [DEFER] Secret leakage in live container logs is not tested because no app currently reaches live container execution.
- [DEFER] Cloud ambiguous-outcome duplicate provision is tested at reconciliation logic level only, not against real providers.
- [DEFER] Network egress bypass and container escape need live container tests once OpenClaw/Hermes can run.
- [DEFER] Live MCP dispatch attacks need app-process integration beyond the governance decision layer.

## Verdict

[KEEP] The current Launchpad slice is materially safer than a normal launcher: it fails closed, does not mark apps available, blocks host installer patterns, redacts projected secrets, quarantines MCP by default, and emits receipts/EvidencePacks for the paths it exercises.

[REBUILD] It is not production complete until live app e2e, live MCP dispatch binding, and app/container red-team tests pass.
