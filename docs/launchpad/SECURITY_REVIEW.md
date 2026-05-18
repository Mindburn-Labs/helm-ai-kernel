# Launchpad Security Review

Status: fail-closed implementation review. This is not a production security sign-off because no third-party app has completed live local-container e2e and no signed OpenClaw/Hermes artifact manifest has been produced by CI.

## Results

- [KEEP] Registry validation blocks `oss_supported` apps unless license, redistribution, artifact/build, policy, sandbox, healthcheck, e2e, teardown, receipt, and EvidencePack evidence are present.
- [KEEP] `helm-ai-kernel launch promote` blocks app promotion unless the merged CI promotion manifest records immutable image digest, cosign signature, syft SBOM, grype/trivy scan, provenance, live e2e, EvidencePack, and teardown refs.
- [KEEP] Promotion refs must be tied to the same GitHub workflow run as the artifact manifest; stale or unrelated evidence refs are rejected.
- [KEEP] OpenClaw, Hermes, OpenCode, and Kilo Code remain `oss_candidate`.
- [KEEP] Codex, Claude Code, Cursor, and Junie remain external/BYO adapters; no proprietary redistribution claim is made.
- [KEEP] CLI/API launch path returns `ESCALATE` for missing required secrets and does not crash.
- [KEEP] Installer tests reject missing digest, host `curl | bash`, `git pull`, `git stash`, and package-manager mutation inside the current worktree.
- [KEEP] Policy validation requires `permission_bypass_forbidden = true`, `recursive_launch_forbidden = true`, and network default `deny`.
- [KEEP] Runtime preflight tests block host filesystem escape, non-deny network defaults, privileged mode, privilege-escalation flags, recursive launch, and secret leakage through projected env handles.
- [KEEP] Local-container OpenRouter egress is fail-closed: non-OpenRouter allowlists are rejected, OpenRouter allowlists use a launch-owned CONNECT proxy path when no external proxy is configured, and runtime start requires an egress proxy receipt for networked `RUNNING` launches.
- [KEEP] Live conformance tests no longer fake container IDs; they exercise Docker-backed runtime startup and app healthchecks.
- [KEEP] MCP governance tests quarantine unknown servers/tools, require schema pins, deny schema drift, require approval receipts for side-effect tools, and block revoked tools.
- [KEEP] Session store tests reject unknown verdicts, reject side-effect states without `ALLOW`, reject `RUNNING` without launch/healthcheck/sandbox refs, reject networked `RUNNING` without egress refs, and reject `DELETED` without teardown receipt.
- [KEEP] Generated and static Launchpad EvidencePacks verify offline through `helm-ai-kernel verify --bundle`.
- [KEEP] Skill Pack scanning denies policy bypass instructions, secret exfiltration, global install by default, MCP side-effect auto-enable, hook auto-approval, symlink/path escape, opaque binaries, missing license, and invalid manifests.
- [KEEP] Skill Pack remote GitHub fetch requires pinned non-mutable refs plus archive digest and rejects path escapes.
- [KEEP] OSS and Enterprise Console teardown controls require a second explicit confirmation.
- [KEEP] Enterprise Launchpad route tests and Playwright coverage now cover matrix rendering, approval escalation, evidence refs, teardown receipt, and EvidencePack visibility.
- [KEEP] Enterprise Skills route tests cover scan, install, rollout, receipt, usage, and drift surfaces.
- [KEEP] Enterprise route registry/OpenAPI parity passes for the added Launchpad and Skills routes.
- [REBUILD] Enterprise `make verify-boundary` fails because 12 mirrored kernel/protocol files differ from `helm-ai-kernel.lock`; this must be resolved through the approved OSS sync path.

## Remaining Red-Team Work

- [REBUILD] Prompt injection through app metadata needs a dedicated malicious metadata fixture.
- [REBUILD] Malicious AppSpec/SubstrateSpec schema attacks need fuzz or adversarial corpus coverage beyond strict schema validation.
- [REBUILD] License spoofing needs tests against forged SPDX/license metadata and upstream-source mismatch.
- [REBUILD] Public-key cryptographic Skill Pack signatures are not implemented; current first-party verification is keyring/ref/content-hash based.
- [DEFER] Secret leakage in live container logs is not tested because no app currently reaches live container execution.
- [DEFER] Cloud ambiguous-outcome duplicate provision is tested at reconciliation logic level only, not against real providers.
- [DEFER] Network egress bypass and container escape need live container tests once OpenClaw/Hermes can run.
- [DEFER] Live MCP dispatch attacks need app-process integration beyond the governance decision layer.
- [REBUILD] Enterprise live OSS runtime delegation and commercial approval/retention security review remain blocked until boundary drift is cleared and delegation is wired.

## Verdict

[KEEP] The current Skill Packs + Launchpad slice is materially safer than a normal launcher: it fails closed, does not mark apps available, blocks host installer patterns, redacts projected secrets, quarantines MCP by default, requires promotion evidence, validates skill metadata/policies, and emits receipts/EvidencePacks for the paths it exercises.

[REBUILD] It is not production complete until signed artifacts, live app e2e, live MCP dispatch binding, Enterprise boundary sync, Enterprise runtime delegation, and app/container red-team tests pass.
