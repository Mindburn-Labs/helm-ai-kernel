# Launchpad Security Review

Status: `v0.5.4` production release review passed for OpenClaw and Hermes
local-container support; public GA remains gated on clean-install evidence.

## Results

- [KEEP] Registry validation blocks `oss_supported` apps unless license,
  redistribution, artifact/build, policy, sandbox, healthcheck, e2e, teardown,
  receipt, and EvidencePack evidence are present.
- [KEEP] `helm-ai-kernel launch promote` blocks app promotion unless the merged
  CI promotion manifest records immutable image digest, cosign signature, syft
  SBOM, grype/trivy scan, provenance, live e2e, EvidencePack, and teardown refs.
- [KEEP] Promotion refs must be tied to the same GitHub workflow run as the
  artifact manifest; stale or unrelated evidence refs are rejected.
- [KEEP] OpenClaw and Hermes are promoted to `oss_supported` from signed CI
  artifacts and live local-container evidence.
- [KEEP] OpenCode and Kilo Code remain `oss_candidate`.
- [KEEP] Codex, Claude Code, Cursor, and Junie remain external/BYO adapters; no
  proprietary redistribution claim is made.
- [KEEP] CLI/API launch path returns `ESCALATE` for missing required secrets and
  does not crash.
- [KEEP] Live CI uses `HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY`, mapped to
  `OPENROUTER_API_KEY` only inside the test step.
- [KEEP] `scripts/launch/secret_fragment_audit.py` scans command output, GitHub
  logs, release notes/assets, reports, and EvidencePacks for the scoped test key
  and fixed-length fragments without printing the secret or fragments.
- [KEEP] Installer tests reject missing digest, host `curl | bash`, `git pull`,
  `git stash`, and package-manager mutation inside the current worktree.
- [KEEP] Policy validation requires `permission_bypass_forbidden = true`,
  `recursive_launch_forbidden = true`, and network default `deny`.
- [KEEP] Runtime preflight tests block host filesystem escape, non-deny network
  defaults, privileged mode, privilege-escalation flags, recursive launch, and
  secret leakage through projected env handles.
- [KEEP] Local-container OpenRouter egress is fail-closed: non-OpenRouter
  allowlists are rejected, OpenRouter allowlists use a launch-scoped proxy path,
  and runtime start requires an egress proxy receipt for networked `RUNNING`
  launches.
- [KEEP] Live conformance tests exercise Docker-backed runtime startup and app
  healthchecks.
- [KEEP] MCP governance tests quarantine unknown servers/tools, require schema
  pins, deny schema drift, require approval receipts for side-effect tools, and
  block revoked tools.
- [KEEP] Session store tests reject unknown verdicts, reject side-effect states
  without `ALLOW`, reject `RUNNING` without launch/healthcheck/sandbox refs,
  reject networked `RUNNING` without egress refs, and reject `DELETED` without
  teardown receipt.
- [KEEP] Generated and static Launchpad EvidencePacks verify offline through
  `helm-ai-kernel verify --bundle`.
- [KEEP] Enterprise Launchpad route tests and Playwright coverage cover matrix
  rendering, approval escalation, evidence refs, teardown receipt, and
  EvidencePack visibility.
- [KEEP] Enterprise Skills route tests cover scan, install, rollout, receipt,
  usage, and drift surfaces.
- [KEEP] Enterprise route registry/OpenAPI parity passes for the added Launchpad
  and Skills routes.

## Remaining Red-Team Work

- [REBUILD] Prompt injection through app metadata needs a dedicated malicious
  metadata fixture.
- [REBUILD] Malicious AppSpec/SubstrateSpec schema attacks need fuzz or
  adversarial corpus coverage beyond strict schema validation.
- [REBUILD] License spoofing needs tests against forged SPDX/license metadata
  and upstream-source mismatch.
- [REBUILD] Public-key cryptographic Skill Pack signatures are not implemented;
  current first-party verification is keyring/ref/content-hash based.
- [DEFER] Cloud ambiguous-outcome duplicate provision is tested at
  reconciliation logic level only, not against real providers.
- [DEFER] Network egress bypass and container escape need continued live
  container tests as the app catalog expands.
- [DEFER] OpenCode and Kilo Code must pass the OpenClaw/Hermes evidence bar
  before promotion.

## Verdict

[KEEP] The current Skill Packs + Launchpad slice is materially safer than a
normal launcher: it fails closed, blocks host installer patterns, redacts scoped
secrets, quarantines MCP by default, requires promotion evidence, validates
skill metadata/policies, and emits signed receipts/EvidencePacks for the paths
it exercises.

[KEEP] OpenClaw and Hermes are release-backed for `local-container` in `v0.5.4`.

[DEFER] Public GA claims remain blocked until the clean-install gate records a
passing separate-Mac report and the public docs/website checks pass.
