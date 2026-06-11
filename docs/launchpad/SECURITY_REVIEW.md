# Launchpad Security Review

Status: Launchpad v1 local-container review passes for OpenClaw and Hermes from
workflow `26198407296`. OpenCode and Kilo Code are `verify_only`; `--version`
smoke checks do not count as live-agent F2 coverage. The `v0.5.9`
clean-install gate remains the package/install release gate.

## Results

- [KEEP] Registry validation blocks `oss_supported` apps unless license,
  redistribution, artifact/build, policy, sandbox, healthcheck, e2e, teardown,
  receipt, and EvidencePack evidence are present.
- [KEEP] F2 attack matrices are blocked until `f2_contract_preflight` proves
  digest parity, command parity, sandbox, egress proxy, writable state paths,
  provider secret projection, MCP manifest parity, healthcheck, EvidencePack,
  and offline verify output.
- [KEEP] `helm-ai-kernel launch promote` blocks app promotion unless the merged
  CI promotion manifest records immutable image digest, cosign signature, syft
  SBOM, grype/trivy scan, provenance, live e2e, EvidencePack, and teardown refs.
- [KEEP] Promotion refs must be tied to the same GitHub workflow run as the
  artifact manifest; stale or unrelated evidence refs are rejected.
- [KEEP] OpenClaw and Hermes are promoted to live support from signed CI
  artifacts, contract preflight, live local-container evidence, teardown
  receipts, and offline EvidencePack verification in workflow `26198407296`.
- [KEEP] OpenCode and Kilo Code stay `verify_only` until live-agent command
  evidence beyond `--version` smoke checks is attached.
- [KEEP] Codex, Claude Code, Cursor, and Junie remain external/BYO adapters; no
  proprietary redistribution claim is made.
- [KEEP] CLI/API launch path returns `ESCALATE` for missing required secrets and
  does not crash.
- [KEEP] Live CI uses one scoped BYO model-provider key from the embedded
  provider catalog. The `HELM_LAUNCHPAD_CI_OPENROUTER_API_KEY` compatibility
  path still maps to `OPENROUTER_API_KEY` only inside the test step.
- [KEEP] `scripts/launch/secret_fragment_audit.py` scans command output, GitHub
  logs, release notes/assets, reports, and EvidencePacks for the scoped test key
  and fixed-length fragments without printing the secret or fragments.
- [KEEP] Installer tests reject missing digest, host `curl | bash`, `git pull`,
  `git stash`, and package-manager mutation inside the current worktree.
- [KEEP] Policy validation requires `permission_bypass_forbidden = true`,
  `recursive_launch_forbidden = true`, and network default `deny`.
- [KEEP] Substrate validation now requires explicit capability metadata for
  isolation strength, network enforcement, secret mode, receipt support,
  teardown proof, status, and the full plan/preflight/launch/healthcheck/
  execute/evidence/reconcile/delete/post-delete lifecycle.
- [KEEP] `availability: supported` substrates must be GA and must require
  receipts and teardown proof; microVM and hosted sandbox adapters remain
  experimental until their runtime adapters pass conformance.
- [KEEP] Runtime preflight tests block host filesystem escape, non-deny network
  defaults, privileged mode, privilege-escalation flags, recursive launch, and
  secret leakage through projected env handles.
- [KEEP] Local-container Docker isolation is documented and receipted as a
  baseline developer substrate. Hardened modes rootless/userns, Docker ECI,
  gVisor, Kata/Firecracker, and dedicated VM are explicit isolation tiers and
  fail closed when requested without matching runtime evidence.
- [KEEP] Local-container BYO model-provider egress is fail-closed:
  non-catalog destinations are rejected, catalog allowlists use a launch-scoped
  proxy path, and runtime start requires an egress proxy receipt for networked
  `RUNNING` launches.
- [KEEP] Egress receipts label CONNECT payloads as opaque and record that the
  proxy proves destination allowlisting only unless token-broker mode is enabled.
- [KEEP] Live conformance tests exercise Docker-backed runtime startup and app
  healthchecks.
- [KEEP] MCP governance tests quarantine unknown servers/tools, require schema
  pins, deny schema drift, require approval receipts for side-effect tools, and
  block revoked tools.
- [KEEP] MCP mediation proof tests cover stdio, HTTP JSON-RPC,
  `/mcp/v1/execute`, SSE primer behavior, generated client configs, MCPB
  packaging, pre-executor schema denial, side-effect approval denial,
  unapproved-server denial, and fail-closed rejection for unsupported WebSocket
  transport.
- [KEEP] Supported app registry entries must reference signed MCP manifests
  with pinned command, package digest, schema hash, tool schema hashes, effect
  labels, required secrets, and network/filesystem grants.
- [KEEP] Generated Launchpad EvidencePacks redact secret-like payloads before
  disk writes and include `04_EXPORTS/launchpad_evidence_graph.json`, a
  hash-chained receipt graph inspectable with `helm-ai-kernel evidence inspect`.
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
- [REBUILD] Proxy-only model gateway credentials are not yet connected for the
  local-container runtime. Current supported apps use logical secret binding
  with launch-process env projection and redaction; do not claim raw-provider
  key elimination until the token/proxy broker lands.
- [REBUILD] License spoofing needs tests against forged SPDX/license metadata
  and upstream-source mismatch.
- [REBUILD] Public-key cryptographic Skill Pack signatures are not implemented;
  current first-party verification is keyring/ref/content-hash based.
- [DEFER] Cloud ambiguous-outcome duplicate provision is tested at
  reconciliation logic level only, not against real providers.
- [DEFER] Network egress bypass and container escape need continued live
  container tests as the app catalog expands.
- [DEFER] Additional apps must pass the four-app evidence bar before promotion.
- [DEFER] Third-party red-team and audit evidence is required before any
  category-leading public claim.

## Verdict

[KEEP] The current Skill Packs + Launchpad slice is materially safer than a
normal launcher: it fails closed, blocks host installer patterns, redacts scoped
secrets, quarantines MCP by default, requires promotion evidence, validates
skill metadata/policies, and emits signed receipts plus hash-chained
EvidencePacks for the paths it exercises.

[KEEP] OpenClaw and Hermes are artifact-backed for live `local-container`
Launchpad v1 support. Release `v0.5.9` packages the
Launchpad registry/policy data required for Homebrew clean installs.

[KEEP] The GitHub macOS clean-install gate passed for `v0.5.9` with Homebrew
install, supported app launches, cascade delete, offline EvidencePack
verification, and a zero-finding secret-fragment audit. Hetzner live beta
remains fail-closed until a scoped token is available.
