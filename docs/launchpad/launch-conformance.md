---
title: Launchpad Launch Conformance Review Oracle
last_reviewed: 2026-06-19
---

# Launchpad Launch Conformance Review Oracle

This is the PR-review oracle for Launchpad changes that can affect
`openclaw/local-container` or `hermes/local-container` launch behavior. Use it
before approving registry, policy, artifact, runtime, receipt, EvidencePack, or
F2 report changes.

## Scope

| Case | App path | Review intent | Source truth |
| --- | --- | --- | --- |
| U-LAUNCH-02 | OpenClaw on `local-container` | Container path for a live browser-split agent with model-provider egress through the launch-scoped proxy. | `registry/launchpad/apps/openclaw.yaml`, `policies/launchpad/apps/openclaw.safe.toml`, `registry/launchpad/mcp/openclaw.default.yaml` |
| U-LAUNCH-03 | Hermes on `local-container` | Installer-style agent path that must still resolve to a signed artifact, sandboxed runtime, and no host mutation. | `registry/launchpad/apps/hermes.yaml`, `policies/launchpad/apps/hermes.safe.toml`, `registry/launchpad/mcp/hermes.default.yaml` |

OpenClaw and Hermes are the only current `agent_live` Launchpad apps. OpenCode
and Kilo Code stay `verify_only` until they pass the same live-agent evidence
bar. Do not use `--version` smoke evidence as F2 coverage.

## Review Checklist

- Registry entries keep `availability: oss_supported`, `support_level:
  agent_live`, immutable `@sha256:` images, `sha256:` install digests, and
  matching `supply_chain_evidence.artifact_digest`.
- Promotion evidence stays bound to one workflow run and includes cosign
  signature, syft SBOM, grype or trivy vulnerability scan, provenance,
  live-e2e, teardown, receipt, and EvidencePack refs.
- `f2_contract_preflight` remains required before any prompt, attack matrix, or
  public F2 report can run.
- The launch plan proves command parity, digest parity, sandbox profile,
  writable HOME/cache/state paths, model gateway secret projection, MCP manifest
  parity, healthcheck definition, EvidencePack export, and offline verification.
- Networked runs require a launch-scoped egress receipt before `RUNNING`.
  Non-catalog destinations must fail closed.
- MCP unknown servers and tools remain quarantined until a scoped approval
  receipt exists. Side-effect tools require approval receipts.
- Runtime setup failures are `RUNTIME_REPAIR_REQUIRED`, `PLAN_DENY`, or
  `PLAN_ESCALATE`; they are never counted as `ATTACK_BLOCKED`.
- OpenClaw/Hermes docs and public claims continue to name only the supported
  proof: signed artifact, local-container launch, receipts, teardown, and
  offline-verifiable EvidencePack.

## Forbidden Actions

Launchpad review must reject any change that allows these actions in the host
or current worktree path:

| Forbidden action | Why it fails review | Implementation guard |
| --- | --- | --- |
| `curl | bash`, `curl | sh`, `irm ... | iex` | Host pipe-to-shell installers bypass artifact and policy review. | `core/pkg/launchpad/install/artifact_installer.go` |
| `git pull` in `current/` | Mutable source updates break digest parity and replayable evidence. | `core/pkg/launchpad/install/source_installer.go` |
| `npm install` in `current/` | Package-manager mutation breaks reviewed dependency state. | `core/pkg/launchpad/install/source_installer.go` |
| `pnpm install` or `yarn install` in `current/` | Same mutable dependency hazard as `npm install`. | `core/pkg/launchpad/install/source_installer.go` |
| `git stash` or `git stash apply` | Hides unreviewed state transitions from evidence review. | `core/pkg/launchpad/install/source_installer.go` |

Sandboxed upstream installers remain a separate artifact strategy. They must
run inside the sandbox, not as host setup, and they do not replace signed OCI
promotion evidence for `oss_supported` apps.

## Failure Branch Table

| Branch | Expected verdict/status | Reason code | Expected evidence |
| --- | --- | --- | --- |
| F2 contract preflight fails | `DENY` / `DENIED` | `ERR_LAUNCHPAD_F2_CONTRACT_REPAIR_REQUIRED` | Contract preflight JSON, kernel verdict, sandbox preflight receipt, MCP quarantine receipt, escalation receipt, blocked healthcheck receipt, EvidencePack. No runtime start. |
| Artifact digest missing or image not pinned | `DENY` / `DENIED` | `ERR_LAUNCHPAD_ARTIFACT_DIGEST_NOT_PINNED` | Kernel verdict and launch plan showing artifact verification failure. No install/start receipts. |
| Artifact digest differs from supply-chain evidence | `DENY` / `DENIED` | `ERR_LAUNCHPAD_ARTIFACT_DIGEST_MISMATCH` | Kernel verdict and launch plan with mismatched digest fields. No install/start receipts. |
| Cosign signature ref missing for supported artifact | `DENY` / `DENIED` | `ERR_LAUNCHPAD_COSIGN_SIGNATURE_REQUIRED` | Kernel verdict and launch plan naming the missing signature evidence. No install/start receipts. |
| SBOM evidence missing | `DENY` / `DENIED` | `ERR_LAUNCHPAD_SBOM_REQUIRED` | Kernel verdict and launch plan naming the missing SBOM evidence. No install/start receipts. |
| Vulnerability scan evidence missing | `DENY` / `DENIED` | `ERR_LAUNCHPAD_VULNERABILITY_SCAN_REQUIRED` | Kernel verdict and launch plan naming the missing grype/trivy evidence. No install/start receipts. |
| Model-provider catalog lookup fails | `ESCALATE` / `ESCALATED` | `ERR_LAUNCHPAD_MODEL_PROVIDER_CATALOG` | Failure plan, CPI output, escalation receipt, EvidencePack. No runtime start. |
| Required model-provider secret missing | `ESCALATE` / `ESCALATED` | `ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING` | Kernel verdict, contract preflight, MCP quarantine receipt, model-gateway receipt, escalation receipt, blocked healthcheck receipt, EvidencePack. No secret grant or runtime start. |
| App lacks full conformance for live support | `ESCALATE` / `ESCALATED` | `ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED` | Launch plan naming missing conformance, CPI output, escalation receipt, EvidencePack. No runtime start. |
| CPI cannot evaluate launch actions | `ESCALATE` / `ESCALATED` | `ERR_LAUNCHPAD_CPI_UNAVAILABLE` | Plan hash, ActionIR, and error evidence. No runtime start. |
| CPI policy conflict | `ESCALATE` / `ESCALATED` | `ERR_LAUNCHPAD_POLICY_CONFLICT` | CPI output with conflict result hash, ActionIR, escalation evidence. No runtime start. |
| CPI escalates requested side effects | `ESCALATE` / `ESCALATED` | `ERR_LAUNCHPAD_CPI_ESCALATE` | CPI output, ActionIR, escalation evidence. No runtime start. |
| CPI denies requested side effects | `DENY` / `DENIED` | `ERR_LAUNCHPAD_POLICY_DENY` | CPI output, ActionIR, denial evidence. No runtime start. |
| Unknown MCP server or tool | `ESCALATE` | `ERR_MCP_SERVER_QUARANTINED` | MCP quarantine decision and no side-effect dispatch unless approval receipt exists. |
| Runtime starts without required egress receipt | `ALLOW` plan, run becomes `REPAIR_REQUIRED` | Runtime repair required | Runtime failure receipt, runtime environment evidence, EvidencePack. No `RUNNING` state. |
| Healthcheck fails after runtime start | `ALLOW` plan, run becomes `REPAIR_REQUIRED` | Runtime repair required | Healthcheck failure receipt, runtime environment evidence, EvidencePack, teardown expectation. |

## Expected Success Evidence

An accepted U-LAUNCH-02 or U-LAUNCH-03 run must attach or regenerate all of the
following evidence:

- `launch_plan` with `KernelVerdict: ALLOW`, `Status: VALIDATED`, stable
  `plan_hash`, `ActionIR`, and `TeardownIR`.
- `f2_contract_preflight` result with verdict `ALLOW`.
- `launchpad-kernel-verdict.json`, `launchpad-contract-preflight.json`,
  `launchpad-sandbox-preflight.json`, `launchpad-mcp-quarantine.json`,
  `launchpad-model-gateway-grant.json` for networked model-provider paths.
- `launchpad-secret-grants.json` only after an `ALLOW` plan and only for the
  launch-scoped provider env.
- `launchpad-install.json`, `launchpad-launch.json`,
  `launchpad-start.json`, and `launchpad-healthcheck.json`.
- `launchpad-egress-proxy.json` for OpenRouter-backed paths before `RUNNING`.
- `launchpad-teardown.json` and `teardown_proof.json` after cascade delete.
- EvidencePack directory or archive that verifies offline with
  `helm-ai-kernel verify --bundle <pack>`.
- Raw per-case F2 results if the PR makes or changes an attack-matrix claim.

## Reviewer Commands

```bash
helm-ai-kernel launch plan openclaw local-container --json
helm-ai-kernel launch openclaw local-container --headless --output json
helm-ai-kernel launch plan hermes local-container --json
helm-ai-kernel launch hermes local-container --headless --output json
helm-ai-kernel launch delete <launch_id> --cascade
helm-ai-kernel verify --bundle <pack>
```

Use `scripts/launch/clean_install_gate.sh` for release-gate review. Use
`docs/launchpad/CONFORMANCE.md`, `docs/launchpad/CLEAN_INSTALL_GA.md`, and
`docs/launchpad/v1_report.json` as current release truth when these commands
are not re-run in the PR.
