---
title: HELM Launchpad
last_reviewed: 2026-06-29
---

# HELM Launchpad

Launchpad runs selected AI app contracts through the HELM AI Kernel execution
boundary. The public claim is intentionally narrow: local-container proof for
supported apps, verify-only contract checks for candidates, signed receipts, and
offline EvidencePack verification.

Start with `helm-ai-kernel quickstart` before using Launchpad. Hosted account
pairing, cloud substrates, and commercial workflows are outside this public
Kernel proof path.

## Current Local Support

| App | Public status | Command | What is proven |
| --- | --- | --- | --- |
| OpenClaw | local app proof | `helm up openclaw` | contract preflight, local-container launch, receipts, EvidencePack |
| Hermes | local app proof | `helm up hermes --target local` | contract preflight, local-container launch, receipts, EvidencePack |
| OpenCode | `verify_only` | `helm-ai-kernel app preflight opencode --json` | signed artifact and contract preflight only |
| Kilo Code | `verify_only` | `helm-ai-kernel app preflight kilocode --json` | signed artifact and contract preflight only |

Verify-only pages do not claim a live agent workload. They prove registry,
artifact, policy, and preflight shape only. `--version` smoke checks do not count as live-agent F2 coverage.

## Source Truth

- CLI entrypoint: `core/cmd/helm-ai-kernel/launch_cmd.go`
- Runtime package: `core/pkg/launchpad/`
- App and substrate registry: `registry/launchpad/`
- Policy packs: `policies/launchpad/`
- Contract schemas: `schemas/launchpad/`

## Local Commands

```bash
helm up openclaw
helm up hermes --target local
helm-ai-kernel app preflight opencode --json
helm-ai-kernel app preflight kilocode --json
helm-ai-kernel verify --bundle <pack>
```

Launchpad reads local EvidencePack trust config from `helm/helm.yaml`,
`HELM_EVIDENCE_TRUST_CONFIG`, or `$HELM_DATA_DIR/trust/evidence-pack.json`.

## Safety Boundary

- Runtime verdicts are only `ALLOW`, `DENY`, or `ESCALATE`.
- Unknown MCP servers and tools are quarantined or escalated before dispatch.
- Supported app proof requires signed artifact references, policy pack,
  sandbox, healthcheck, teardown, signed receipts, EvidencePack export, and
  offline verification.
- Local-container is the only public default substrate in this page.
- Cloud substrates are opt-in beta/dry-run material and are not part of this
  public Kernel proof.
- Generated import candidates remain untrusted until sandbox build, SBOM,
  vulnerability scan, license review, smoke test, teardown, and evidence refs
  are complete.

## Evidence Inspection

```bash
helm-ai-kernel launch evidence <launch_id> --output <dir>
helm-ai-kernel evidence inspect <pack>
helm-ai-kernel verify --bundle <pack>
```

Evidence must include lifecycle receipts, artifact refs, policy refs, and a
verifier result. If a required receipt is missing, hold the claim.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| App launch fails before healthcheck | Run the app preflight command and inspect the registry entry. |
| Verify-only app is described as live | Correct the copy to `verify-only` until live workload evidence exists. |
| EvidencePack does not verify | Re-export the pack and verify the original file before editing or copying it. |
| Cloud path appears in public copy | Move it to maintainer evidence or mark it beta/dry-run outside the public proof path. |
