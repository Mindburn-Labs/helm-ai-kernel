---
title: Skill Packs
last_reviewed: 2026-07-01
---

# Skill Packs

Skill Packs are scoped instruction packages for agents. They can guide an
agent, but they do not grant tool permissions.

## Inspect And Verify

```bash
helm-ai-kernel skills search --json
helm-ai-kernel skills inspect helm/repo-auditor --json
helm-ai-kernel skills verify helm/repo-auditor --json
```

Run these from a checkout of this repository: the first-party packs live in
`registry/skills/helm/` and are not inside the binary.

Skill Packs are not signed, and nothing a pack says about itself counts as
verification. `skills verify` (also available as `skills scan`) reports a
`publisher_verification` state it computes:

| State | Meaning | Result |
| --- | --- | --- |
| `first_party` | Every file of the pack hashes to the SHA-256 digest that this binary was built with for the pack's id and version. | `ALLOW` unless another check objects, exit 0 |
| `first_party_mismatch` | The binary pins this id and version, and the pack's files differ. | `DENY`, exit 1 |
| `unsigned` | The pack is not one the binary pins. No publisher was verified. | `DENY` if the pack declares `status: verified`, otherwise `ESCALATE`; exit 1 |

`first_party` is a digest comparison against a manifest compiled into the
binary. It shows that the pack is the one in the source tree the binary was
built from, so it is worth as much as the binary you run. No signature is
checked. A pack from any other publisher cannot be verified today.

The verdict is reached under rules built into the binary. A `policy_ref` in the
pack, or a policy file next to it, does not change the verdict.

## Install For A Repo

```bash
helm-ai-kernel skills install helm/repo-auditor \
  --agent codex \
  --scope repo \
  --json
```

Repo-scoped install writes the projected skill and receipt metadata, and only
for a pack that verifies as `first_party`. Every other pack is blocked and
nothing is written. User-scope install escalates and writes no projected skill
by default.

## Export A Codex Plugin

```bash
helm-ai-kernel skills export helm/repo-auditor \
  --format codex-plugin \
  --output ./dist/repo-auditor
```

Exported plugin MCP entries stay pending and hooks stay off by default. Export
refuses a pack the scan denies and still packages an unsigned pack the scan
escalates; `plugin.json` records the scan verdict and publisher state.

## Revoke

```bash
helm-ai-kernel skills revoke helm/repo-auditor --json
```

Revocation removes HELM-managed projection files and writes a revoke receipt.
