---
title: Agent Risk Scan
last_reviewed: 2026-08-11
---

# Agent Risk Scan

`helm-ai-kernel scan` is the local-first AI agent risk audit command. It reads
local Claude, Codex, MCP, source, and optional workstation receipt evidence,
then emits an anonymized `RiskEnvelope` plus local preview and evidence-pack
artifacts.

## Audience

Use this command when you need a safe first-pass audit of agent access before
installing an in-path boundary, or when you need to turn observe-mode receipts
into the same risk vocabulary used by static scan.

## Outcome

After running `scan`, you can show:

- an A–F boundary grade for the scanned tree, with its reason;
- which agent surface was detected;
- which risk codes were emitted;
- how many MCP servers and config files were observed;
- a content hash for the exported envelope;
- a local preview generated only from the envelope;
- an evidence pack containing only anonymized scan artifacts.

## Capability Matrix

| Capability | Command or artifact |
| --- | --- |
| Static local scan | `helm-ai-kernel scan --path .` |
| RiskEnvelope JSON | `--risk-envelope out.json` |
| Markdown preview | `--preview out.md` |
| HTML preview | `--preview out.html` |
| Evidence pack tar | `--evidence-pack pack.tar` |
| Offline evidence-pack verification | `helm-ai-kernel verify-scan --bundle pack.tar` |
| Explicit upload | `--upload --upload-url <url> --yes` |
| Receipt projection | `--from-receipts <dir>` |
| Local salt | `--salt-file <path>` |
| Exclude user config | `--no-user-config` |
| Content hash | `envelope_content_hash` |
| Boundary grade | `boundary_grade`, `Boundary grade:` on stdout and in both previews |

## Boundary Grade

A static scan reports one A–F grade for the scanned tree. The grade is
deterministic — the same tree produces the same letter and the same reason —
and it is computed from the shadow scanner findings plus whether HELM was
detected in the tree:

| Grade | Condition |
| --- | --- |
| A | boundary present with no ungoverned signals, or no agent surface at all |
| B | boundary present; MEDIUM signals not yet routed through it |
| C | boundary present; HIGH-severity exposures remain |
| D | agent surface detected with no boundary, no HIGH findings |
| F | agent surface with no boundary and HIGH-severity exposure |

The grade appears on stdout, in `boundary_grade` inside the envelope, and as
the headline of the Markdown and HTML previews:

```
Boundary grade: F — 3 agent signal(s) with no execution boundary and 1 HIGH-severity exposure(s)
```

`boundary_grade` is optional in the schema. Receipt projections observe traffic
rather than a static tree, so they omit it rather than report a default letter.

The reason is not a free-text field. The envelope and the schema both accept
only the grader's own deterministic sentences, so no scanned path, repository
name, or secret can reach an upload body through it.

Scope, as with the rest of a static scan: the grade describes declared and
locally discoverable configuration. It does not establish what an agent
executed at runtime.

## Static Scan

Run a local scan without upload:

```bash
helm-ai-kernel scan \
  --path . \
  --cohort unknown \
  --salt-file ~/.config/helm-ai-kernel/scan_salt.hex \
  --risk-envelope out/risk-envelope.json \
  --preview out/risk-report.md \
  --preview out/risk-report.html \
  --evidence-pack out/risk-scan-pack.tar
```

For a static scan, the scanner reads recognized config shapes from the declared
`--path` tree:

- `.mcp.json`
- `mcp.json`
- `.claude.json`
- `claude_desktop_config.json`
- `.claude/settings*.json`
- `.codex/config.toml`

It also reads this bounded set of user-level candidates by default, rather than
walking the home directory:

- `~/.claude.json`
- `~/.claude/settings.json` and `~/.claude/settings.local.json`
- `~/.codex/config.toml`
- `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS
  or `~/.config/Claude/claude_desktop_config.json` on Linux
- `.mcp.json` from an enabled Claude plugin selected through its local installed
  plugin inventory; when more than one installation is present, the latest
  RFC3339 timestamp wins

Project settings take precedence over a user setting when determining the
reported permission mode. Use `--no-user-config` to exclude only the bounded
user-level candidates; it does not skip configuration below `--path`. The flag
has no effect in `--from-receipts` mode.

Missing optional user config is normal. A discovered recognized config file
that cannot be read or parsed stops the static scan without exporting an
artifact, so a partial configuration observation is not presented as complete.

It also uses the local shadow scanner findings to project risk codes such as
`MCP_WRITE_SCOPE_WITHOUT_APPROVAL`, `SECRET_CLASS_AGENT_READABLE`,
`NO_MANAGED_SETTINGS`, and `NO_AUDIT_EXPORT`.

## Receipt Projection

Project observe-mode receipts into the same envelope shape:

```bash
helm-ai-kernel scan \
  --from-receipts ./receipts \
  --salt-file ~/.config/helm-ai-kernel/scan_salt.hex \
  --risk-envelope out/risk-envelope.json \
  --preview out/risk-report.md
```

Receipt mode reads `.json` and `.ndjson` files containing
`agent_run_receipt.v1` or workstation policy decision receipts. It maps
observed effect classes into the existing `RiskCode`, `Severity`, and
`ToolClass` vocabulary. It does not change runtime dispatch and does not add
enforce behavior.

## Privacy Boundary

`scan` is private by non-collection plus a local-only salt. The salt is
generated with CSPRNG bytes, persisted with `0600` permissions, and never
serialized into the envelope, preview, evidence pack, or upload body.

These values are not exported:

- raw paths;
- raw repository names;
- raw MCP server names;
- raw commands or command bodies;
- raw prompts;
- source snippets;
- metadata targets;
- secret values;
- local salts.

The evidence-pack tar contains exactly:

- `evidence-pack.json`, using the generic `contracts.EvidencePack` contract;
- `risk-envelope.json`;
- zero or more requested `.md` or `.html` previews under `previews/`.

It adds no independent archive index, seal, signature, or trust format. The raw
source pack, raw config files, and raw receipts stay local.

## Offline Verification

Verify an archive without uploading it:

```bash
helm-ai-kernel verify-scan --bundle out/risk-scan-pack.tar
helm-ai-kernel verify-scan --bundle out/risk-scan-pack.tar --json
```

The verifier checks:

- the generic EvidencePack validator's required identifiers and status fields,
  required `attestation.pack_hash`, and its JCS-computed contract hash; this
  path does not independently apply the complete EvidencePack JSON Schema;
- the canonical RiskEnvelope representation, content hash, schema, and privacy
  non-collection fields;
- the pack-to-envelope IDs and hashes, plus every declared artifact path and
  SHA-256 hash;
- the exact supported layout, rejecting missing, unexpected, unsupported, or
  hash-mismatched files and unsafe archive entries.

A signature or signer in this local risk-scan pack is rejected as unsupported:
the scan has no independently trusted signer. `VERIFIED` therefore means local
artifact integrity only. It does not prove that execution occurred or was
governed or authorized, nor does it establish runtime provenance or live
posture.

## Upload Contract

Upload is off by default. When `--upload` is used, `--upload-url` is required.
The command prints the destination URL, exact body hash, body size, and privacy
summary before sending. Without `--yes`, upload is not sent.

Only the anonymized RiskEnvelope JSON body is posted. No backend ingestion route
is implied by this command; operators must provide the explicit upload URL.

## Test Coverage

| Behavior | Test |
| --- | --- |
| salt generation, `0600` persistence, and local-only salt behavior | `core/pkg/riskenvelope/envelope_test.go` |
| Go enum to JSON Schema parity | `core/pkg/riskenvelope/envelope_test.go` |
| grade reason is a closed sentence set in both Go and the schema | `core/pkg/riskenvelope/envelope_test.go`, `core/pkg/riskscan/scan_test.go` |
| grade reaches the envelope, previews, and stdout | `core/pkg/riskscan/scan_test.go`, `core/cmd/helm-ai-kernel/scan_cmd_test.go` |
| content hash changes when findings change | `core/pkg/riskenvelope/envelope_test.go` |
| static projection omits raw paths, repo names, commands, and secrets | `core/pkg/riskscan/scan_test.go` |
| Markdown, HTML, and evidence pack outputs omit raw inputs | `core/pkg/riskscan/scan_test.go` |
| deterministic evidence pack tar contents | `core/pkg/riskscan/scan_test.go` |
| upload sends the exact printed envelope body | `core/pkg/riskscan/scan_test.go`, `core/cmd/helm-ai-kernel/scan_cmd_test.go` |
| `--upload-url` and `--yes` gates | `core/cmd/helm-ai-kernel/scan_cmd_test.go` |
| user config opt-in, project-over-user precedence, and CLI opt-out | `core/pkg/riskscan/scan_test.go`, `core/cmd/helm-ai-kernel/scan_cmd_test.go` |
| receipt-derived risk mapping and raw receipt leakage checks | `core/pkg/riskscan/scan_test.go`, `core/cmd/helm-ai-kernel/scan_cmd_test.go` |

Run the focused test set:

```bash
cd core
go test ./pkg/riskenvelope ./pkg/riskscan ./pkg/shadow ./cmd/helm-ai-kernel
```

Then run repository gates:

```bash
make verify-boundary
make docs-coverage
make docs-truth
```

## Limits

Static scan shows declared and locally discoverable surface area; it does not
prove what an agent actually used. Receipt projection shows observed traffic
only for receipts supplied to `--from-receipts`. Enforce mode remains the
runtime boundary path and is not enabled by `scan`.

Do not market `RiskEnvelope` as k-anonymity. Suppression metadata exists in the
schema, but v1 does not implement an aggregation or suppression model.
