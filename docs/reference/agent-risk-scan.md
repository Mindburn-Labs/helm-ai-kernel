---
title: Agent Risk Scan
last_reviewed: 2026-06-30
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

- which agent surface was detected;
- which risk codes were emitted;
- how many MCP servers and config files were observed;
- a content hash for the exported envelope;
- a local preview generated only from the envelope;
- an evidence pack containing only anonymized scan artifacts.

## Source Truth

- CLI: [`core/cmd/helm-ai-kernel/scan_cmd.go`](../../core/cmd/helm-ai-kernel/scan_cmd.go)
- Static projector: [`core/pkg/riskscan/scan.go`](../../core/pkg/riskscan/scan.go)
- Receipt projector: [`core/pkg/riskscan/receipts.go`](../../core/pkg/riskscan/receipts.go)
- Envelope contract: [`core/pkg/riskenvelope/envelope.go`](../../core/pkg/riskenvelope/envelope.go)
- JSON Schema: [`protocols/json-schemas/risk-envelope/v1.json`](../../protocols/json-schemas/risk-envelope/v1.json)
- Tests: [`core/pkg/riskscan/scan_test.go`](../../core/pkg/riskscan/scan_test.go), [`core/cmd/helm-ai-kernel/scan_cmd_test.go`](../../core/cmd/helm-ai-kernel/scan_cmd_test.go)

## Capability Matrix

| Capability | Command or artifact | Source |
| --- | --- | --- |
| Static local scan | `helm-ai-kernel scan --path .` | `riskscan.Scan` |
| RiskEnvelope JSON | `--risk-envelope out.json` | `riskscan.EnvelopeJSON` |
| Markdown preview | `--preview out.md` | `riskscan.RenderMarkdown` |
| HTML preview | `--preview out.html` | `html/template` in `riskscan.RenderHTML` |
| Evidence pack tar | `--evidence-pack pack.tar` | `riskscan.WriteEvidencePack` |
| Explicit upload | `--upload --upload-url <url> --yes` | `riskscan.UploadEnvelope` |
| Receipt projection | `--from-receipts <dir>` | `riskscan.ScanReceipts` |
| Local salt | `--salt-file <path>` | `riskenvelope.LoadOrCreateSaltFile` |
| Content hash | `envelope_content_hash` | `riskenvelope.Seal` |

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

The scanner reads these local config shapes when present:

- `.mcp.json`
- `mcp.json`
- `claude_desktop_config.json`
- `.claude/settings*.json`
- `.codex/config.toml`

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

The evidence pack contains only:

- `risk-envelope.json`;
- `schema-validation.json`;
- `privacy-manifest.json`;
- `source-pack-hash.json`;
- requested previews.

The raw source pack, raw config files, and raw receipts stay local.

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
| content hash changes when findings change | `core/pkg/riskenvelope/envelope_test.go` |
| static projection omits raw paths, repo names, commands, and secrets | `core/pkg/riskscan/scan_test.go` |
| Markdown, HTML, and evidence pack outputs omit raw inputs | `core/pkg/riskscan/scan_test.go` |
| deterministic evidence pack tar contents | `core/pkg/riskscan/scan_test.go` |
| upload sends the exact printed envelope body | `core/pkg/riskscan/scan_test.go`, `core/cmd/helm-ai-kernel/scan_cmd_test.go` |
| `--upload-url` and `--yes` gates | `core/cmd/helm-ai-kernel/scan_cmd_test.go` |
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
