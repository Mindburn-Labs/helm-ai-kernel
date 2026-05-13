# HELM Launch Demo

This local suite demonstrates HELM as a fail-closed execution boundary for
agent actions. It uses only localhost fixtures, temp directories, sample policy
data, and dry-run receipts.

## Run

```bash
make launch-smoke
```

Run individual demos:

```bash
./scripts/launch/demo-local.sh
./scripts/launch/demo-mcp.sh
./scripts/launch/demo-openai-proxy.sh
./scripts/launch/demo-proof.sh
./scripts/launch/demo-console.sh
```

Record sanitized launch transcripts:

```bash
make launch-record-assets
```

## Seven-Action Demo

`scripts/launch/demo-local.sh` starts a local `helm-ai-kernel serve` boundary and calls
`/api/demo/run` for every public launch action:

| Action | Expected verdict |
| --- | --- |
| read ticket / read file | `ALLOW` |
| draft reply / dry run | `ALLOW` |
| small refund / low-risk write | `ALLOW` |
| large refund / high-risk write | `ESCALATE` |
| dangerous shell command | `DENY` |
| export customer list / secret exfiltration | `DENY` |
| modify policy / IAM-like action | `ESCALATE` |

Each action must emit `receipt.receipt_id`, `receipt.signature`,
`proof_refs.receipt_hash`, and `receipt.metadata.side_effect_dispatched ==
false`. The script also verifies every receipt through `/api/demo/verify`.

## MCP Quarantine Demo

`scripts/launch/demo-mcp.sh` discovers the local fixture server, keeps it
quarantined by default, inspects the metadata/schema, classifies risk, creates
an approval record bound to a HELM receipt, approves the registry record, then
allows one schema-pinned `local.echo` call.

Unknown MCP servers, unknown tools, and missing schema pins must return `DENY`
or `ESCALATE`; they must never dispatch to the fixture server.

## Offline Proof And Tamper Failure

`scripts/launch/demo-proof.sh` runs the proof path against localhost only. It
creates a signed `DENY` receipt for the dangerous shell fixture, verifies the
receipt through `/api/demo/verify`, then submits a flipped-verdict copy through
`/api/demo/tamper`. The original receipt must verify, and the tamper attempt
must fail both signature and ProofGraph hash checks.

## Side-Effect Boundary

The launch suite does not contact real payment systems, customer stores, shell
targets, infrastructure APIs, or external model endpoints. The OpenAI-compatible
proxy demo points at `scripts/launch/mock-openai-upstream.py` on localhost.
