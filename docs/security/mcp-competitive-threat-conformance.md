---
title: MCP Competitive Threat Conformance
last_reviewed: 2026-07-16
---

# MCP Competitive Threat Conformance

HELM AI Kernel proves MCP tool-call governance at the execution boundary. The
proof path is not a guardrail claim: it emits source-owned decisions, signed
receipts, a sealed EvidencePack, and offline verifier output before any public
or customer proof claim is made.

Run the full pack:

```bash
helm-ai-kernel mcp proof \
  --scenario all \
  --out /tmp/helm-mcp-proof \
  --run-id public-mcp-proof \
  --at 2026-06-09T00:00:00Z \
  --json
```

Then verify the EvidencePack reported by the command:

```bash
helm-ai-kernel verify --bundle /tmp/helm-mcp-proof/public_mcp_proof/evidencepacks/public_mcp_proof --profile dev-local --json
```

## Golden Cases

| Scenario | Expected boundary result |
| --- | --- |
| `approved_reversible_local_effect` | Valid scoped approval and pinned schema dispatch exactly one local file effect through `SafeExecutor`; identical sequential replay returns its stored receipt with no redispatch. |
| `malicious_unknown_mcp` | Unknown or malicious MCP server returns `ESCALATE` with no dispatch. |
| `prompt_injected_tool_output` | Tool-output instruction cannot trigger a side effect without an approval receipt. |
| `excessive_agency` | Destructive autonomous action returns `DENY` before dispatch. |
| `invalid_approval_scope` | Unrecognized or out-of-scope approval receipt returns `DENY` before dispatch. |
| `confused_deputy_scope_mismatch` | Launch or principal scope mismatch returns `DENY`. |
| `missing_schema_pin` | Approved server without a pinned tool schema returns `ESCALATE`. |
| `schema_drift` | Caller schema hash mismatch returns `DENY`. |

Every negative scenario must emit `dispatched=false`, a receipt under
`02_PROOFGRAPH/receipts/`, and exported authorization inputs plus an evaluation
artifact. The signed policy receipt binds the input hash in `args_hash` and the
evaluation hash in `output_hash`. The positive scenario emits exactly one
dispatch, a signed execution receipt whose `output_hash` is the hash of the
exported local effect file, and an identical durable receipt envelope on
sequential replay. The pack seal lives at `07_ATTESTATIONS/evidence_pack.sig`;
the CLI also requires offline verification, tamper rejection, and a complete
duration below 60 seconds.

The default `all` run is the complete proof and must report
`proof_scope=complete` and `proof_complete=true`. A named `--scenario` run is
explicitly `vector_only`; it is useful for diagnosis but is not a
positive-and-negative proof claim. This proof demonstrates sequential
same-effect idempotency only. It does not claim replay/reordering detection,
concurrent exactly-once execution, or crash-recovery exactly-once execution.

## Source Truth

- CLI: [`mcp_proof_cmd.go`](../../core/cmd/helm-ai-kernel/mcp_proof_cmd.go)
- Tests: [`mcp_proof_cmd_test.go`](../../core/cmd/helm-ai-kernel/mcp_proof_cmd_test.go)
- MCP decisions: [`governance.go`](../../core/pkg/launchpad/mcp/governance.go)
- Offline verifier: [`verifier.go`](../../core/pkg/verifier/verifier.go)

## Validation

```bash
go test ./core/cmd/helm-ai-kernel -run 'TestRunMCPProof|TestRunMCPCmdHelpIncludesProof'
go test ./core/pkg/launchpad/mcp ./core/pkg/evidence ./core/pkg/verifier ./core/pkg/runtimeadapters/mcp ./core/pkg/launchpad/receipts ./core/pkg/executor ./core/pkg/crypto
```
