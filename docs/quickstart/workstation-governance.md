# Protect Local Coding Agents

HELM can sit around Codex, Claude Code, and similar local agent workflows. The
goal is narrow: selected effects cross a HELM boundary before dispatch, and
each decision leaves a local receipt.

HELM is not a competing coding agent. It evaluates the actions your agent wants
to take.

## Install A Local Hook

Inspect the writes first:

```bash
helm-ai-kernel setup codex --dry-run --json
helm-ai-kernel setup claude-code --dry-run --json
```

Install the local integration:

```bash
helm-ai-kernel setup codex --yes
helm-ai-kernel setup claude-code --yes
```

Setup writes draft policy and quarantine artifacts. It does not approve tools
or grant broad operating permissions.

## Scan The Agent Surface

Before installing an in-path hook, run the local risk scanner against the repo
and agent config files:

```bash
mkdir -p out
helm-ai-kernel scan \
  --path . \
  --risk-envelope out/risk-envelope.json \
  --preview out/risk-report.md
```

The scan emits an anonymized local envelope and preview. It does not change
runtime dispatch, approve tools, or upload anything.

## Prove A Denial

Ask the local agent to attempt an action the starter policy denies, such as a
risky shell cleanup. HELM should block before dispatch and write a receipt.

Verify the receipt:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/wpd_<decision>.json
```

Expected fields:

```text
verdict: DENY
reason: OPERATE_PERMISSIONS_EMPTY
effect: WORKSTATION_SHELL_COMMAND
signature: true
```

## Prove An Escalation

For MCP-backed local tools, unknown servers and missing scoped approvals should
pause as `ESCALATE`:

```bash
helm-ai-kernel mcp authorize-call \
  --server-id helm-demo-shell \
  --tool-name pwd
```

Use the approval loop in [Quickstart](/quickstart#see-an-escalation). Then
rerun the original action. Approval never resumes it automatically.

## Revoke Access

```bash
helm-ai-kernel mcp revoke \
  --server-id helm-demo-shell \
  --reason "repo inspection finished"
```

The next evaluation must fail closed when the approval is revoked, expired, or
outside its server, tool, or effect scope.

## Inspect Receipts

```bash
helm-ai-kernel mcp pending --json
helm-ai-kernel mcp receipts --json
helm-ai-kernel boundary records --json
```

The report is receipt-scoped and covers only configured hooks and adapters.
