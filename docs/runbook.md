# Operations Runbook: helm-ai-kernel

Local diagnostics for a running kernel. Every command below is registered in
`core/cmd/helm-ai-kernel/`; run `helm-ai-kernel help` for the full surface.

## Is it up, and is the setup sane?

```bash
helm-ai-kernel health            # local HELM server health
helm-ai-kernel doctor            # crypto, policies, connectors, config (alias: diag)
```

`doctor` is the first thing to run on a machine that "used to work" — it checks the
setup surfaces independently rather than only asking the server whether it is alive.

## What did it decide, and why?

```bash
helm-ai-kernel receipts tail --agent <id>   # durable receipts as they land
helm-ai-kernel traces                       # hash-linked harness traces
helm-ai-kernel boundary status              # execution-boundary status
helm-ai-kernel boundary records --verdict <ALLOW|DENY|ESCALATE>
```

Receipts and boundary records are the audit surface. There is no `audit.log` file to
tail; durability lives in the receipt store and the transparency log.

```bash
helm-ai-kernel log sth                      # signed tree head
helm-ai-kernel log verify-inclusion         # prove a receipt is in the log
helm-ai-kernel verify --bundle <path> --json  # verify an exported EvidencePack
```

## Stopping governed calls

```bash
helm-ai-kernel freeze --principal <id> --data-dir <dir>
helm-ai-kernel unfreeze --principal <id> --data-dir <dir>
```

Global freeze is the deliberate stop lever. Use it when you need governed calls
to stop before you have diagnosed why — freezing is cheap, and a fail-closed
kernel that denies is behaving correctly, not malfunctioning.

The freeze denies every Guardian evaluation, with `SYSTEM_FROZEN`, in each
process that reads that data directory: `serve`, `proxy` and `mcp serve` on this
host. It does not stop approval-grant consumption, dispatch admission or effect
reservation, which do not ask the Guardian, and it does not cancel work already
in flight. The scoped emergency-stop fence
([EMERGENCY_STOP_FENCE.md](EMERGENCY_STOP_FENCE.md)) covers consumption and
admission for one tenant and workspace.

The freeze is `freeze_state.json` in the kernel data directory. Pass the same
`--data-dir` the server runs with (`serve --data-dir`, `mcp serve --data-dir`).
Without it both sides use `$HELM_DATA_DIR`, then `./data` under the working
directory. `proxy` reads `$HELM_DATA_DIR`. The file holds per host, not across
replicas.

## Policy

```bash
helm-ai-kernel policy            # compilation and testing
helm-ai-kernel bundle build <file> --language <cel|rego|cedar>
```

Policy is compiled into signed bundles from CEL, Rego, or Cedar sources. There is no
runtime policy cache to flush and no admission controller in this repo, so "reload the
policies" is not an operation that exists — rebuild the bundle and restart.

## A note on this file

Until 2026-08-09 this runbook told operators to run `helm-ai-kernel status`,
`helm-ai-kernel tail -f audit.log`, and `helm-ai-kernel reload-policies`. None of the
three is a registered subcommand — each returns "Unknown command". It also instructed
them to check a Kyverno/OPA policy cache for corruption; the only file in this
repository that has ever mentioned Kyverno was this runbook.

It was generator boilerplate cloned across peripheral repos in June 2026 and was named
by the 2026-06-29 markdown estate audit. Replaced under HELM-486 with commands verified
against `core/cmd/helm-ai-kernel/`.
