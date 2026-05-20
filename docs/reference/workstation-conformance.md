# Workstation Governance Conformance

The workstation conformance pack lives at `protocols/conformance/workstation/v1/conformance-pack.json`.

Certification modes:

| Mode | Meaning |
| --- | --- |
| `observe-only` | Adapter imports manifests, emits signed Agent Run Receipts, binds artifact hashes, and replays deterministically. |
| `enforceable` | Observe-only plus selected-effect policy decision receipts and CLI/hook refusal for denied effects. |
| `high-risk-effect-capable` | Enforceable plus memory write, recurring loop, and tainted-context fixtures. |

Run:

```bash
cd helm-ai-kernel/core
go run ./cmd/helm-ai-kernel workstation certify \
  --fixtures ../fixtures/workstation \
  --mode high-risk-effect-capable
```

Reference artifacts:

- `fixtures/workstation/reference/receipts/`
- `fixtures/workstation/sample-evidencepack/`

The pack intentionally distinguishes selected-effect enforcement from complete workstation control. Adapters that only observe artifacts should certify as `observe-only`; wrappers that refuse denied selected effects can certify as `enforceable`; adapters that additionally model memory writes, recurring loops, and tainted context can certify as `high-risk-effect-capable`.
