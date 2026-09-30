# Workstation Governance Conformance

The workstation conformance pack lives at `protocols/conformance/workstation/v1/conformance-pack.json`.

Adapter levels:

| Mode | Meaning |
| --- | --- |
| `observe-only` | Adapter imports manifests, emits signed Agent Run Receipts, binds artifact hashes, and replays deterministically. |
| `enforceable` | Observe-only plus selected-effect policy decision receipts and CLI/hook refusal for denied effects. |
| `high-risk-effect-capable` | Enforceable plus memory write, recurring loop, and tainted-context fixtures. |

The `workstation certify` command that graded fixtures against these levels
was removed in HELM-756. It printed a certification from checked-in fixtures
rather than from a running adapter. The levels remain a vocabulary for
describing an adapter; the fixtures and reference artifacts below remain
test inputs for `workstation import`, `enforce` and `evidence`.

Reference artifacts:

- `fixtures/workstation/reference/receipts/`
- `fixtures/workstation/sample-evidencepack/`

The pack intentionally distinguishes selected-effect enforcement from complete workstation control. Adapters that only observe artifacts are `observe-only`; wrappers that refuse denied selected effects are `enforceable`; adapters that additionally model memory writes, recurring loops, and tainted context are `high-risk-effect-capable`.
