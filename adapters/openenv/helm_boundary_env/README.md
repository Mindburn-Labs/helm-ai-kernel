# HELM Boundary OpenEnv Adapter

This directory contains an optional, example-only OpenEnv-shaped adapter for
synthetic and shadow evaluation of HELM-safe agent behavior. It is not imported
by `core/`, is not listed in `core/go.mod`, and cannot issue Kernel verdicts or
execute production side effects.

## Modes

| Mode | Purpose | Production authority |
| --- | --- | --- |
| `SIMULATION` | Score a synthetic task fixture against expected HELM behavior. | None |
| `SHADOW` | Record what an agent would have done against a task fixture. | None |
| `PRODUCTION_UNSUPPORTED` | Guardrail mode for accidental production use. | Raises `ProductionUnsupportedError` on `step()` |

## Local Self-Check

Run from the repository root:

```bash
python3 adapters/openenv/helm_boundary_env/self_check.py
```

The self-check loads the action-safety fixtures in
`examples/openenv/tasksets/action_safety/` and verifies that simulation and
shadow modes are non-authoritative while production mode fails closed.
