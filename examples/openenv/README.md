# OpenEnv Evaluation Fixtures

These fixtures provide an OpenEnv-shaped, non-authoritative evaluation surface
for HELM-safe agent behavior. They are useful for synthetic training/eval loops
and shadow scoring, not for Kernel enforcement.

The optional adapter lives at:

```text
adapters/openenv/helm_boundary_env/
```

Run the local self-check from the repository root:

```bash
python3 adapters/openenv/helm_boundary_env/self_check.py
```

The adapter exposes three explicit modes:

- `SIMULATION` scores expected synthetic behavior against fixture evidence.
- `SHADOW` records would-have-happened behavior with zero authority.
- `PRODUCTION_UNSUPPORTED` raises a hard error on `step()`.

No OpenEnv or LangChain dependency is required by the Kernel core for these
fixtures.
