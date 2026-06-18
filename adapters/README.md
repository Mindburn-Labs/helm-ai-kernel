# Adapters

This surface contains optional adapter examples that expose HELM behavior to
external evaluation or integration protocols without moving those protocols into
Kernel authority.

Current adapter examples:

- `openenv/helm_boundary_env/`: synthetic and shadow OpenEnv-shaped evaluation
  harness for HELM-safe agent behavior. Production execution is explicitly
  unsupported.

Adapter code under this surface must not be imported by `core/`, must not add
dependencies to `core/go.mod`, and must not issue Kernel verdicts.
