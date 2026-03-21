# Capability Manifests

> **Canonical** · v1.0 · Normative
>
> This document defines the configuration primitives for HELM's
> **bounded execution surface** (Layer A — Surface Containment).
> These primitives shape what an agent can reach before any
> runtime policy evaluation begins.
>
> **Reference**: [EXECUTION_SECURITY_MODEL.md](EXECUTION_SECURITY_MODEL.md) § Layer A.

---

## Design Principle

The bounded surface is not an abstraction — it is a **configurable
first-class primitive**. HELM does not only verify each call; it
radically reduces what can be called in the first place.

Surface containment is a **design-time property**: configured before
execution, not computed per-call.

---

## 1. Domain-Scoped Tool Bundles

Tools are grouped into **domain bundles** — isolated sets with
independent governance. An agent can only access the bundles
explicitly assigned to it.

```yaml
# helm.yaml
bundles:
  filesystem:
    tools: [file_read, file_write, file_list]
    sandbox: restricted
    side_effect_class: write_limited

  network:
    tools: [http_get, http_post]
    sandbox: isolated
    side_effect_class: full
    destinations:
      - "api.example.com"
      - "*.internal.corp"

  analytics:
    tools: [query_db, aggregate]
    sandbox: restricted
    side_effect_class: read_only
```

**Properties:**
- Each bundle has independent sandbox profiles
- Bundle membership is closed — tools not in any assigned bundle are unreachable
- Cross-bundle access requires explicit multi-bundle assignment

---

## 2. Explicit Capability Manifests

Every agent/profile declares an explicit **capability manifest** —
the exhaustive list of tools and operations it is permitted to use.

```yaml
# capability-manifest.yaml
agent: research-assistant
version: "1.0"
capabilities:
  bundles: [analytics, filesystem]
  max_side_effect_class: write_limited
  destinations:
    allow: ["api.example.com", "cdn.example.com"]
    deny: ["*.production.internal"]
  budget:
    max_calls_per_session: 100
    max_cost_usd: 5.00
```

**Invariants:**
- No tool is accessible unless declared in the manifest
- Manifest is version-pinned and content-addressed (SHA-256)
- Manifest changes require re-deployment or policy bundle update

---

## 3. Side-Effect Class Profiles

Every tool class has a declared **side-effect profile** that constrains
the maximum impact it can have:

| Profile | Permitted Operations |
| :--- | :--- |
| `read_only` | Query, list, describe. No state mutation. |
| `write_limited` | Create, update with explicit approval. No delete. |
| `full` | All operations (requires elevated sandbox + budget ceiling) |
| `destructive` | Delete, recreate, destroy (requires approval ceremony) |

**Enforcement:**
- Write action through a `read_only` profile → `DENY`
- Delete action through a `write_limited` profile → `DENY`
- `destructive` operations always require approval ceremony regardless of profile

---

## 4. Connector Allowlists

Connector access is restricted by **allowlist** at multiple scopes:

| Scope | Description |
| :--- | :--- |
| Per-tenant | Organization-wide connector restrictions |
| Per-app | Application-specific connector access |
| Per-profile | Agent-profile-level restrictions |

**Default:** deny all connectors not explicitly listed.

```yaml
connectors:
  tenant_allowlist:
    - connector: github
      version: ">=2.0"
    - connector: slack
      version: "1.5"
  
  app_overrides:
    research-app:
      deny: [slack]  # this app cannot use slack
```

---

## 5. Destination Scoping

Tool calls that interact with external systems are restricted to
**explicit destination allowlists**:

```yaml
destinations:
  allow:
    - "api.openai.com"
    - "*.internal.company.com"
    - "cdn.example.com"
  deny:
    - "*.production.database.internal"  # explicit deny
  default: deny  # anything not in allow list is denied
```

**Properties:**
- DNS-level destination control
- Deny takes precedence over allow for overlapping patterns
- Default deny — unlisted destinations are blocked

---

## 6. Filesystem / Network Deny-by-Default

WASI sandbox enforces **deny-by-default** for all I/O:

| Resource | Default | Override |
| :--- | :--- | :--- |
| Filesystem read | Denied | Explicit path allowlist |
| Filesystem write | Denied | Explicit path allowlist + write profile |
| Network outbound | Denied | Explicit destination allowlist |
| Network inbound | Denied | Not available in OSS |
| Environment variables | Denied | Explicit key allowlist |
| System calls | Denied | WASI-limited subset only |

---

## 7. Sandbox Profile Requirement

Every tool class must declare a **sandbox profile** before execution
is permitted. Undeclared sandbox profiles → `DENY`.

| Sandbox Level | Isolation | Use Case |
| :--- | :--- | :--- |
| `restricted` | WASI with gas/time/memory caps | Default for most tools |
| `isolated` | Full WASI sandbox + network restriction | Network-capable tools |
| `native` | Host process (TCB only) | Internal kernel operations |

---

## Relationship to Other Layers

Surface containment (Layer A) sets the **maximum possible scope**.
Dispatch enforcement (Layer B) then evaluates each individual call
within that scope. Verifiable receipts (Layer C) prove what happened.

```
Capability Manifest     → defines maximum surface
  ↓
Tool Bundles            → groups tools with governance
  ↓
Side-Effect Profiles    → constrains impact class
  ↓
Connector Allowlists    → restricts which connectors
  ↓
Destination Scoping     → restricts where calls go
  ↓
Sandbox Profiles        → constrains execution environment
  ↓
Layer B (PEP/CPI)       → evaluates each call at dispatch
  ↓
Layer C (Receipts)      → proves the outcome
```

---

## Implementation References

| Component | Location |
| :--- | :--- |
| WASI sandbox | `core/pkg/runtime/sandbox/` |
| Tool catalog | `core/pkg/mcp/` |
| Manifest validation | `core/pkg/manifest/` |
| Budget ceilings | `core/pkg/runtime/budget/` |
| Connector contracts | `core/pkg/contracts/` |

---

_Canonical revision: 2026-03-21 · HELM UCS v1.2_
