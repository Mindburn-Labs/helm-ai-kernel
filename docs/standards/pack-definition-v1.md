# Pack Definition Standard

**Version:** 1.0.0
**Status:** DRAFT
**Owner:** Mindburn Labs / HELM Core
**Last Updated:** 2026-04-04

---

## Abstract

This standard defines the canonical structure, composition rules, policy
precedence model, and installation lifecycle for HELM Packs. A Pack is a
versioned, distributable workspace template that bundles programs, virtual
employees, capability grants, budget envelopes, signal watches, automation
schedules, and policy overlays into a single atomic deployment unit.

Packs are the primary delivery vehicle for HELM capabilities to enterprise
tenants. They establish immediate product legibility by proving end-to-end
governed workflows out of the box. The reference pack set — Executive Ops,
Recruiting, Revenue/Customer Ops, and Procurement — covers the four highest-
value automation surfaces for enterprise buyers (see ADR-007).

Packs compose via a three-tier policy precedence model: P0 ceilings (global
organizational limits), P1 bundles (pack-level defaults), and P2 overlays
(tenant-specific fine-tuning). Higher-numbered tiers MUST NOT exceed the
authority granted by lower-numbered tiers.

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

| Term | Definition |
|---|---|
| **Pack** | A versioned, distributable workspace configuration bundle. |
| **PackManifest** | The canonical `pack.yaml` descriptor at the root of every pack. |
| **Program** | A signal routing and work categorization unit within a HELM workspace. |
| **Virtual Employee** | A HELM-governed agent principal with a role, budget, and capability grant. |
| **Capability Grant** | A scoped permission binding a virtual employee to connectors and skills. |
| **Budget Envelope** | A time-windowed spending limit applied to a virtual employee. |
| **Signal Watch** | A filter rule that routes inbound signals into specific programs. |
| **Policy Overlay** | A pack-level policy layer applied on top of global P0 ceilings (ADR-007). |
| **P0 Ceiling** | The global organizational policy floor that no pack may exceed. |
| **P1 Bundle** | The pack's own policy layer, bounded by P0. |
| **P2 Overlay** | Tenant-supplied customizations, bounded by P1. |
| **Installation Receipt** | The signed, ProofGraph-linked artifact produced by atomic pack installation. |

---

## Pack Directory Structure

A pack archive MUST contain the following structure:

```
my-pack-1.0.0/
├── pack.yaml                  # PackManifest (REQUIRED)
├── policies/
│   ├── p1-bundle.yaml         # P1 policy bundle (REQUIRED)
│   └── p2-overlay-defaults.yaml  # P2 overlay defaults (OPTIONAL)
├── programs/
│   └── main.yaml              # Program definitions (REQUIRED, min 1)
├── employees/
│   └── employees.yaml         # Virtual employee definitions (OPTIONAL)
├── grants/
│   └── capability-grants.yaml # Capability grant bindings (OPTIONAL)
├── budgets/
│   └── budget-envelopes.yaml  # Budget envelope definitions (OPTIONAL)
├── watches/
│   └── signal-watches.yaml    # Signal watch filter rules (OPTIONAL)
├── schedules/
│   └── schedules.yaml         # Automation schedules (OPTIONAL, schema: automation-schedule-v1)
└── README.md                  # Human-readable pack description (RECOMMENDED)
```

---

## Wire Format

### PackManifest (`pack.yaml`)

```yaml
schema: "https://helm.mindburn.org/schemas/packs/pack_manifest.v1.yaml"
pack_id: "packs/org.mindburn.exec-ops"
name: "Executive Ops"
version: "1.2.0"
description: >
  Automates executive assistant workflows: email triage, meeting follow-ups,
  document summaries, and calendar management.
category: "executive_ops"
tags:
  - "email"
  - "calendar"
  - "document"

required_connectors:
  - "connectors/org.mindburn.gmail"
  - "connectors/org.mindburn.google-calendar"
  - "connectors/org.mindburn.slack"

optional_connectors:
  - "connectors/org.mindburn.google-docs"
  - "connectors/org.mindburn.zoom"

required_skill_bundles:
  - "skills/org.mindburn.email-triage@^1.0"
  - "skills/org.mindburn.document-summarizer@^2.0"

required_packs: []
conflicts_with: []

policy_p1_ref: "policies/p1-bundle.yaml"
policy_p2_defaults_ref: "policies/p2-overlay-defaults.yaml"

compatibility:
  min_runtime_version: "1.0.0"
  max_runtime_version: null

pack_hash: "sha256:c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
signature_ref: "signatures/exec-ops@1.2.0.sig"
published_by: "principal_helm_release_authority"
published_at_unix_ms: 1743765000000
```

### PackManifest Field Descriptions

| Field | Type | Constraints | Description |
|---|---|---|---|
| `schema` | string (URI) | REQUIRED | YAML/JSON Schema `$id`. |
| `pack_id` | string | REQUIRED, format `packs/{reverse-domain}.{name}` | Globally unique, stable pack identifier. |
| `name` | string | REQUIRED, 1–128 chars | Human-readable display name. |
| `version` | string | REQUIRED, semver | Pack release version. |
| `description` | string | REQUIRED, 1–1024 chars | One-paragraph description of what the pack does. |
| `category` | string | REQUIRED | Pack category (see Reference Packs table). |
| `tags` | string[] | OPTIONAL | Searchable tags for marketplace discovery. |
| `required_connectors` | string[] | REQUIRED, min 0 | Connectors that MUST be installed for the pack to function. |
| `optional_connectors` | string[] | OPTIONAL | Connectors that enable additional pack features if present. |
| `required_skill_bundles` | string[] | REQUIRED, min 0 | Skill bundles with version constraints (semver ranges). |
| `required_packs` | string[] | OPTIONAL | Other packs that must be installed first (dependency ordering). |
| `conflicts_with` | string[] | OPTIONAL | Pack IDs that MUST NOT be co-installed in the same workspace. |
| `policy_p1_ref` | string | REQUIRED | Path to the P1 policy bundle within the pack archive. |
| `policy_p2_defaults_ref` | string | OPTIONAL | Path to P2 overlay defaults within the pack archive. |
| `compatibility` | object | REQUIRED | Min/max HELM runtime version constraints. |
| `pack_hash` | string | REQUIRED, format `sha256:{hex}` | SHA-256 of canonical pack archive. |
| `signature_ref` | string | REQUIRED | Path to Ed25519 signature over `pack_hash`. |
| `published_by` | string | REQUIRED | HELM principal that published the pack. |
| `published_at_unix_ms` | integer | REQUIRED | Unix millisecond publication timestamp. |

---

## Policy Precedence Model

HELM enforces a three-tier policy precedence hierarchy:

```
P0 — Global Ceiling  (set by tenant admin, applies to all packs)
  ├── P1 — Pack Bundle  (set by pack publisher, bounded by P0)
  │     └── P2 — Tenant Overlay  (set by tenant operator, bounded by P1)
  │           └── [effective policy applied to virtual employees]
```

### Rules

1. **MUST** — P2 overlays MUST NOT grant permissions that exceed P1 bundle
   policy. The HELM kernel MUST reject P2 overlays that attempt to elevate
   above P1.

2. **MUST** — P1 bundle policy MUST NOT grant permissions that exceed P0
   ceilings. A pack that attempts to install a P1 that violates P0 MUST fail
   installation with `POLICY_CEILING_VIOLATION`.

3. **SHOULD** — P2 overlay defaults shipped within the pack SHOULD represent
   the minimal permissions required for the pack's described use cases. Tenants
   MAY tighten but SHOULD NOT need to tighten defaults for normal use.

4. **MUST** — Policy precedence evaluation is deterministic. Given identical P0,
   P1, and P2 inputs, the effective policy output MUST be identical across all
   HELM runtime instances.

### Example: Email Triage Policy Precedence

```yaml
# P0 (global ceiling — set by tenant admin)
effect_classes_allowed: [E0, E1, E2]
max_daily_outbound_emails: 50

# P1 (pack bundle — from exec-ops pack)
default_effect_class: E1
email_domains_allowed: ["*.acme.com", "*.trusted-partner.com"]
require_approval_for_external: true

# P2 (tenant overlay — operator-configured)
email_domains_allowed: ["*.acme.com"]  # tighter than P1
require_approval_for_external: true    # unchanged
```

---

## Validation Rules

1. **MUST** — `pack_hash` MUST be verified before installation begins. A
   mismatch MUST abort installation with `PACK_INTEGRITY_VIOLATION`.

2. **MUST** — The Ed25519 signature at `signature_ref` MUST verify against the
   HELM pack publisher trust key. An invalid signature MUST abort installation.

3. **MUST** — All `required_connectors` and `required_skill_bundles` MUST be
   present in `certified` state before the pack installation completes.

4. **MUST** — All `conflicts_with` pack IDs MUST NOT be installed in the target
   workspace. If a conflict is detected, installation MUST fail with
   `PACK_CONFLICT`.

5. **MUST** — The `policy_p1_ref` bundle MUST pass policy validation against the
   workspace's active P0 ceiling before any pack resources are created.

6. **MUST** — Pack installation MUST be atomic. If any step fails after the
   first resource is created, all created resources MUST be rolled back.
   Partial installations are not permitted.

7. **MUST** — Pack installation MUST be idempotent. Re-installing a pack at the
   same version MUST update configuration to match the pack definition without
   duplicating resources.

8. **MUST** — Every installation MUST produce a signed `InstallationReceipt`
   linked to a ProofGraph node. The receipt MUST reference all created resource
   IDs.

9. **SHOULD** — `conflicts_with` SHOULD be populated when two packs define
   overlapping program names or signal watch patterns that would create routing
   ambiguity.

10. **MUST** — Uninstalling a pack MUST cleanly remove all resources created
    by that pack's installation. Resources shared with other packs (via
    `required_packs`) MUST NOT be removed.

---

## Reference Packs

The four reference packs, in priority order (ADR-007):

| Priority | Pack ID | Category | Key Connectors | Key Skills |
|---|---|---|---|---|
| 1 | `packs/org.mindburn.exec-ops` | `executive_ops` | gmail, google-calendar, slack, zoom | email-triage, doc-summarizer, meeting-followup |
| 2 | `packs/org.mindburn.recruiting` | `recruiting` | gmail, greenhouse, slack, calendar | resume-triage, candidate-comms, interview-scheduler |
| 3 | `packs/org.mindburn.customer-ops` | `customer_ops` | gmail, salesforce, slack, zendesk | customer-followup, crm-sync, escalation-router |
| 4 | `packs/org.mindburn.procurement` | `procurement` | gmail, slack, netsuite | vendor-intake, spend-request, budget-checker |

Each reference pack reuses infrastructure from higher-priority packs:
- `recruiting` reuses email and calendar connectors from `exec-ops`
- `customer-ops` reuses email and slack from `exec-ops`
- `procurement` reuses email, slack, and approval flows from `exec-ops`

---

## Pack Composition Rules

When multiple packs are installed in a workspace:

1. **Program namespacing.** Program names MUST be globally unique within a
   workspace. Pack publishers MUST prefix program names with their pack category
   (e.g., `exec_ops.email_triage`, not `email_triage`).

2. **Signal watch routing.** If two installed packs define signal watches with
   overlapping filter patterns, the higher-priority pack's watch takes
   precedence. Ties MUST generate an operator warning.

3. **Virtual employee namespacing.** Virtual employee IDs MUST be scoped to the
   pack that defined them. Cross-pack delegation MUST be explicit via capability
   grants, not implicit.

4. **Policy isolation.** Each pack's P1 bundle is applied independently. The
   effective policy for a virtual employee is the intersection of all applicable
   P1 bundles, bounded by P0, refined by P2 overlays.

5. **Budget isolation.** Budget envelopes are scoped per virtual employee per
   pack. A virtual employee shared across packs (via `required_packs`) has a
   separate budget envelope per pack.

---

## Installation Lifecycle

```
[POST /api/v1/workspaces/{id}/packs/install]
                │
                ▼
      [verify pack_hash + signature]
                │
       (fail?)──▶ abort: PACK_INTEGRITY_VIOLATION
                │
                ▼
      [check required_connectors + skill_bundles]
                │
       (missing?)──▶ abort: MISSING_DEPENDENCY
                │
                ▼
      [check conflicts_with]
                │
       (conflict?)──▶ abort: PACK_CONFLICT
                │
                ▼
      [validate P1 policy against P0 ceiling]
                │
       (violation?)──▶ abort: POLICY_CEILING_VIOLATION
                │
                ▼
      [create resources atomically:
         programs, employees, grants,
         budgets, watches, schedules]
                │
       (any fail?)──▶ rollback all, abort: INSTALLATION_FAILED
                │
                ▼
      [issue InstallationReceipt + ProofGraph node]
                │
                ▼
        [pack active in workspace]
```

---

## Versioning Policy

- Pack versions follow semver 2.0.
- A new **major** version MUST be treated as a new pack installation.
  Auto-migration is not guaranteed; operators MUST explicitly install v2 and
  uninstall v1.
- A new **minor** version MAY add optional resources. Re-installation updates
  resources to the new definitions.
- A new **patch** version MUST NOT change resource schemas or policy structure.
- Published packs are immutable per ADR-006. Corrections require a new semver.

---

## Security Considerations

- **Supply-chain integrity.** `pack_hash` + `signature_ref` provide tamper
  detection from publisher to workspace. The HELM kernel performs verification;
  workspace administrators cannot bypass this check.

- **Policy ceiling enforcement.** The P0→P1→P2 precedence ensures that pack
  publishers cannot grant themselves permissions beyond what the tenant
  administrator has authorized. This boundary is enforced by the kernel, not by
  the pack.

- **Atomic installation.** All-or-nothing installation prevents partial
  deployments that could create inconsistent permission states where a virtual
  employee exists but its governing policy has not been applied.

- **Idempotent re-installation.** Idempotency prevents duplicate resource
  creation that could inflate capability grants or budget envelopes beyond
  intended levels.

---

## References

- ADR-004: All Runtime Mutation Goes Through Forge
- ADR-005: R0-R3 Action Risk Class Taxonomy
- ADR-006: Schema Namespace Organization
- ADR-007: Reference Pack Priority
- skill-bundle-v1.md (this standard set)
- connector-release-v1.md (this standard set)
- automation-schedule-v1.md (this standard set)
- GOVERNANCE_SPEC.md
- POLICY_BUNDLES.md
