# HELM RFC: Effect Taxonomy

| Field        | Value                         |
|-------------|-------------------------------|
| RFC          | HELM-RFC-0002                 |
| Status       | Draft                         |
| Version      | 1.1.0-alpha.1                 |
| Authors      | HELM Core                     |
| Created      | 2026-02-22                    |
| Canonical    | `specs/effects/`              |

## Abstract

Tools are **effect-typed**. Policies bind to effects, not to intent. Every tool in the HELM
ecosystem declares which effects it may produce, and the Authority Court evaluates policy
against those declared effects — not against the agent's narrative or goal description.

## Canonical Effect Types

| Effect Type           | Risk Taxon | Reversibility   | Preflight | Two-Phase | Min Evidence |
|-----------------------|-----------|-----------------|-----------|-----------|--------------|
| `DATA_READ`           | E0        | reversible      | No        | No        | E0           |
| `DATA_WRITE`          | E2        | reversible      | No        | No        | E1           |
| `DATA_DELETE`         | E3        | irreversible    | Yes       | Yes       | E2           |
| `DATA_EXPORT`         | E2        | irreversible    | Yes       | Yes       | E2           |
| `IAM_CHANGE`          | E3        | compensatable   | Yes       | Yes       | E2           |
| `SECRET_READ`         | E2        | reversible      | No        | No        | E2           |
| `SECRET_WRITE`        | E3        | compensatable   | Yes       | Yes       | E3           |
| `PAYMENT_SEND`        | E4        | irreversible    | Yes       | Yes       | E3           |
| `BILLING_CHANGE`      | E3        | compensatable   | Yes       | Yes       | E2           |
| `DEPLOY_RELEASE`      | E3        | compensatable   | Yes       | Yes       | E2           |
| `INFRA_CHANGE`        | E3        | compensatable   | Yes       | Yes       | E2           |
| `MESSAGING_BULK_SEND` | E3        | irreversible    | Yes       | Yes       | E2           |
| `CUSTOMER_OUTREACH`   | E2        | irreversible    | Yes       | Yes       | E2           |
| `CODE_EXEC`           | E3        | reversible      | Yes       | No        | E2           |
| `SHELL_EXEC`          | E4        | irreversible    | Yes       | Yes       | E3           |
| `NETWORK_EXFIL`       | E4        | irreversible    | Yes       | Yes       | E3           |
| `CONFIG_CHANGE`       | E2        | reversible      | No        | No        | E1           |
| `AUDIT_LOG`           | E0        | reversible      | No        | No        | E0           |
| `EXTERNAL_API_CALL`   | E1        | varies          | No        | No        | E1           |
| `NOTIFY`              | E1        | irreversible    | No        | No        | E0           |
| `MODULE_INSTALL`      | E4        | reversible      | Yes       | Yes       | E3           |
| `FUNDS_TRANSFER`      | E4        | compensatable   | Yes       | Yes       | E3           |
| `PERMISSION_CHANGE`   | E3        | compensatable   | Yes       | Yes       | E2           |

## Risk Taxon (E0-E4)

| Grade | Name     | Description                                          | Default Approval |
|-------|----------|------------------------------------------------------|------------------|
| E0    | Compute  | Pure computation, no side effects                    | none             |
| E1    | Read     | Read-only access to data or external systems         | none             |
| E2    | Soft     | Reversible or low-impact writes                      | none             |
| E3    | Hard     | Significant writes, compensatable or critical scope  | single_human     |
| E4    | Critical | Irreversible financial, security, or infrastructure  | dual_control     |

## Evidence Grades

| Grade | Name       | Description                              |
|-------|------------|------------------------------------------|
| E0    | None       | No evidence required                     |
| E1    | Log        | Audit log entry sufficient               |
| E2    | Receipt    | Signed receipt with decision binding     |
| E3    | Full Pack  | Full EvidencePack with merkle root       |

## Each Effect Type Requires

1. **Minimum ceilings** — budget, rate, scope limits
2. **Minimum evidence grade** — what gets recorded
3. **Preflight** — whether dry-run/simulation is mandatory
4. **Two-phase commit** — whether CommitToken flow is required
5. **Blast radius** — maximum scope of impact
6. **Policy hooks** — named hooks that fire in Authority Court

## Extending the Taxonomy

New effect types MUST:
- Be added to the canonical enum in `effect_type_catalog.schema.json`
- Specify all required columns (risk taxon, reversibility, preflight, two-phase, evidence)
- Be reviewed as a spec change (requires SPEC_VERSION bump)

Custom domain-specific effects (e.g. `ORDER_PLACE`, `WITHDRAWAL`) SHOULD map to
canonical types via composition:
```
ORDER_PLACE = FUNDS_TRANSFER + EXTERNAL_API_CALL
WITHDRAWAL = FUNDS_TRANSFER (irreversible)
```

### Launch Mission preview effects

The six launch lifecycle rows are **preview contracts, not executable effect
types**. They are deliberately absent from `DefaultEffectCatalog`, the PDP input
allowlists, and the Kernel effect boundary. Catalog membership never grants
execution authority. Promotion requires one atomic release that adds enforced
base-effect expansion, consumer-schema parity, policy coverage, a certified
connector, and conformance vectors. Until that release, the Kernel must reject
these identifiers at its production boundary. Because this is a prerelease
preview rather than a canonical protocol release, it does not change the global
`SPEC_VERSION`; promotion must perform that version bump.

Every launch effect expands to established base effects before policy evaluation;
a denial of any base effect denies the composite effect:

| Preview effect | Risk | Reversibility | Preflight | Two-phase | Evidence | Mandatory base-effect expansion |
|---|---|---|---|---|---|---|
| `PROVIDER_PROVISION` | E3 | compensatable | Yes | Yes | E3 | `INFRA_CHANGE` + `BILLING_CHANGE` + `EXTERNAL_API_CALL` |
| `DEPLOY_PRODUCTION_ACTIVATE` | E3 | compensatable | Yes | Yes | E3 | `DEPLOY_RELEASE` + `CONFIG_CHANGE` |
| `SPEND_AUTHORIZE` | E3 | reversible | Yes | Yes | E3 | `BILLING_CHANGE` |
| `PROVIDER_ROLLBACK` | E3 | compensatable | Yes | Yes | E3 | `DEPLOY_RELEASE` + `INFRA_CHANGE` |
| `PROVIDER_TEARDOWN` | E4 | irreversible | Yes | Yes | E3 | `DATA_DELETE` + `INFRA_CHANGE` + `BILLING_CHANGE` |
| `COMPANY_ARTIFACT_UPDATE` | E2 | reversible | Yes | Yes | E2 | `DATA_WRITE` |

Provider effects enter the Kernel through the closed `helm-provider-route`
connector and generic actions such as `urn:helm:provider-route:provision`.
The canonical input then binds the exact provider connector/action, provider
payload hash, RepositoryAnalysis, WorkloadGraph, capability profile, RouteBinding,
quote, and constraint set. Both layers must bind the exact connector contracts,
canonical input hash, derived idempotency key, policy epoch,
the exact current emergency-fence epoch, approval artifact, verdict validity
window, and single-use effect permit. The data plane must consume that permit
with an atomic compare-and-swap only after every schema, semantic, temporal,
binding, and signature check passes. `UNKNOWN` outcomes freeze dependants and
bind a reconciliation locator plus dependency-set/state artifacts before a retry
or terminal mission result is considered; provider identifiers are never
fabricated when a timeout occurs before the provider returns them.
`DEPLOY_PRODUCTION_ACTIVATE` grants one exact cutover only; deployment-on-push or
other standing authority is outside this version.

`DEPLOY_PRODUCTION_ACTIVATE` is the HELM-259 preview mapping for the existing
HELM-117 `deploy.production_cutover` contract. It is not a second cutover model.
The promotion release must either reuse that source-owned binding directly or
publish an explicit compatibility adapter and conformance vectors.

The Kernel preview is provider- and workload-neutral. Every immutable repository
commit can produce a truthful `SUPPORTED`, `NEEDS_INPUT`, `UNSUPPORTED`, or
`UNKNOWN` analysis and a provider-neutral workload graph; accepting a repository
never implies that a safe route exists. Provider regions, hostnames, SKUs,
supported workload kinds, pricing evidence, terms, actions, and reconciliation
semantics live in separately versioned capability profiles and certified
connector contracts. Adding a cloud therefore does not add a Kernel effect type.

DigitalOcean App Platform is the first **candidate** provider profile and remains
non-executable until connector certification is source-proven. Its first route
may constrain workloads to static sites and one stateless HTTP service, regions
to `ams`/`fra`, exposure to EUR 50 monthly, and activation to a provider-managed
hostname. Those are route-policy facts, not universal Kernel constraints.

A failed or unknown provision does not carry pre-authorized deletion authority.
The mission and its budget reservation remain frozen until reconciliation proves
the outcome; any cleanup then requires a fresh E4 dual-control
`PROVIDER_TEARDOWN` approval. Activation may carry a narrowly pre-authorized
rollback only for the exact previous healthy deployment bound into its input and
expiring rollback permit. The rollback effect must bind that permit, the
originating activation receipt, the provisioning receipt, and the exact approved
provider route; its fresh dispatch permit remains separately single-use. Spend authority
must bind `authorized_at` and expire no later than one calendar month afterward.

Launch effect receipts are an extended Receipt Format v1 profile: the receipt ID
is the lowercase hexadecimal SHA-256 of the RFC 8785 projection with
`receipt_id` and `signature` cleared, and the base64 Ed25519 signature covers
that receipt ID. Verification resolves `signer_key_id` through the published
trust root and proves the referenced ProofGraph node. Each receipt also binds
the input schema, approval, permit hash, atomic permit-consumption artifact,
policy epoch, and exact emergency-fence epoch. Reconciliation revisions are
append-only, content-addressed, Lamport-ordered, and may not mutate terminal
material.

## Compatibility

This taxonomy supersedes the existing 9-type enum in `effect_type_catalog.schema.json`.
The original types (`DATA_WRITE`, `FUNDS_TRANSFER`, `PERMISSION_CHANGE`, `DEPLOY`, `NOTIFY`,
`MODULE_INSTALL`, `CONFIG_CHANGE`, `AUDIT_LOG`, `EXTERNAL_API_CALL`) remain valid and are
extended. `DEPLOY` remains a legacy compatibility identifier; new contracts use
`DEPLOY_RELEASE`, and any later deprecation requires an explicit compatibility
mapping rather than a silent rename.
