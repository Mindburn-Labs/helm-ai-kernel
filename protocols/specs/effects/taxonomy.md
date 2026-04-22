# HELM RFC: Effect Taxonomy

| Field        | Value                         |
|-------------|-------------------------------|
| RFC          | HELM-RFC-0002                 |
| Status       | Draft                         |
| Version      | 1.0.0-alpha.1                 |
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

## Compatibility

This taxonomy supersedes the existing 9-type enum in `effect_type_catalog.schema.json`.
The original types (`DATA_WRITE`, `FUNDS_TRANSFER`, `PERMISSION_CHANGE`, `DEPLOY`, `NOTIFY`,
`MODULE_INSTALL`, `CONFIG_CHANGE`, `AUDIT_LOG`, `EXTERNAL_API_CALL`) remain valid and are
extended. `DEPLOY` is renamed to `DEPLOY_RELEASE` for clarity.
