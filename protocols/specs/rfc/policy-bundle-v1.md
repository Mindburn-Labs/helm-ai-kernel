---
title: Policy Bundle Format v1
status: final
version: 1.0.0
date: 2026-03-06
authors:
  - HELM Core Team
---

# RFC: HELM Policy Bundle Format v1

## 1. Abstract

This document specifies the format, lifecycle, and trust model for HELM policy
bundles — self-contained, signed, versioned packages of governance rules that
can be loaded at runtime without recompilation.

## 2. Motivation

Governance must be configuration, not code. Policy bundles enable:

- Runtime policy updates without binary redeployment
- Signed, verifiable policy provenance
- Jurisdiction and industry-specific policy packs
- Separation of policy authoring from kernel development

## 3. Bundle Structure

A policy bundle is a directory or archive containing:

```
my-bundle/
├── manifest.yaml          # Bundle metadata
├── policies/              # Policy files
│   ├── deny-system-writes.yaml
│   ├── require-approval-for-deploys.yaml
│   └── budget-limits.yaml
├── schemas/               # Optional: custom schemas
│   └── custom-effect.schema.json
└── SIGNATURE              # Ed25519 detached signature
```

## 4. Manifest Format

```yaml
apiVersion: helm.mindburn.run/v1
kind: PolicyBundle
metadata:
  name: corporate-baseline
  version: 1.2.0
  description: Corporate baseline governance policies
  author: security-team@example.com
  jurisdiction: US
  industry: finance
  tags: [sox, baseline, production]
spec:
  min_helm_version: "1.0.0"
  policies:
    - path: policies/deny-system-writes.yaml
      kind: DenyRule
      priority: 100
    - path: policies/require-approval-for-deploys.yaml
      kind: ApprovalGate
      priority: 90
    - path: policies/budget-limits.yaml
      kind: BudgetConstraint
      priority: 80
  schemas:
    - path: schemas/custom-effect.schema.json
  trust:
    signer_key_id: "key-corporate-2026"
    signature_algorithm: Ed25519
```

## 5. Policy File Format

```yaml
apiVersion: helm.mindburn.run/v1
kind: DenyRule
metadata:
  name: deny-system-writes
  description: Deny writes to system directories
spec:
  match:
    effect_type: file_write
    conditions:
      - field: params.path
        operator: starts_with
        values: ["/etc/", "/usr/", "/bin/", "/sbin/"]
  verdict: DENY
  reason_code: POLICY_VIOLATION
  reason: "Writing to system directories is prohibited"
```

## 6. Trust Model

### 6.1 Signing

Bundles MUST be signed with Ed25519:

```bash
helm bundle sign --key /path/to/private.key ./my-bundle/
```

This produces a `SIGNATURE` file containing the signature over the
bundle's content hash (SHA-256 of the manifest + all policy files).

### 6.2 Verification

```bash
helm bundle verify --public-key /path/to/public.key ./my-bundle/
```

### 6.3 Trust Root

The HELM kernel maintains a trust root (set of accepted public keys).
Only bundles signed by trusted keys are loaded.

```yaml
trust_roots:
  - key_id: "key-corporate-2026"
    public_key: "base64-encoded-ed25519-public-key"
    valid_from: "2026-01-01T00:00:00Z"
    valid_until: "2027-12-31T23:59:59Z"
```

## 7. Lifecycle

### 7.1 Loading

```go
bundle, err := bundles.LoadBundle("/path/to/my-bundle")
```

### 7.2 Hot Reload

Bundles can be reloaded without restart:

```yaml
bundle_loader:
  watch: true
  reload_interval: 30s
  paths:
    - /etc/helm/bundles/
```

### 7.3 Remote Fetch

```yaml
bundle_loader:
  remote:
    url: https://bundles.mindburn.run/corporate-baseline/v1.2.0
    refresh_interval: 1h
    signature_verification: required
```

### 7.4 Revocation

Bundles can be revoked by adding their content hash to the revocation list:

```yaml
revocation_list:
  - content_hash: "sha256:abc123..."
    revoked_at: "2026-03-06T00:00:00Z"
    reason: "Policy defect discovered"
```

## 8. EvidencePack Integration

Active bundle metadata MUST appear in the EvidencePack:

```json
{
  "active_bundles": [
    {
      "name": "corporate-baseline",
      "version": "1.2.0",
      "content_hash": "sha256:...",
      "signer_key_id": "key-corporate-2026",
      "loaded_at": "2026-03-06T12:00:00Z"
    }
  ]
}
```

## 9. Conformance

A bundle loader is conformant if:

1. It validates the manifest schema
2. It verifies the Ed25519 signature before loading
3. It rejects bundles with unknown `apiVersion`
4. It fails closed if signature verification fails
5. It records loaded bundles in the EvidencePack
6. It checks the revocation list before loading
