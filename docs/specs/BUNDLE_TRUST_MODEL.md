# HELM Policy Bundle Trust Model

> How bundles establish, maintain, and revoke trust.

## 1. Trust Chain

```
┌──────────────┐     ┌────────────┐     ┌──────────────┐
│  Trust Root  │◀────│  Bundle    │◀────│  Runtime     │
│  (Key Pair)  │     │  Author    │     │  Loader      │
└──────────────┘     └────────────┘     └──────────────┘
       │                    │                    │
   Ed25519 key        Signs bundle         Verifies sig
   in keyring         with private key     against keyring
```

## 2. Signing

### 2.1 Bundle Signing Flow

1. Author creates bundle manifest + policies
2. Author computes `content_hash = SHA-256(canonical_json(manifest + policies))`
3. Author signs `content_hash` with their Ed25519 private key
4. Signed bundle structure:

```json
{
  "manifest": { ... },
  "policies": [ ... ],
  "signature": {
    "algorithm": "Ed25519",
    "signer_key_id": "urn:helm:key:author-corp-2026",
    "content_hash": "sha256:abc123...",
    "signature": "base64:...",
    "signed_at": "2026-01-15T00:00:00Z"
  }
}
```

### 2.2 Key Management

| Trust Level       | Key Source                | Rotation Policy |
| ----------------- | ------------------------- | --------------- |
| **Root**          | Offline HSM or Vault      | Annual rotation |
| **Intermediate**  | Derived from root         | Quarterly       |
| **Bundle Author** | Derived from intermediate | Per-release     |

## 3. Verification

### 3.1 Runtime Verification Steps

1. Load trust root keyring from `trust_roots/` directory
2. Read bundle `signature.signer_key_id`
3. Resolve key from keyring or delegated trust chain
4. Verify Ed25519 signature over `content_hash`
5. Recompute `SHA-256(canonical_json(manifest + policies))`
6. Compare computed hash with declared `content_hash`
7. If any step fails → **reject bundle, fail-closed**

### 3.2 Fail-Closed

An unverifiable bundle MUST be rejected. The kernel MUST NOT load policies from an unsigned or tampered bundle.

## 4. Revocation

### 4.1 Revocation List

A revocation list is maintained at `trust_roots/revoked.json`:

```json
{
  "revoked_keys": [
    {
      "key_id": "urn:helm:key:compromised-2025",
      "revoked_at": "2026-01-01T00:00:00Z",
      "reason": "Key compromise"
    }
  ],
  "revoked_bundles": [
    {
      "content_hash": "sha256:deadbeef...",
      "revoked_at": "2026-02-01T00:00:00Z",
      "reason": "Policy error discovered"
    }
  ]
}
```

### 4.2 Online Revocation

For deployments with network access, the runtime MAY check an online revocation endpoint:

```
GET /v1/trust/revocations?since=2026-01-01T00:00:00Z
```

## 5. Hot Reload

### 5.1 Reload Trigger

Bundles MAY be reloaded without restart:

1. File system watcher detects change to bundle path
2. New bundle is loaded and verified
3. If verification passes, policies are atomically swapped
4. If verification fails, existing policies remain (fail-closed)
5. A receipt is generated for the bundle swap event

### 5.2 Remote Fetch

```yaml
bundle_sources:
  - type: file
    path: /etc/helm/bundles/
  - type: https
    url: https://bundles.mindburn.run/corporate-baseline
    poll_interval: 300s
    verify: true
```

## 6. Bundle Manifest Schema

See `protocols/json-schemas/packs/pack_manifest.v1.schema.json` for the
machine-readable schema. Key fields:

| Field          | Required | Description                                |
| -------------- | -------- | ------------------------------------------ |
| `name`         | Yes      | Bundle identifier                          |
| `version`      | Yes      | Semver version                             |
| `content_hash` | Yes      | SHA-256 of canonical content               |
| `policies`     | Yes      | Array of policy definitions                |
| `signature`    | Yes      | Ed25519 signature block                    |
| `created_at`   | Yes      | ISO 8601 timestamp                         |
| `expires_at`   | No       | Expiration (after which bundle is invalid) |
| `dependencies` | No       | Other bundles this depends on              |

## 7. CLI Commands

```bash
helm bundle install <path-or-url>   # Install and verify a bundle
helm bundle list                     # List installed bundles
helm bundle pin <name> <version>     # Pin a bundle to a specific version
helm bundle verify <path-or-url>     # Verify bundle integrity only
helm bundle update                   # Update all bundles from sources
helm bundle revoke <content-hash>    # Add bundle to local revocation list
```
