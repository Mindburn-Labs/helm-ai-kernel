---
title: Policy Bundle Format v1
status: final
version: 1.0.0
date: 2026-03-06
last_reviewed: 2026-08-09
authors:
  - HELM Core Team
---

# RFC: HELM Policy Bundle Format v1

> [!IMPORTANT]
> **Status: PARTIALLY IMPLEMENTED.** Sections 3–5 and 7.1 describe the format
> and API that ship in this repository today and are safe to integrate against.
> Sections 6 and 7.2–7.4 are **DESIGN TARGET — not implemented**; they are
> retained as the intended direction and are individually marked. Do not build
> an integration against a section marked TARGET.
>
> Implementation of record: [`core/pkg/bundles/loader.go`](../../../core/pkg/bundles/loader.go)
> (the whole package), [`core/cmd/helm-ai-kernel/bundle_cmd.go`](../../../core/cmd/helm-ai-kernel/bundle_cmd.go)
> (CLI), and [`core/pkg/conform/gates/g14_bundle_integrity.go`](../../../core/pkg/conform/gates/g14_bundle_integrity.go)
> (the conformance gate). These are the only three places in the repository that
> read the policy bundle format.

## 1. Abstract

This document specifies the format, lifecycle, and trust model for HELM policy
bundles — versioned, content-hashed packages of governance rules that can be
loaded at runtime without recompilation.

## 2. Motivation

Governance must be configuration, not code. Policy bundles enable:

- Runtime policy updates without binary redeployment
- Content-addressed, verifiable policy identity
- Jurisdiction and industry-specific policy packs
- Separation of policy authoring from kernel development

## 3. Bundle Structure

**A policy bundle is a single YAML file.** It is not a directory, not an
archive, and has no manifest, no `policies/` subdirectory, no `schemas/`
subdirectory, and no `SIGNATURE` sidecar. One file is one complete bundle.

```
/etc/helm/bundles/
├── corporate-baseline.yaml     # one file = one complete bundle
├── finance-sox.yaml            # another complete bundle
└── data-residency-eu.yaml      # another complete bundle
```

Tools that consume a *directory* treat every `*.yaml` and `*.yml` file in that
directory as an independent bundle and load each one whole. The glob is
non-recursive. This is what `bundle list --dir` does, and what the L3
conformance gate G14 does against `<evidence-dir>/bundles/`.

## 4. Bundle File Format

The complete set of top-level keys is `apiVersion`, `kind`, `metadata`, and
`rules`.

```yaml
apiVersion: helm.mindburn.run/v1
kind: PolicyBundle
metadata:
  name: corporate-baseline      # REQUIRED — load fails without it
  version: "1.2.0"
rules:
  - id: deny-system-writes
    action: "file_write"
    expression: 'params.path.startsWith("/etc/")'
    verdict: BLOCK
    reason: "Writing to system directories is prohibited"
  - id: allow-reads
    action: "read.*"
    expression: "true"
    verdict: ALLOW
    reason: "Reads are permitted"
```

### 4.1 Field reference

`metadata`:

| Key | Required | Notes |
| --- | --- | --- |
| `name` | yes | Load fails with `ErrBundleInvalid` if empty. |
| `version` | no | Free-form string; not parsed or range-checked. |
| `hash` | no | **Computed on load and overwritten.** Do not author it. |

`rules[]`:

| Key | Required | Notes |
| --- | --- | --- |
| `id` | yes | Load fails if empty. Also the composition dedup key. |
| `action` | yes | Load fails if empty. Effect-type pattern, matched by the caller. |
| `expression` | no | CEL source. **Carried as an opaque string** — see §4.3. |
| `verdict` | yes | Must be `BLOCK`, `ALLOW`, or `ESCALATE`. Case-insensitive. |
| `reason` | no | Human-readable explanation. |

`verdict` accepts exactly those three values. **`DENY` is rejected** at load
time with `ErrRuleInvalid` — use `BLOCK`. Verdict is upper-cased before the
check, so `block` and `Block` both load.

`apiVersion` and `kind` are parsed into the struct but are **not validated**.
An unknown `apiVersion` does not cause a load failure today; see §9.

### 4.2 JSON field names

The YAML keys and the JSON keys are not identical: the `Bundle` struct tags the
top-level `apiVersion` as **`api_version`** for JSON. All other keys keep their
spelling. No shipped code path marshals a `Bundle` to JSON today, so this
mapping matters only to Go callers that serialize the struct themselves.

The two CLI commands that emit JSON do **not** emit a bundle. Both
`bundle inspect` and `bundle list --json` emit `BundleInfo`, a flat inspection
record with no `api_version`, no `kind`, and no rule bodies:

```json
{
  "name": "corporate-baseline",
  "version": "1.2.0",
  "hash": "4ca9fb0250d6603ef7e51771b19801d7152691c3335de11ebdcef582b2100475",
  "rule_count": 2,
  "actions": ["file_write", "read.*"],
  "valid": true
}
```

`bundle list --json` emits an array of these; `bundle inspect` emits one.

### 4.3 Expression handling

`expression` is declared as CEL, but the bundle package **does not compile or
evaluate it**. It is loaded, hashed, composed, and handed on as a string. A
syntactically invalid expression therefore loads without error. Callers that
evaluate rules are responsible for compiling the expression and for reporting
compile failures.

Compiling a standalone Rego or Cedar policy is a **separate** pipeline reached
through `bundle build`, and it neither reads nor produces the format in this
section; see §6.3.

## 5. Integrity

Bundle identity is a content hash. There is no signature in the shipped format.

`metadata.hash` is set on every load to the SHA-256, hex-encoded, of the Go
`encoding/json` encoding of `{name, version, rules}` — in that field order.

Two consequences matter for integrators:

1. **`apiVersion` and `kind` are outside the hash.** Changing either does not
   change `metadata.hash`.
2. Any `hash` value present in the source YAML is discarded and replaced.

Verification compares a recomputed hash against an expected one:

```bash
# The hash is the one `bundle inspect` prints for the §4 example bundle.
helm-ai-kernel bundle verify --file ./corporate-baseline.yaml \
  --hash 4ca9fb0250d6603ef7e51771b19801d7152691c3335de11ebdcef582b2100475
```

A mismatch returns `ErrBundleHashMismatch` and exit code 1.

### 5.1 Composition

`Compose` merges bundles into one policy. Rules are deduplicated by `id` and
**the first bundle to define an id wins**; later definitions are dropped. When
a dropped rule carries a different `verdict` than the winner, the disagreement
is recorded in `conflicts` — it does not fail the composition. Composed rules
are sorted by `id`, and the composed hash is the SHA-256 of the encoded rule
list alone (bundle metadata is not part of it).

## 6. Trust Model

> [!IMPORTANT]
> **Status: DESIGN TARGET — not implemented.** Nothing in §6.1 or §6.2 exists.
> There is no `bundle sign` subcommand, no `--public-key` flag, no `SIGNATURE`
> file, no signature profile field in the bundle format, and no trust root
> store. The shipped integrity mechanism is the content hash in §5. Do not
> write an integration against this section.

### 6.1 Signing (target)

<!-- quantum_posture: policy bundle signing is unimplemented and profile-aware
only as a design target; classical Ed25519 would be legacy-compatible, while
hybrid deployments must require the hybrid profile and reject classical-only
bundle signatures. No bundle signature is produced or verified today. -->

The intended model: bundles declare a signature profile and algorithm. The
`classical` profile is Ed25519-compatible and not post-quantum. Deployments
requiring post-quantum durability must require a hybrid profile and reject
classical-only bundle signatures as a downgrade.

Intended profile names:

- `classical` with `ed25519-sha256`
- `hybrid` with `hybrid-ed25519-mldsa65-sha256`

### 6.2 Trust root (target)

The intended model is a kernel-held set of accepted public keys, with only
bundles signed by a trusted key being loaded.

```yaml
# TARGET — not read by any code today.
trust_roots:
  - key_id: "key-corporate-2026"
    public_key: "base64-encoded-ed25519-public-key"
    valid_from: "2026-01-01T00:00:00Z"
    valid_until: "2027-12-31T23:59:59Z"
```

### 6.3 What `bundle build` actually does

`bundle build` is implemented, but it does **not** operate on the format in §4
and it does **not** sign anything. Its own usage line calls the output "a signed
bundle"; that string is wrong. The command compiles one standalone policy source
through the `policybundles` registry and prints the compiled bundle's identity as
JSON. No signature, and no file, is written — the result goes to stdout.

Only `rego` and `cedar` are routed through the registry:

```bash
helm-ai-kernel bundle build --language=rego ./policy.rego
helm-ai-kernel bundle build --language=cedar --entities=./entities.json ./policy.cedar
helm-ai-kernel bundle build ./policy.rego     # language detected from extension
```

`--language=cel` is **rejected** at compile time with
`policybundles: language=cel is not yet routed through the registry; use the
existing celcheck path` and exit code 1. CEL is accepted as a language *name*
but has no registry path.

Output keys: `language`, `hash`, `bundle_id`, `name`, `version`. Language is
detected from the file extension when `--language` is omitted.

## 7. Lifecycle

### 7.1 Loading

```go
import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/bundles"

bundle, err := bundles.LoadFromFile("/etc/helm/bundles/corporate-baseline.yaml")
```

The exported surface of the package is:

| Function | Signature |
| --- | --- |
| `LoadFromFile` | `(path string) (*Bundle, error)` |
| `LoadFromBytes` | `(data []byte) (*Bundle, error)` |
| `Verify` | `(bundle *Bundle, expectedHash string) error` |
| `Compose` | `(bundles ...*Bundle) (*ComposedPolicy, error)` |
| `Inspect` | `(bundle *Bundle) *BundleInfo` |

Both loaders take a *file*, never a directory. Sentinel errors are
`ErrBundleNotFound`, `ErrBundleInvalid`, `ErrBundleHashMismatch`,
`ErrRuleInvalid`, and `ErrCompositionConflict`.

`Inspect` returns `{name, version, hash, rule_count, actions, valid}`, where
`actions` is the sorted unique set of rule `action` values.

### 7.2 Hot reload (target)

> [!IMPORTANT]
> **Status: DESIGN TARGET — not implemented.** No `bundle_loader` configuration
> key is read anywhere in this repository, and the bundle package contains no
> file watcher, no reload interval, and no snapshot swap. Reloading a bundle
> today means calling `LoadFromFile` again.

The intended model: file watchers or callbacks are wake-up hints only; the
runtime still loads the canonical bundle, verifies the expected content hash
and provenance, compiles an immutable snapshot, and swaps that snapshot
atomically.

```yaml
# TARGET — not read by any code today.
bundle_loader:
  watch: true
  reload_interval: 30s
  paths:
    - /etc/helm/bundles/
```

### 7.3 Remote fetch (target)

> [!IMPORTANT]
> **Status: DESIGN TARGET — not implemented.** Bundles are read from the local
> filesystem only. No remote fetch, refresh interval, or fetch-time signature
> verification exists.

```yaml
# TARGET — not read by any code today.
bundle_loader:
  remote:
    url: https://bundles.mindburn.run/corporate-baseline/v1.2.0
    refresh_interval: 1h
    signature_verification: required
```

### 7.4 Revocation (target)

> [!IMPORTANT]
> **Status: DESIGN TARGET — not implemented.** There is no bundle revocation
> list and no revocation check on the load path. A revoked bundle will load.

```yaml
# TARGET — not read by any code today.
revocation_list:
  - content_hash: "sha256:abc123..."
    revoked_at: "2026-03-06T00:00:00Z"
    reason: "Policy defect discovered"
```

## 8. EvidencePack Integration

`active_bundles` is a required EvidencePack field in the v1 conformance
vectors ([`protocols/conformance/v1/test-vectors.json`](../../conformance/v1/test-vectors.json),
`evidence_bundle_fixture`), alongside `schema_version`, `session_id`,
`receipts`, `decisions`, and `created_at`. The fixture shape is:

```json
{
  "active_bundles": [
    {
      "name": "corporate-baseline",
      "version": "1.0.0",
      "content_hash": "sha256:abc123"
    }
  ]
}
```

> [!NOTE]
> No emitter in this repository populates `active_bundles` — the field is
> defined by the conformance vector, and producers are expected to supply it.
> A `signer_key_id` member is **not** part of this shape and cannot be produced
> while §6 is unimplemented.

## 9. Conformance

The L3 gate G14 (`Policy Bundle Integrity`) is the executable conformance check.
Against `<evidence-dir>/bundles/` it fails when the directory is absent, when it
contains no `*.yaml`/`*.yml` file, when any file cannot be read, when any file
fails to load, or when a file's hash is not reproducible across two loads. It
counts successes in `bundles_verified`.

A bundle loader is conformant with the **shipped** format if:

1. It treats each YAML file as one complete bundle.
2. It rejects a bundle with an empty `metadata.name`.
3. It rejects a rule with an empty `id` or empty `action`.
4. It rejects a rule whose `verdict` is not `BLOCK`, `ALLOW`, or `ESCALATE`.
5. It computes `metadata.hash` deterministically over `{name, version, rules}`.
6. It deduplicates composed rules by `id`, first-wins, recording verdict
   conflicts without failing.

The following were previously listed as conformance requirements but are **not
implemented** and are retained as targets: rejecting an unknown `apiVersion`,
verifying a declared signature profile before loading, failing closed on
signature-verification failure, and checking a revocation list before loading.
