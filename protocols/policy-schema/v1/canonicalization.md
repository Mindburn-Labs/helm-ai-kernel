# Canonicalization Rules v0

> [!IMPORTANT]
> **Status: DESIGN TARGET — UNSPECIFIED, not implemented.**
> Sections 2–7 describe the intended canonicalization for the `helm.policy.v1`
> schema. **None of it is implemented in this repository.** The `helm.policy.v1`
> messages generate no code (`sdk/go/gen/` carries `helm/{authority,effects,
> intervention,kernel,truth}/v1` only), there is no policy VM, and no gate
> checks any rule below.
>
> Per [ADR 0003 §D2](../../../docs/adr/0003-normative-artifact-arbitration.md),
> an integrity contract is normative only when a specification under
> `protocols/specs/` is paired with a CI-bound reference pack under
> `reference_packs/`. This document is neither, so it is **UNSPECIFIED** in the
> ADR 0003 §D3 sense: do not build a verifier against it, and do not cite it as
> a conformance target.
>
> **For canonical JSON that actually ships, use
> [`protocols/specs/rfc/canonical-json-v1.md`](../../specs/rfc/canonical-json-v1.md)
> (status: final) and its reference pack
> [`reference_packs/canonical-json-v1/`](../../../reference_packs/canonical-json-v1/).**
> See §0 below for the full map of what canonicalizes policy today.

> Intended rules for computing deterministic hashes of policy artifacts.
> The design goal is byte-identical digests across independent runtimes; §7
> records how far that has actually been taken.

## 0. What canonicalizes policy today (implemented)

This section is the part of the page an integrator can build against. Everything
after it is a target.

| Concern | Real interface | Gate |
| --- | --- | --- |
| Canonical JSON bytes | `canonicalize.JCS` / `JCSString` / `CanonicalHash` — `core/pkg/canonicalize/jcs.go:47,84,69` | `make verify-canonical-json-vectors` (`Makefile:56`), reached from `make verify-fixtures` (`Makefile:136`), run in CI at `.github/workflows/ci.yml:167` |
| The rule those bytes follow | [`protocols/specs/rfc/canonical-json-v1.md`](../../specs/rfc/canonical-json-v1.md) — RFC 8785 with one stated number-serialization deviation | same target; vectors in [`reference_packs/canonical-json-v1/vectors.json`](../../../reference_packs/canonical-json-v1/vectors.json), independently verified by `verify_vectors.py` |
| Signing preimages | `core/pkg/crypto/canonical.go`, `core/pkg/crypto/canonical_v5.go` | per-family reference packs; see ADR 0003 §D4 for which families are SPECIFIED |
| Policy-stack validation ("CPI") | `core/pkg/kernel/cpi/cpi.go` — pure Go, unconditionally compiled, and the only CPI implementation | `core/pkg/kernel/cpi/cpi_test.go` |
| WASM policy execution | `core/pkg/policy/wasm/` — Go + wazero, modules content-addressed by SHA-256 of the binary | `core/pkg/policy/wasm/executor_test.go` |

Two divergences an integrator must not miss:

- **The shipped CPI does not implement §§2–6.** `core/pkg/kernel/cpi/cpi.go`
  hashes plain `encoding/json` output (`hashBytes`, `computeLayerHash`,
  `computeResultHash`, `computeBundleHash`) over the Go structs `PolicyLayer`,
  `PolicyRule`, `ValidationResult` and `CompiledBundle` — **not** over
  `canonicalize.JCS`, and **not** over any `helm.policy.v1` protobuf message.
  Its JSON tags (`name`, `priority`, `rules`, `verdict`, `hash`, `conflicts`,
  `layers`) are the actual field names on the wire; no field named in §§3–6
  exists in code.
- **The WASM path is not a second implementation of these rules.**
  `core/pkg/policy/wasm` runs caller-supplied compiled modules; it defines no
  canonicalization of its own and shares no code with §2.

## 1. General Principles

- **Never hash raw Protobuf bytes** — Protobuf serialization is not deterministic across implementations
- Compute hashes over **canonical bytes** derived from the typed structure
- All hashes use **SHA-256** unless otherwise specified

## 2. Canonical JSON Encoding

> Target. When implemented this MUST call `canonicalize.JCS`
> (`core/pkg/canonicalize/jcs.go:47`) rather than re-deriving the rule, so that
> policy artifacts land inside the specification and vector pack that already
> exist.

For fields marked `*_canonical` (e.g. `params_canonical`, `value_canonical`):

1. **Key ordering**: ascending by **UTF-16 code unit**, per RFC 8785 §3.2.3 and
   [`canonical-json-v1.md` §3](../../specs/rfc/canonical-json-v1.md).
   This is **not** Unicode code point order and **not** UTF-8 byte order — a
   supplementary-plane key sorts before U+E000..U+FFFF, not after. Python's
   `json.dumps(sort_keys=True)` and Rust's `Vec<&String>::sort()` are code point
   order and are non-conformant. (Earlier revisions of this page specified code
   point order; that was wrong.)
2. **No whitespace**: no spaces, tabs, or newlines between tokens
3. **Number encoding**: integers as decimal (no leading zeros), no `+` prefix.
   Stay inside integers in ±(2^53−1) — outside that subset the Go canonicalizer
   preserves the source literal instead of re-rendering it
   (`canonical-json-v1.md` §§4–5), so cross-implementation agreement is only
   guaranteed within the subset.
4. **String encoding**: UTF-8, escape only `"`, `\`, and control characters
   (RFC 8785 §3.2.2.2; U+007F, U+2028, U+2029, `<`, `>` and `&` are **not**
   escaped)
5. **No trailing commas**
6. **Financial values**: int64 cents (never floating point)
7. **Null handling**: omit null fields entirely (do not emit `"key": null`).
   Note this is a *profile* rule about which fields enter the document;
   `canonicalize.JCS` itself emits a `null` literal for a null it is given.

## 3. TooltipModelV1 Canonical Bytes

> Target. `TooltipModelV1` and `WitnessSummary` are declared in
> `explain.proto` / `focus.proto` and have no implementation.

Used for `WitnessSummary.tooltip_model_canonical`:

### Array Ordering

| Array        | Sort Key                                     | Tie-Breaker                 |
| ------------ | -------------------------------------------- | --------------------------- |
| `reasons`    | `code` (lexicographic)                       | `subjects[0]` ID            |
| `highlights` | `subject` ID (node_id \|\| edge_id \|\| ...) | —                           |
| `actions`    | `kind` (enum value ascending)                | `patch_id` or `policy_path` |

### Map Key Ordering

All `map<string, ArgValue>` fields: keys sorted lexicographic ascending.

### Encoding

1. Sort all arrays and maps per rules above
2. Serialize to Protobuf using deterministic encoding (sorted map keys)
3. Hash the resulting bytes with SHA-256

## 4. PlanIRDelta Canonical Hash

> Target. `PlanIRDelta` (`plan_ir.proto`) and `CpiVerdict` (`verdict.proto`) are
> declarations only.

For `BaseRef.org_genome_snapshot.digest` and `CpiVerdict.plan_ir_hash`:

1. Extract all fields from the PlanIRDelta (excluding `op.op_id` and `actor`)
2. Encode as canonical JSON (§2 rules)
3. Hash with SHA-256

## 5. PolicyBundle Canonical Hash

> Target. `PolicyBundle` (`policy_bundle.proto`) is a declaration only. The
> bundle hash the kernel computes today is
> `core/pkg/kernel/cpi/cpi.go` `computeBundleHash` over `CompiledBundle.Layers`,
> which has none of the fields below.

For `PolicyBundle.policy_bundle_hash`:

1. Extract: `cpi_hash`, `jurisdiction_scope_id`, `adapter_set_refs` (sorted), `bytecode`, `source_syntax_version`
2. Concatenate as: `cpi_hash || jurisdiction_scope_id || sorted_refs || bytecode || version`
3. Hash with SHA-256

## 6. Patch Application Digest

> Target. `ApplyWitnessPatchDelta` (`plan_ir.proto`, `focus.proto`) is a
> declaration only.

For `ApplyWitnessPatchDelta` verification:

1. Concatenate: `patch_set_hash || sorted(patch_ids) || canonical(parameters_canonical)`
2. Hash with SHA-256
3. Deterministic IDs: `SHA256(patch_set_hash || patch_id || subject_id || "helm-patch-v0")`

## 7. Cross-Runtime Equivalence

**Not implemented. There is no `helm-policy-vm` crate and no golden corpus at
`helm-policy-vm/tests/golden/`.** `crates/` has never existed in this
repository — `git log --all -- crates` returns nothing across the full history
of a non-shallow clone.

The last reference to that crate anywhere in the tree was
`core/pkg/kernel/cpi/cgo_bridge.go`, which linked `-lhelm_policy_vm` and
included `crates/helm-policy-vm/include/helm_cpi.h` behind a
`//go:build cpi_native` tag that no Makefile target, workflow or script ever
set. It was deleted in #821, together with the complementary
`//go:build !cpi_native` constraint on `cpi.go`. `core/pkg/kernel/cpi/cpi.go` is
now the only CPI implementation, compiled unconditionally. After this page is
corrected, no reference to `helm-policy-vm` remains in the repository.

There is likewise no WASM leg to compare against: the only WASM in the policy
path is the Go/wazero host in `core/pkg/policy/wasm`, which executes modules
rather than canonicalizing anything.

**What CI does verify today** — the nearest shipped analogue, and the model to
copy:

| Check | Where |
| --- | --- |
| Go canonicalizer against an independent pure-stdlib Python implementation, 13 vectors | `make verify-canonical-json-vectors` (`Makefile:56`) → `.github/workflows/ci.yml:167` |
| **Rust** canonicalizer against the same Go-produced canonical bytes | `sdk/rust/src/canonical.rs` (UTF-16 key ordering at `:11-13,37`) asserted against `reference_packs/extauthz/vectors.json`, run by `make test-sdk-rust` (`Makefile:110`) → `.github/workflows/ci.yml:217-223` |

Note the Rust that CI holds to byte identity is the **client SDK crate**
(`sdk/rust`), not a policy VM, and the agreement holds over the interoperable
subset defined in `canonical-json-v1.md` §5.

**Target, with prerequisites.** Before a cross-runtime equivalence gate can be
required here, in order: (1) `helm.policy.v1` needs a code-generation target and
an implementation; (2) the canonical bytes need a preimage specification under
`protocols/specs/` and a reference pack under `reference_packs/` per ADR 0003
§D2; (3) only then can a second runtime be held to those vectors in CI, the way
`sdk/rust` is held to `reference_packs/extauthz/`.
