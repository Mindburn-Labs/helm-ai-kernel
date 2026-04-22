# Canonicalization Rules v0

> Exact rules for computing deterministic hashes of policy artifacts.
> These rules ensure byte-identical digests across native Rust and WASM runtimes.

## 1. General Principles

- **Never hash raw Protobuf bytes** — Protobuf serialization is not deterministic across implementations
- Compute hashes over **canonical bytes** derived from the typed structure
- All hashes use **SHA-256** unless otherwise specified

## 2. Canonical JSON Encoding

For fields marked `*_canonical` (e.g. `params_canonical`, `value_canonical`):

1. **Key ordering**: lexicographic ascending (Unicode code point order)
2. **No whitespace**: no spaces, tabs, or newlines between tokens
3. **Number encoding**: integers as decimal (no leading zeros), no `+` prefix
4. **String encoding**: UTF-8, escape only `"`, `\`, and control characters
5. **No trailing commas**
6. **Financial values**: int64 cents (never floating point)
7. **Null handling**: omit null fields entirely (do not emit `"key": null`)

## 3. TooltipModelV1 Canonical Bytes

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

For `BaseRef.org_genome_snapshot.digest` and `CpiVerdict.plan_ir_hash`:

1. Extract all fields from the PlanIRDelta (excluding `op.op_id` and `actor`)
2. Encode as canonical JSON (§2 rules)
3. Hash with SHA-256

## 5. PolicyBundle Canonical Hash

For `PolicyBundle.policy_bundle_hash`:

1. Extract: `cpi_hash`, `jurisdiction_scope_id`, `adapter_set_refs` (sorted), `bytecode`, `source_syntax_version`
2. Concatenate as: `cpi_hash || jurisdiction_scope_id || sorted_refs || bytecode || version`
3. Hash with SHA-256

## 6. Patch Application Digest

For `ApplyWitnessPatchDelta` verification:

1. Concatenate: `patch_set_hash || sorted(patch_ids) || canonical(parameters_canonical)`
2. Hash with SHA-256
3. Deterministic IDs: `SHA256(patch_set_hash || patch_id || subject_id || "helm-patch-v0")`

## 7. Cross-Runtime Equivalence

CI MUST verify that native Rust and WASM produce byte-identical canonical bytes for the same input. Test with the golden corpus in `helm-policy-vm/tests/golden/`.
