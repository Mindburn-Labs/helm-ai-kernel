# canonical-json-v1 Reference Pack

Status: Live. This pack is the conformance surface for
[`protocols/specs/rfc/canonical-json-v1.md`](../../protocols/specs/rfc/canonical-json-v1.md),
the normative specification of the JSON canonicalization every HELM signing
preimage, content address and chain hash is built on.

It proves one thing: the canonicalization rule is reproducible from the
specification alone. Two independent implementations — the kernel's Go
`canonicalize` package and `verify_vectors.py`, written from the specification
in pure-stdlib Python without calling `json.dumps` — are held to the same bytes
in CI.

It does **not** prove anything about any particular receipt, permit or
EvidencePack. Which fields enter a canonical document belongs to that
artifact's own profile specification.

## Contents

| File | Purpose |
|---|---|
| `vectors.json` | 13 vectors: input JSON text, exact canonical bytes, SHA-256, subset membership, and — for every deviation — what a strict RFC 8785 implementation produces instead |
| `verify_vectors.py` | Independent verifier, Python standard library only |

## Running it

```bash
make verify-canonical-json-vectors     # Go + Python, both implementations
python3 reference_packs/canonical-json-v1/verify_vectors.py
```

The Go half is
`TestCanonicalJSONReferencePackMatchesGoImplementation` in
`core/pkg/canonicalize/reference_pack_test.go`.

## The two things a third-party implementer must not miss

1. **Object keys are ordered by UTF-16 code unit, not by code point.** They
   differ for exactly one input class — a supplementary-plane key sorts before
   U+E000..U+FFFF, not after. `vectors.json` carries the sorting sample
   published in RFC 8785 Section 3.2.3 plus the minimal two-key case.
   `json.dumps(sort_keys=True)` and Rust's `Vec<&String>::sort()` are code
   point order and fail these vectors.

2. **Numbers deviate from RFC 8785.** HELM preserves the source literal rather
   than re-rendering it with the ECMAScript Number-to-String algorithm. The
   `deviation_*` vectors enumerate every observable case. Any document whose
   numbers are all integers within ±(2^53−1) is unaffected, and every signed
   HELM artifact is required to stay inside that subset — see Section 5 of the
   specification.
