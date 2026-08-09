---
title: "HELM Canonical JSON Specification"
status: final
version: "1.0.0"
created: 2026-08-06
finalized: 2026-08-06
authors:
  - HELM Core Team
---

# RFC: HELM Canonical JSON v1.0

## Abstract

This document specifies the byte-exact JSON canonicalization used to build
every signing preimage, content address and chain hash in HELM. It states one
deviation from RFC 8785 precisely enough for an independent implementation to
reproduce HELM bytes on purpose, and defines the subset on which HELM and a
strict RFC 8785 implementation are byte-identical.

## Status

Final — Normative Standard.

This specification is normative for the `canonicalize` package
(`core/pkg/canonicalize/jcs.go`) and every artifact whose signing payload,
content hash or chain hash passes through it. It replaces the informal claim
"RFC 8785 compliant" that previously appeared in the package documentation.

## 1. Introduction

### 1.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

### 1.2 Relationship to RFC 8785

HELM canonical JSON is RFC 8785 (JSON Canonicalization Scheme) with **one
deviation from its normative serialization rules**: Section 3.2.2.3 number
serialization. Object property ordering (RFC 8785 Section 3.2.3), string
escaping (Section 3.2.2.2), whitespace and literal handling are implemented as
specified.

Two behaviours concern input that RFC 8785 places outside its data model and
therefore does not specify — ill-formed UTF-8 (Section 2.2 below) and duplicate
object keys (Section 2.3). They are not deviations from the RFC, but they are
observable, so they are stated rather than left to be discovered.

Sections 2 and 3 of this document restate the conformant parts so the rule is
readable without the RFC in hand. Sections 4 and 5 define the deviation and the
subset that eliminates it. Section 7 lists the vectors.

## 2. Serialization

Canonical output is a UTF-8 byte sequence with:

- no whitespace between tokens;
- no trailing newline;
- `null`, `true` and `false` as those exact literals;
- arrays as `[` element `,` element `]` with element order **preserved**
  exactly as received — array order is data and MUST NOT be sorted;
- objects as `{` key `:` value `,` key `:` value `}` with keys ordered per
  Section 3.

Verified against `core/pkg/canonicalize/jcs.go:92-166`.

### 2.1 Strings

Only the following are escaped, per RFC 8785 Section 3.2.2.2:

| Input | Output |
|---|---|
| U+0022 QUOTATION MARK | `\"` |
| U+005C REVERSE SOLIDUS | `\\` |
| U+0008 | `\b` |
| U+000C | `\f` |
| U+000A | `\n` |
| U+000D | `\r` |
| U+0009 | `\t` |
| other U+0000..U+001F | `\u` followed by four **lowercase** hexadecimal digits |

Every other code point is emitted as literal UTF-8. In particular U+007F,
U+0080, U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are **not**
escaped, and `<`, `>` and `&` are **not** escaped. Implementations built on a
JSON encoder that escapes HTML characters or the JavaScript line terminators
MUST disable that behaviour.

Verified against `core/pkg/canonicalize/jcs.go:314-347` (`marshalJCSString`).

### 2.2 Ill-formed UTF-8 (implementation note, not a rule)

`canonicalize.JCS` accepts a Go value that has already passed through
`encoding/json`, which substitutes U+FFFD for ill-formed byte sequences. An
input carrying invalid UTF-8 therefore canonicalizes to a document containing
U+FFFD rather than failing. Producers MUST NOT rely on this: a HELM artifact
MUST contain only well-formed UTF-8, and a verifier MAY reject ill-formed input
outright. Pinned by `TestJCSIsLossyOnInvalidUTF8`.

### 2.3 Duplicate object keys (implementation note, not a rule)

RFC 7493 (I-JSON), which RFC 8785 builds on, forbids duplicate object member
names. `canonicalize.JCS` does not reject them: the `encoding/json` decode into
a map keeps the **last** occurrence, so `{"a":1,"a":2}` canonicalizes to
`{"a":2}`. A producer MUST NOT emit a document with duplicate keys, and a
verifier that parses the wire bytes itself SHOULD reject one rather than
silently agreeing with us.

### 2.4 Top-level values

A top-level value of any JSON type is canonicalized, not only an object.
`JCS("x")` yields `"x"`.

## 3. Object property ordering (normative)

Property names MUST be sorted by comparing them as arrays of **UTF-16 code
units**, each treated as an unsigned integer, with a shorter name that is a
prefix of a longer one sorting first. This is RFC 8785 Section 3.2.3.

This is **not** the same as sorting by UTF-8 bytes or by Unicode code point.
Those two agree with each other and differ from UTF-16 order for exactly one
input class: a supplementary-plane character (U+10000 and above) is encoded in
UTF-16 as a surrogate pair beginning in U+D800..U+DBFF, so it sorts **before**
every character in U+E000..U+FFFF, whereas in code point order it sorts after.

Reference implementations of the comparison:

| Language | Expression |
|---|---|
| Go | `utf16.Encode([]rune(k))`, compared element-wise |
| Python | `sorted(obj, key=lambda k: k.encode("utf-16-be"))` |
| Rust | `keys.sort_by_key(\|k\| k.encode_utf16().collect::<Vec<u16>>())` |
| JavaScript / Java / .NET | native string comparison (already UTF-16) |

`json.dumps(..., sort_keys=True)` in Python and `Vec<&String>::sort()` in Rust
are code point order and are therefore **not** conformant. Both were corrected
in this repository on 2026-08-06.

Verified against `core/pkg/canonicalize/jcs.go:172-192` (`lessUTF16`) and
`core/pkg/canonicalize/jcs.go:130` (the map branch of `marshalRecursive`).

## 4. Numbers — the deviation (normative)

RFC 8785 Section 3.2.2.3 requires a number to be converted to an IEEE 754
double and re-serialized by the ECMAScript `Number::toString` algorithm
(ECMA-262 Section 7.1.12.1, with the Note 2 enhancement).

**HELM does not do this.** HELM emits the JSON number **literal** unchanged:

- when canonicalizing a JSON text, the number token is copied verbatim from
  the source document;
- when canonicalizing a Go value, `encoding/json` formats the value first, and
  that literal is then preserved verbatim.

Consequences, all pinned by vectors in Section 7:

| Input literal | HELM emits | Strict RFC 8785 emits |
|---|---|---|
| `1e2` | `1e2` | `100` |
| `1E2` | `1E2` | `100` |
| `1.0` | `1.0` | `1` |
| `1.50` | `1.50` | `1.5` |
| `-0` | `-0` | `0` |
| `9007199254740993` | `9007199254740993` | `9007199254740992` |
| `1e21` (as a Go `float64`) | `1e+21` | `1e+21` |

**Rationale.** HELM signs `uint64` and `int64` fields — `lamport_clock`,
`tree_size` — whose exact value is part of the governed meaning. Round-tripping
them through an IEEE 754 double would sign a different number than the one the
kernel decided on. RFC 8785 Appendix B anticipates this and recommends
confining true integers to ±(2^53−1); Section 5 makes that recommendation
enforceable rather than advisory.

## 5. The interoperable subset (normative)

A JSON number is **interoperable** if and only if its literal is a decimal
integer matching `-?(0|[1-9][0-9]*)`, is not `-0`, and has absolute value at
most 9007199254740991 (2^53−1).

For a document in which every number is interoperable, HELM canonical JSON and
a strict RFC 8785 implementation produce **identical bytes**. Outside the
subset they may differ, and the deviation in Section 4 becomes observable.

Therefore:

- Every HELM artifact whose canonical bytes are signed, hashed into a chain, or
  published as a test vector **MUST** contain only interoperable numbers.
- A producer **MUST** apply the check before freezing bytes.
  `canonicalize.CheckInteroperableNumbers` returns an error naming the JSON
  path of the first offending value; `canonicalize.InteroperableJCS` refuses to
  emit bytes at all. The equivalent in the Python reference verifier is
  `check_interoperable`.
- A quantity that cannot satisfy the subset — a monetary amount, a ratio, a
  measurement — **MUST** be carried as a JSON string, not as a JSON number.

Verified against `core/pkg/canonicalize/jcs.go:206-296` and
`reference_packs/canonical-json-v1/verify_vectors.py`.

## 6. One canonicalizer per artifact (normative)

There is exactly one canonical JSON encoder in the kernel Go tree:
`core/pkg/canonicalize`. `crypto.CanonicalMarshal` is retained as a thin alias
for `canonicalize.JCS` and MUST NOT be reimplemented.

Before 2026-08-06 `crypto.CanonicalMarshal` was an independent encoder built on
`encoding/json.Encoder`. It disagreed with `canonicalize.JCS` on three inputs:
it emitted **struct fields in Go declaration order** rather than sorted order,
it escaped U+2028/U+2029, and it escaped the U+FFFD substitutions produced from
ill-formed UTF-8. It was the encoder behind
`translog.SignedTreeHead.SigningBytes`, so reordering a Go struct field changed
signed bytes silently. The signed tree head payload
(`log_id`, `root_hash`, `timestamp`, `tree_size`) happened to be declared in
lexicographic order, so no published tree head changed; that coincidence is now
a pinned golden (`TestSTHSigningBytesAreCanonicalGolden`,
`TestSTHSignatureIsReproducibleFromAFixedSeed`).

A second private copy lived in `core/cmd/helm-ai-kernel/conform.go`
(`canonicalJSON`/`marshalCanonical`). It also produced signed bytes — the
external-failure HCV validation manifest at
`writeExternalFailureValidationManifest` — and had drifted in two ways: it
sorted keys by code point and it escaped U+2028/U+2029. It now delegates to
`canonicalize.JCS`; its manifest preimage is pinned by
`TestValidationManifestPreimageIsByteStable`.

The following implementations outside `core/` also implement this
specification and are held to the same vectors:

| Implementation | Path |
|---|---|
| Rust SDK | `sdk/rust/src/canonical.rs` |
| Reference-pack verifier (its own pack, plus imported by 9 others) | `reference_packs/approval/verify_approval_vectors.py` |
| Reference-pack verifier (extauthz) | `reference_packs/extauthz/verify_extauthz_vectors.py` |
| Specification reference implementation | `reference_packs/canonical-json-v1/verify_vectors.py` |

### 6.1 The one permitted specialization

`crypto.CanonicalizeDecisionV4` (`core/pkg/crypto/canonical.go:398-460`)
appends the decision.v4 envelope's twelve keys in a hardcoded order with a
hand-written string escaper (`appendJCSQuotedString`, `:461`), to keep the
authorization hot path allocation-free. It is byte-for-byte equivalent to
`canonicalize.JCS` over the same envelope, and that equivalence is asserted
against the real encoder — not against a literal — by
`TestCanonicalizeDecisionV4MatchesJCS`
(`core/pkg/crypto/decision_signature_v4_test.go:149`). All twelve keys are
ASCII, so Section 3 ordering is neutral for it.

A specialization of this kind is permitted only with such an equivalence test.
Without one it is a second definition of a signed preimage.

### 6.2 Outside this specification's scope

`protocols/policy-schema/v1/canonicalization.md` describes a **separate and
unimplemented** canonicalization: the intended content of the `*_canonical`
protobuf fields on the `helm.policy.v1` messages (`params_canonical`,
`value_canonical`, `tooltip_model_canonical` and the rest). It is a design
target, not a conformance target. It sits outside `protocols/specs/`, has no
reference pack under `reference_packs/`, and no gate checks any rule in it, so
under ADR 0003 §§D2–D3 it is UNSPECIFIED and MUST NOT be cited as a
specification. `helm.policy.v1` generates no code — `sdk/go/gen/helm/` carries
`{authority,effects,intervention,kernel,truth}/v1` only — so nothing in this
repository populates those fields.

The distinction from this document is one of subject, not of rule: this
document specifies a JSON encoder and the exact bytes it emits, while that page
sketches per-message canonical-bytes profiles for protobuf artifacts — which
fields enter a preimage, and how repeated fields and maps are ordered before
encoding. If those profiles are ever implemented they MUST take their JSON
bytes from `canonicalize.JCS` rather than re-derive the rule; a profile that
re-derives it is a second definition of a signed preimage, which Section 6.1
admits only with an equivalence test.

New code MUST NOT construct a canonical encoder from `encoding/json`,
`json.dumps`, `serde_json::to_string` or any other library encoder without
applying Sections 2, 3 and 5 on top of it.

## 7. Conformance vectors

`reference_packs/canonical-json-v1/` holds the vectors. Each entry carries the
input JSON text, the exact canonical bytes, their SHA-256 digest, whether the
input is inside the Section 5 subset, and — for every vector outside it — the
rendering a strict RFC 8785 implementation produces instead, so no deviation is
silent.

Run both implementations:

```bash
make verify-canonical-json-vectors
```

That target runs the Go implementation
(`TestCanonicalJSONReferencePackMatchesGoImplementation`) and
`reference_packs/canonical-json-v1/verify_vectors.py`, a second implementation
written from this document in pure-stdlib Python that does not call
`json.dumps`. Passing both is the evidence that this specification is
sufficient to build a conformant implementation without reading the kernel's
Go.

Vector coverage:

| Vector | Property |
|---|---|
| `rfc8785_section_3_2_3_sorting` | the sorting sample published in RFC 8785 Section 3.2.3 |
| `supplementary_plane_key_sorts_first` | the minimal UTF-16-vs-code-point divergence |
| `bmp_keys_order_identically` | ordering is unchanged below U+E000 |
| `escape_set_rfc8785_section_3_2_2_2` | the full escape set, including what is *not* escaped |
| `array_order_is_preserved` | arrays are never sorted |
| `literal_types` | `null`, `true`, `false`, `{}`, `[]` |
| `safe_integer_bounds` | the Section 5 subset boundary |
| `deviation_exponent_literal` | negative: `1e2` |
| `deviation_uppercase_exponent` | negative: `1E2` |
| `deviation_trailing_zero_fraction` | negative: `1.0`, `1.50` |
| `deviation_negative_zero` | negative: `-0` |
| `deviation_beyond_safe_integer` | negative: 2^53+1 |
| `deviation_non_integer` | negative: `0.1`, identical today by runtime accident |

## 8. What this specification does not cover

- It does not define any signing preimage. Which fields enter the canonical
  document, and in what shape, belongs to each artifact's own profile
  specification.
- It does not define signature algorithms or encodings.
- It does not cover `crypto.CanonicalizeReceipt` (the legacy V4 colon-delimited
  receipt preimage) or `crypto.CanonicalizeDecision`, which are string
  concatenations, not JSON canonicalization.

## 9. Changelog

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-08-06 | Initial specification. Corrects object ordering from code point to UTF-16 code unit in the Go canonicalizer, the Rust SDK and the reference-pack Python verifiers; folds `crypto.CanonicalMarshal` and the `conform` CLI's private copy into `canonicalize.JCS`; defines the interoperable number subset and the enforcement helpers. No published canonical artifact changed: all 49 `*.c14n.json` files in `reference_packs/` use ASCII object keys and safe-range integers only, and all 12 reference-pack verifiers pass unchanged. |
