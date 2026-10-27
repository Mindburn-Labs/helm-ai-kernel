# Provider recovery checkpoint evidence v1

This contract is a typed evidence primitive. It does not capture or retain a
checkpoint, observe Kubernetes or storage, call a signer, or authorize backup,
restore, dispatch or resume. Those producers remain separate integrations.

The closed descriptor schema lives in
`protocols/json-schemas/evidence/provider_recovery_checkpoint.v1.schema.json`.
Its fixed DSSE payload type is
`application/vnd.helm.provider-recovery-checkpoint.v1+json`, with purpose
`provider-recovery-checkpoint`. Every field is required. Unknown, duplicate,
case-aliased, null, incorrectly typed or unsupported fields refuse. Integers
stay within the interoperable `2^53-1` range. Go validation additionally
enforces byte/array bounds, ordered identity sets and cross-field bindings.
Integer wire values use unsigned decimal JSON integer literals; fractional
and exponent forms refuse even when they denote a mathematical integer.

`contracts.EncodeRecoveryCheckpoint` validates and deterministically encodes a
descriptor. `contracts.DecodeRecoveryCheckpoint` strictly decodes bytes while
preserving the distinction between application values and their wire encoding.
Invalid UTF-8 and unpaired escaped UTF-16 surrogates refuse before JSON decoding
can replace them. The schema covers seven runtime components and Console,
the exact native version cohort, installation and producer identities, capture
watermarks, private-content digest/length and all declared store participants.
It does not prove those observations occurred.

`evidence.RecoveryCheckpointPAE` constructs DSSEv1 pre-authentication encoding
using decimal **byte** lengths and the original payload bytes. A valid payload
need not already use the builder's canonical formatting. Signers and verifiers
must never substitute a re-encoded value for those bytes.
`evidence.NewRecoveryCheckpointEnvelope` assembles the one supported Ed25519
signature returned by an external signer. It accepts no private key. Signature
and payload base64 use the exact padded standard alphabet with canonical pad
bits; embedded keys and unsigned metadata are forbidden.

`evidence.VerifyRecoveryCheckpointEnvelope` requires an external policy with
the trusted public key, key hint, permitted purpose/type, validity window,
revocation state and complete expected descriptor. The expected descriptor
must come from authenticated capture/native/installation owners, never from
the envelope being verified. That context pins issuer, producer source/image,
bound Pod and ServiceAccount, scope, all eight installed identities, native
generation/cohort/cutoff, custody/content and lifecycle/store watermarks. A
signature or embedded key identifier cannot establish that policy.

Verification returns independent snapshot, descriptor and raw-envelope hashes,
plus copies of the same verified payload and envelope bytes. After a coordinator
or log has frozen an envelope, set `FrozenEnvelopeDigest` when reading it again.
An equivalent outer JSON representation has a different retained hash and is
refused in that mode. Future coordinator recovery must read the retained
envelope after a lost signer acknowledgement before attempting another sign;
randomized signatures must not replace the first frozen bytes. This library
does not consume replay identities or implement that persistence protocol.

`contracts.VerifyRecoveryCheckpointContent` checks supplied private bytes
against the descriptor's exact digest and size. It does not store, export,
interpret or make a custody claim about those bytes. Public descriptors contain
hashes and opaque identities; they contain no raw content, credential/token
values, lease tokens, private keys or storage locators. Source metadata and
hash claims still require their owning producers and scoped private custody.

The reference vector in
`core/pkg/evidence/testdata/recovery-checkpoint.v1.json` was constructed using
independent Python sorted UTF-8 JSON and byte-length PAE, then signed by OpenSSL
Ed25519 with a public RFC 8032 test seed. It is test material only. Its multibyte
issuer distinguishes byte lengths from rune counts. Native tests pin the full
payload, PAE, signature and envelope, and exercise closed-schema, trust,
semantic-binding, content and exact-replay refusal controls. No legacy fixture
or signature gains new checkpoint authority.
