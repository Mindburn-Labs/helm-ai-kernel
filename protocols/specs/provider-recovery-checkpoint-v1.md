# Provider recovery checkpoint evidence v1

<!-- quantum_posture: this contract uses classical Ed25519 DSSE signatures only. -->

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
UUID fields accept exactly nonzero lowercase hexadecimal IDs in the hyphenated
8-4-4-4-12 form. They impose no UUID version or variant restriction.

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

The shipped offline CLI exposes these operations through
`helm-ai-kernel evidence checkpoint`. `prepare --descriptor descriptor.json`
prints a public JSON bundle containing canonical payload and DSSE PAE as
base64. Use `--emit payload` or `--emit pae` for exact bytes on stdout.
The global `--format=json` selection works for JSON results and refuses when
combined with an exact-byte `--emit` mode.
`assemble --payload payload.json --key-id KEY_ID --signature-hex SIGNATURE`
packages the explicitly supplied external signature without verifying it or
claiming signing authority. It preserves the exact validated payload bytes.
The released signer still needs its separate purpose-specific integration;
preparing material does not establish that an existing signer accepts it.

`verify` requires every independent trust input explicitly:

```sh
helm-ai-kernel evidence checkpoint verify \
  --envelope envelope.json --expected trusted-descriptor.json \
  --public-key-hex "$TRUSTED_PUBLIC_KEY_HEX" --key-id "$TRUSTED_KEY_ID" \
  --purpose provider-recovery-checkpoint \
  --payload-type application/vnd.helm.provider-recovery-checkpoint.v1+json \
  --valid-from-unix "$TRUSTED_VALID_FROM" --valid-until-unix "$TRUSTED_VALID_UNTIL" \
  --verify-at-unix "$HISTORICAL_VERIFICATION_INSTANT" --revoked=false
```

The caller must obtain every trust input and the complete expected descriptor
through authenticated independent owners. The CLI neither
authenticates those files' provenance nor discovers trust from the envelope.
It reads no clock and performs no network, signer, key-generation or storage
operation. Missing policy inputs refuse. Inputs are bounded regular local
files; descriptor and envelope JSON use the same closed codecs as the library.
Duplicate/unknown flags and positional inputs refuse. Errors omit input paths,
values and file contents. The commands write only stdout/stderr.

Successful verification reports `signed_descriptor_only` and hashes by default.
Adding `--content snapshot.bin` verifies the supplied private bytes' exact hash
and length and reports `signed_descriptor_and_supplied_content`. Results never
contain those bytes or local paths. Neither scope proves capture consistency,
retention, private-store custody, runtime installation, backup or restore/resume
authority. Use `--frozen-envelope-digest sha256:...` when independently retained
state already pins exact envelope bytes. The CLI does not consume replay state.

The reference vector in
`core/pkg/evidence/testdata/recovery-checkpoint.v1.json` was constructed using
independent Python sorted UTF-8 JSON and byte-length PAE, then signed by OpenSSL
Ed25519 with a public RFC 8032 test seed. It is test material only. Its multibyte
issuer distinguishes byte lengths from rune counts. Native tests pin the full
payload, PAE, signature and envelope, and exercise closed-schema, trust,
semantic-binding, content and exact-replay refusal controls. No legacy fixture
or signature gains new checkpoint authority.
