# extauthz Reference Pack

Status: Phase 1 fixture only.

This pack contains cross-language canonicalization vectors for the HELM Kernel
external authorization contract. It does not prove a gateway integration, a real
EffectPermit issuer, a ProofGraph write, or an EvidencePack export.

Pre-dispatch authorization and post-dispatch effect proof remain distinct:

- `ALLOW` can carry a signed, scoped, single-use `EffectPermit`.
- Pre-dispatch responses do not carry final effect receipts.
- Post-dispatch proof closure is represented by later `EFFECT` receipts,
  ProofGraph edges, and EvidencePack references.
