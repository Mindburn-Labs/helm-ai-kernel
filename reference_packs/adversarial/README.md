# Kernel adversarial reference pack

`kernel-v1/` is the committed positive-control EvidencePack used to exercise
the built `helm-ai-kernel conform adversarial` binary in CI. It is deliberately
`dev-local` evidence and is not customer, production, or release authority.

quantum_posture: The reference campaign uses classical Ed25519 signatures for
CI contract coverage only; it makes no post-quantum authorization or report
attestation claim. This pack-level annotation applies to the immutable,
hash-pinned payloads under `kernel-v1/` so their signed bytes are not modified
solely to carry documentation metadata.

The pack is sealed and its campaign-only authorization receipts and tool
manifest are signed. CI supplies the corresponding public campaign trust root:

```text
70f119275e0cd9d66cd72e8d74810eb4654dd58c1800fc3fcceb1881550b3e8d
```

The pack-seal and campaign-signing private keys are not committed. CI derives a
separate, clearly labelled deterministic test-only report-attestation key;
reports produced by that job prove the command contract only and must never be
accepted as production campaign evidence.
