# Approval authority reference vectors

<!-- quantum_posture: these fixtures exercise classical Ed25519 approval
assertions only; they do not establish hybrid or post-quantum approval support. -->

This pack pins the cross-language bytes for the HELM approval challenge,
assertion signing payloads, authority snapshot, sorted signer set, and verified
projection introduced by HELM-142.

`verify_approval_vectors.py` is intentionally independent of the Go contract
implementation and uses only the Python standard library. It verifies RFC 8785
canonical bytes for this ASCII/integer fixture, SHA-256 bindings, strict
Ed25519 signatures, signer ordering, exact authority/challenge linkage, and
negative tamper cases. The positive inputs are intentionally unsorted; the
independent verifier also checks tenant/workspace/role/action/audience scope,
key activity windows, distinct signer dimensions, and an invalid surplus
signature in the over-quorum case.

Signer identity fields use `^[A-Za-z0-9._~:/@+-]+$` and are compared without
normalization as ascending ASCII-byte tuples `(principal_id, credential_id,
device_id, key_id)`. This makes signer-set ordering identical in Go, Python,
and JavaScript.

These vectors are conformance evidence, not mutation authority. They do not
prove durable nonce release, registry provenance, replay consumption, grant or
permit issuance, or pack-lifecycle enforcement.

Run:

```sh
python3 reference_packs/approval/verify_approval_vectors.py
```
