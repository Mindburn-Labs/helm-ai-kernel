# HELM OSS Scope Cutline

> This document defines the boundary between what HELM OSS ships today and what the specification describes.

HELM OSS targets **L1/L2 core conformance**. The specification contains L3, enterprise, and 2030 extensions that are not part of the current OSS release.

For the authoritative scope definition, see [OSS_SCOPE.md](OSS_SCOPE.md).

## Shipped in OSS

| Surface | Conformance Level |
|---------|-------------------|
| Fail-closed PEP | L1 |
| JCS canonicalization + SHA-256 | L1 |
| Ed25519 signed receipts | L1 |
| Lamport-ordered ProofGraph | L2 |
| WASI sandbox (gas/time/memory) | L2 |
| Approval ceremonies | L2 |
| EvidencePack export + offline verify | L2 |
| Proof Condensation (Merkle) | L2 |
| OpenAI-compatible proxy | L1 |
| MCP interceptor | L1 |

## Not Shipped (Spec Only)

| Surface | Target |
|---------|--------|
| L3 conformance (federation, multi-org) | Enterprise |
| Surface Design Studio | Commercial |
| Policy staging / shadow enforcement | Commercial |
| Certified Connector Program | Commercial |
| Enterprise evidence retention | Commercial |
| Managed control plane | Commercial |

## Boundary Invariant

OSS must remain fully useful standalone. The commercial layer adds organizational governance around the kernel — not artificial crippleware.
