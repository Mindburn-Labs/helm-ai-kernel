---
title: ROADMAP
---

# HELM OSS Roadmap

Each item is tied to a conformance level or adoption milestone. No dates — shipped when ready.

## Active

| Item | Target | Status |
|------|--------|--------|
| Conformance L1 + L2 | OSS v0.3 | ✅ Shipped |
| MCP interceptor / proxy mode | OSS v0.3 | ✅ Shipped |
| EvidencePack export + offline verify | OSS v0.3 | ✅ Shipped |
| Multi-language SDKs (TS, Python, Go, Rust, Java) | OSS v0.3 | ✅ Shipped |
| Proof Condensation (Merkle checkpoints) | OSS v0.3 | ✅ Shipped |
| Policy Bundles (load, verify, compose) | OSS v0.3 | ✅ Shipped |

## Shipped in v0.4 (MIN-82 Phase 1-2 + Q1)

| Item | Status |
|------|--------|
| Behavioral trust scoring (0-1000, decay, ProofGraph receipting) | ✅ Shipped |
| Privilege tiers (4-tier execution rings with trust downgrade) | ✅ Shipped |
| Competitive benchmarks (137x faster than Microsoft AGT) | ✅ Shipped |
| ML-DSA-65 post-quantum signing (real, via cloudflare/circl) | ✅ Shipped |
| IATP mutual auth + peer vouching + trust propagation | ✅ Shipped |
| Per-agent kill switch (receipted, ProofGraph-backed) | ✅ Shipped |
| Saga orchestration (compensating transactions) | ✅ Shipped |
| AI-BOM (model provenance, dataset lineage, SPDX deps) | ✅ Shipped |
| Prompt defense hardening (5→12+ threat vectors) | ✅ Shipped |
| Progressive delivery (shadow/canary/blue-green + SLO gates) | ✅ Shipped |
| WASM policy runtime (wazero, fuel-metered, deterministic) | ✅ Shipped |
| TLA+ formal verification (6 specs: Guardian, ProofGraph, Delegation, Tenant, CSNF, Trust) | ✅ Shipped |
| L3 federation conformance (cross-org trust, policy inheritance) | ✅ Shipped |
| W3C Verifiable Credentials (agent capability certificates) | ✅ Shipped |
| Real-time compliance scoring (7 frameworks, live dashboard) | ✅ Shipped |
| Kubernetes Helm chart (14 templates, production-ready) | ✅ Shipped |
| LangChain.js + CrewAI-JS + LlamaIndex-TS adapters | ✅ Shipped |
| Streaming governance examples (Python + TypeScript) | ✅ Shipped |
| Fuzz testing suite (13 targets, up from 5) | ✅ Shipped |
| 5 enterprise compliance packs (SOC2, HIPAA, PCI-DSS, EU AI Act, ISO 42001) | ✅ Shipped |
| SRE documentation overhaul (5 operational guides) | ✅ Shipped |

## Shipped in v0.5 (Q2)

| Item | Status |
|------|--------|
| Zero-knowledge governance proofs (commitment-based Sigma protocol) | ✅ Shipped |
| Hardware TEE attestation (TPM 2.0, Intel TDX, AMD SEV-SNP interface) | ✅ Shipped |
| Distributed ProofGraph (G-Set CRDT, gossip sync) | ✅ Shipped |
| Evidence pack streaming (StreamBuilder + StreamReader) | ✅ Shipped |
| Schema registry documentation | ✅ Shipped |

## Shipped in v0.6 (Q3)

| Item | Status |
|------|--------|
| Decentralized proof markets (SPN/Boundless integration) | ✅ Shipped |
| Agent certification framework (HELM Verified Agent badges) | ✅ Shipped |
| Governance-as-a-Service blueprint (multi-tenant SaaS) | ✅ Shipped |
| VS Code extension (CEL highlighting, ProofGraph viz, compliance widget) | ✅ Shipped |

## Shipped in v1.0 (Q4)

| Item | Status |
|------|--------|
| Privacy-preserving governance (Shamir Secret Sharing + differential privacy) | ✅ Shipped |
| Constitutional AI integration (principle parsing, policy alignment) | ✅ Shipped |
| Byzantine-tolerant ProofGraph consensus (HotStuff-inspired BFT) | ✅ Shipped |
| Edge Guardian µ-HELM (minimal runtime for IoT/edge) | ✅ Shipped |

## Production Hardening (Post v1.0)

| Item | Status |
|------|--------|
| ZK proof soundness fix (ResponseCommitment verification) | ✅ Fixed |
| GF(256) arithmetic verification (exhaustive primitive element test) | ✅ Fixed |
| BFT consensus phase validation | ✅ Fixed |
| ML-DSA-65 MarshalBinary error handling | ✅ Fixed |
| Compliance scorer unique violation counting | ✅ Fixed |
| Guardian compliance checker wiring (was dead code) | ✅ Fixed |
| Guardian integration test (11 tests, full pipeline) | ✅ Added |
| 8 medium-severity fixes (edge, CRDT, saga, IATP, TEE, delivery, vouching, scorer) | ✅ Fixed |

## Future

| Item | Target |
|------|--------|
| Homebrew formula publication | v1.0.1 |
| Real zkVM integration (RISC Zero/SP1) for stronger ZK proofs | v1.1 |
| Production TPM/SGX attestation (beyond simulated) | v1.1 |
| WebAssembly SDK for browser deployment | v1.2 |
| Kubernetes operator controller (beyond CRDs) | v1.2 |

## Non-Goals for OSS

These belong in HELM Commercial and will not appear in this roadmap:

- Surface Design Studio
- Policy staging / shadow enforcement
- Certified Connector Program
- Enterprise evidence retention / legal hold
- Managed federation
