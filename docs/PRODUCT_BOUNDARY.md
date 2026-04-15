---
title: PRODUCT_BOUNDARY
---

# Product Boundary — OSS vs Commercial

HELM ships as two products. This document defines the boundary.

## HELM OSS — The Execution Kernel

**License:** Apache 2.0 (permanent)

Everything needed for a single team to govern AI agent tool execution:

| Component | What it does |
|-----------|-------------|
| Governed proxy | OpenAI-compatible reverse proxy with receipt emission |
| MCP interceptor | Governed MCP server (stdio + HTTP + SSE) |
| Guardian PEP | Fail-closed policy evaluation with PRG |
| Conformance runner | L1/L2/L3 conformance verification |
| Signed receipts | Ed25519 signed, causal-chained (Lamport) |
| ProofGraph DAG | Append-only evidence graph with causal ordering |
| EvidencePack export | Deterministic `.tar.gz`, offline-verifiable |
| Verify CLI | Air-gapped bundle verification |
| Policy bundles | Load, verify, compose, test policy packs |
| WASI sandbox | Gas/time/memory bounded execution |
| Approval ceremonies | Timelock + challenge/response |
| Trust registry | Event-sourced key management |
| SDKs | TypeScript, Python, Go, Rust, Java |
| CI boundary checks | Reusable GitHub Actions workflow |
| Hybrid PQ signing | Ed25519 + ML-DSA-65 dual signatures on every decision |
| W3C DID identity | Decentralized agent identifiers |
| Memory governance | Integrity verification, trust scoring, poisoning defense |
| Ensemble scanner | Quorum-based multi-engine threat detection |
| SkillFortify | Runtime tool integrity verification |
| Supply chain provenance | Signed attestations for tools, policies, models |
| Cost attribution | Per-decision cost tracking and pre-execution estimation |
| MCPTox | Rug-pull, typosquatting, supply chain detection for MCP tools |
| ZK compliance proofs | Prove compliance without revealing policy details |
| Evidence summaries | Constant-size cryptographic summaries of evidence packs |
| Continuous delegation (AIP) | Narrowing delegation with continuous monitoring |
| Reversibility engine | Effect compensation tracking and rollback verification |
| CloudEvents export | Governance decisions as CloudEvents for SIEM integration |
| SLO engine | SLO violations trigger governance actions automatically |
| Replay comparison | Side-by-side replay diff for policy drift detection |
| Federated trust | Cross-org trust roots with policy narrowing |
| OTel integration | Full OpenTelemetry traces, metrics, and spans |

**Nothing security-critical or runtime-essential is paywalled.**

## HELM Commercial — Organizational Coordination

**License:** Proprietary

Everything needed for organizations with multiple teams, compliance requirements, or fleet management:

| Component | What it does |
|-----------|-------------|
| Policy workspace UI | Author, review, and version policies visually |
| Multi-user approvals | Delegated responsibility with audit trail |
| Staged rollout | Shadow mode, canary, progressive policy deploys |
| Org-wide registry | Policy distribution across teams and services |
| Tenant management | Workspace isolation, configuration hierarchy |
| SSO / SCIM / RBAC | Enterprise identity and access management |
| Trust federation | Cross-org trust chain management |
| Long-term retention | Legal hold, export governance, compliance archives |
| Fleet visibility | Dashboards across many agents/services |
| Incident workflows | Audit dashboards, change review, escalation |
| Billing & metering | Usage tracking, quotas, administration |
| Managed control plane | Cloud/hybrid hosted runtime management |

## The Principle

> Give away the execution kernel. Sell organizational coordination around many kernels.

The open-source runtime must be irrational to replace. The commercial layer makes it operationally manageable at scale.
