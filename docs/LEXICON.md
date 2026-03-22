# HELM Lexicon

> Canonical terminology for the HELM open standard.

## Core Product Terms

| Term | Definition |
| :--- | :--- |
| **Execution Authority** | The layer that determines whether a proposed side effect may execute under policy, scope, and proof requirements. |
| **HELM OSS** | The open execution kernel — fail-closed enforcement, ProofGraph, EvidencePacks, policy surfaces. |
| **HELM Platform** | The commercial control plane around the kernel — Mission Control, workspaces, pack distribution, enterprise governance. |
| **Mission Control** | The authoritative operator surface for managing governed execution across an organization. |

## Organizational Terms

| Term | Definition |
| :--- | :--- |
| **OrgDNA** | The evolving organizational model: structure, authority, and constraints as code. |
| **OrgGenome** | The compiled specification of an organization: role lattice, authority graph, policy, budgets, jurisdictions. |
| **OrgPhenotype** | The runtime artifact produced by compiling an OrgGenome. |
| **Principal** | A human, agent, or system actor capable of holding authority. |
| **OrgUnit** | A recursive organizational hierarchy node (team, division, squad, pod). |
| **Role** | A set of responsibilities and permissions assignable to principals. |

## Governance Terms

| Term | Definition |
| :--- | :--- |
| **Policy Enforcement Point (PEP)** | The deterministic boundary that allows or denies side effects. |
| **Constraint and Proof Interface (CPI)** | The validator that checks plans and execution context before the PEP decides. |
| **Verified Genesis Loop (VGL)** | The protocol for compiling and activating OrgGenome with deterministic reflection and explicit approval. |
| **Verified Policy Loop (VPL)** | The protocol for applying policy changes with deterministic evaluation and receipted approval. |
| **KernelVerdict** | The signed decision output of the PEP (PASS/FAIL/DEFER). |
| **EffectPermit** | Single-use, scoped, signed authorization token binding a verdict to a specific connector action. |
| **Authority Evaluation** | The Stage 2 pipeline determining scope, delegation, and approval requirements. |

## Evidence Terms

| Term | Definition |
| :--- | :--- |
| **ProofGraph** | Immutable causal graph of intents, decisions, receipts, and effects. |
| **EvidencePack** | Deterministic evidence bundle for replay and verification. |
| **Receipt** | Cryptographic proof that a governed allow or deny decision happened. |
| **InterventionReceipt** | Cryptographic proof that a human made a governance decision. |
| **DenialTrace** | Post-hoc forensic analysis of why an execution was denied. |

## Truth & Registry Terms

| Term | Definition |
| :--- | :--- |
| **TruthObject** | An immutable versioned governance artifact (policy, schema, regulation). |
| **Truth Registry** | The versioned store of all governance truth — what rules were active when. |
| **PolicyEpoch** | A monotonically increasing identifier for a specific policy snapshot. |
| **Lineage** | The provenance chain linking truth objects through DERIVED_FROM, SUPERSEDES, AMENDS relations. |

## Effect Terms

| Term | Definition |
| :--- | :--- |
| **Effect** | A typed side effect produced by agent execution (READ, WRITE, DELETE, EXECUTE, NETWORK, FINANCE). |
| **Connector** | A bounded execution adapter that performs exactly the action permitted by an EffectPermit. |
| **Effects Gateway** | The single execution chokepoint — ALL external effects transit through this gateway. |
| **NonceStore** | Anti-replay protection ensuring each EffectPermit is consumed exactly once. |

## Strategic Terms

| Term | Definition |
| :--- | :--- |
| **Reference System** | A real system used to prove HELM under demanding operational conditions. |
| **Organizational Execution Substrate** | The long-horizon category HELM defines: infrastructure where humans, agents, software, policy, and physical systems become co-executors. |
| **Pack** | A distributable, versioned capability bundle with an ABI surface. |
| **Surface Compiler** | The compiler that transforms Packs into provider-specific deployable bundles. |
