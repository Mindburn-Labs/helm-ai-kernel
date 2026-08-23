# Decision map — HELM AI Kernel v0.8.5 release convergence

## Destination

Publish and verify HELM AI Kernel v0.8.5 from one exact source identity, converge its release estate and direct integration surfaces, and leave only explicitly human-controlled release/claim/production actions as exact bounded packets if they cannot be executed in-session.

## Scope

- Kernel source, CLI/TUI, release workflow, configured artifacts, images, signatures/checksums, SBOM/VEX/provenance, SDKs, package fanout, clean installs, rollback, and release evidence.
- Evidence-preserving disposition of release-relevant Kernel PRs, branches, and worktrees.
- Source-owned Homebrew, docs, website, and GitOps version propagation.
- HELM-637's separate non-production OrganizationRuntime proof through the public run API and real provider/effect readback.
- Linear reconciliation from exact source and runtime evidence.

## Resolved decisions

| Decision | Rationale | Source | Dependencies |
| --- | --- | --- | --- |
| Reuse HELM-649/650 and existing release/runtime owners | avoids a parallel backlog and preserves history | HELM-649, HELM-650 | none |
| Integrate from current Kernel main; salvage behavior, not stale branches | main already includes the v0.8.5 TUI and 43 post-v0.8.4 commits | HELM-430, HELM-647 | live PR diff/ancestry ledger |
| `VERSION` is the release-version input; built outputs and public surfaces must agree | one source contract prevents drift | HELM-650; existing build-info seam | exact candidate commit |
| Reuse existing release/drift/install/conformance machinery | smaller, auditable change; no second release framework | HELM-650 | inspect current scripts/workflows |
| Preserve HELM-647's fail-closed TUI contract | convenience cannot weaken the execution firewall | HELM-647 | focused production-seam tests |
| Rebuild with Go 1.25.13 and new immutable builder digest | closes the seven real stdlib HIGH findings in both images | HELM-607 | official digest and full pin sweep |
| Verify configured targets only | no speculative platform expansion during release convergence | HELM-650 | current release configuration |
| Bind image security and deployment evidence to digest | mutable tags are insufficient evidence | HELM-607, HELM-650, source-truth | published image digests |
| Keep Kernel publication and OrganizationRuntime proof separate | Kernel is governance, not organization runtime; integration is verification only | HELM-637, repo topology, source-truth | source-owner service heads |
| Bind OrganizationRuntime proof to the completed source-owner prerequisite seams | proposal projection, workload trust, and Evidence Signer are required members of the real live-stack path | HELM-639, HELM-643, HELM-644, HELM-645 | exact merged service heads and CI evidence |
| Treat public provider usage as an active source prerequisite, not a runner fixture | current public run readback omits durable usage and HELM-638 must consume the real source-owned shape | HELM-646, HELM-638 | merged Control Plane source/CI before provider proof |
| Use HELM-637's approved scratch target and spend boundary | bounds real provider/GitHub effects without customer or production scope | HELM-637 via HELM-640 | credentials available through approved local custody |
| Treat source, CI, publication, deployment, runtime, rollback, customer acceptance, and claims as separate states | prevents optimistic status promotion | HELM-221/230/531, source-truth | source-owned evidence per state |
| Tag/package publish, public-claim approval, and production promotion remain separate exact approvals | code-merge authority does not widen release or production authority | workspace policy, Kernel AGENTS, HELM-650 | single-use packet and live identity readback |
| Preserve branches/worktrees until reachability and unique work are proved | cleanup must not destroy user work | HELM-430 | current ledger and recovery refs |
| Generic EvidencePack conformance is not a v0.8.5 claim | ADR 0003 marks the generic contract contradicted | ADR 0003 | named profile/reference-pack verification only |
| No protected trust-contract edit is assumed | release completion cannot silently rewrite signed bytes or wire authority | source-owned contracts/reference packs, ADR 0003, Kernel AGENTS | new scoped decision if a failing seam requires one |

## Prototypes and research

- HELM-647's merged production CLI/TUI tests are prior implementation evidence, not release proof.
- The 2026-08-23 current-state audit and RLM handoff route the work; their findings require fresh exact-head verification before disposition or claims.
- CodeGraph identifies existing public seams: CLI `Run`/`Dispatch`, build-information display, conformance engine/gates, and receipt verifiers. Source and tests remain authoritative.

## Contradictions and assumptions

1. ADR 0003 says the generic EvidencePack document/schema is contradicted. Resolution: do not cite it as normative; verify only the named shipped profile/reference pack and state the limitation.
2. Workspace guidance names protocol lint/API-diff expectations, while ADR 0003 records gaps in actual protocol enforcement. Resolution: avoid a public protocol change in this release unless a separate ticket establishes the required source-owned gates and review.
3. Historic Linear issue bodies contain stale estate and v0.8.4 states. Resolution: current Git, GitHub, registry, GitOps, and runtime readback override those snapshots; retain historical comments as history.
4. The exact v0.8.5 candidate SHA is not yet fixed. Assumption: it becomes the merged result of only answer-key-required changes and is then immutable for release evidence.
5. Real provider credentials are reported as locally available but have not been read. Assumption: execution obtains them through the approved local boundary; absence becomes an explicit runtime blocker, never a fixture substitution.

## Known authority preconditions

- One single-use approval is required before creating/pushing `v0.8.5` or invoking a package-publishing workflow.
- Public release copy requires a separate public-claims approval after public readback.
- Production promotion requires a separate environment-specific approval after staging evidence and rollback readiness.
- Any identity, SHA, workflow, artifact, environment, or expected-readback drift aborts the approved action.

## Unresolved implementation facts

- Which open PR deltas remain valuable against the exact candidate.
- Which release scripts/gates need the smallest correction after deliberate-red rehearsal.
- Which downstream version/pin changes can be prepared before immutable asset hashes exist.
- Whether the current local HELM-638/646 work passes review and source-owner gates; HELM-646 is explicitly required before usage-backed provider proof.

These are discoverable implementation facts, not product decisions; their tickets must preserve the fixed acceptance contract.

## Out of scope

- New organization-runtime ownership in Kernel or `integration-helm`.
- New package ecosystems, release frameworks, evidence formats, connectors, or infrastructure without a demonstrated release requirement.
- HELM-648's broader MCP/fleet/detector scope unless a specific mandatory v0.8.5 seam fails because of it.
- Broad Product Release R0–R4/E0–E3 ratification, customer acceptance, GA, or production claims.
- Destructive or history-rewriting cleanup.
