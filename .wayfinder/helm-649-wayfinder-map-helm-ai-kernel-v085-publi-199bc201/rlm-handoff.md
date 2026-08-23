# RLM handoff — HELM AI Kernel v0.8.5 release convergence

> RLM output is not source truth.

## Scope and question

- Scope: the 2026-08-23 Kernel estate audit, HELM-649/650 and their one-hop release/runtime sources, the Kernel release repository, direct integration owners, downstream public/version repositories, and GitOps/runtime evidence.
- Question: what exact source, artifact, security, install, runtime, deployment, public-truth, and tracker gates must converge before v0.8.5 can truthfully be called a complete public Kernel release?
- Loop class: `report`.
- Safety mode: read-only mixed-context synthesis. No secrets, credential stores, raw environment files, customer payloads, production mutations, tags, package publication, or deployment effects were included.

## Budget and exclusions

- Bounded to one direct source-closure hop from HELM-649 and HELM-650.
- No recursive crawl of ordinary backlinks, old closed issue history, raw provider credentials, production kube/cloud credentials, or private customer evidence.
- Code structure was routed through the existing CodeGraph index; the sidecar did not substitute for source reads or tests.
- The prior audit handoff is reused as advisory input rather than rerunning an unbounded estate scan.

## Artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| Current-state report | `88092134434a442468352e2db088c6f78f51ea83c4600a2575d63ad87a01c2b8` |
| Local Git ledger | `2b689850ef30e2d7f70bf43334b89e1f686e4bbcabd8f1ce43b672da084916dd` |
| Remote Git ledger | `629ab99a45be1fc0f3de9654594e5813547b829790c31ceba7fbd6a9b495514b` |
| Open-PR ledger | `356a228e42d7e081e222fc48000b22dd05520b5755488a5d3f5f5eb10a58504d` |
| Linear snapshot | `60fc27040718481cd0e5ebc0610268e2f06a10adb104a62870f5bef3878aa5a7` |
| Prior RLM handoff / redacted trajectory reference | `1b1174b141230be1c9ad3236a56d8b7db4b1cd3a1e94e52cecc605dc2b3aab25` |
| Source-truth hierarchy | `6c6409f073b05e367b975c27bcd7e6cba7bfe4109cb7a15750ac78745461d9d8` |
| Repository topology | `5e6eb64f274a774c3e9e030d868915a5e718a63b51c19f978a049a38a6eed558` |

## Findings

1. Public v0.8.4 and Kernel main are different release generations; v0.8.5 needs a new exact-source candidate and cannot inherit v0.8.4 artifact evidence.
2. The release graph already exists in pieces: HELM-430, 607, 637/638/641/642, 647, and 221/230/229/513/531. The minimum correct move is to reuse and version-forward those owners.
3. The strongest product seams are the built CLI/verifiers, release/artifact verification, disposable installs and rollback, the real public OrganizationRuntime run API plus provider/effect readback, reconciled workload identity, and deployed public version/status endpoints.
4. The generic EvidencePack document is contradicted under ADR 0003. Existing source-owned profiles/reference packs may be verified, but a universal EvidencePack conformance claim would exceed source truth.
5. Package/tag publication, public-claim approval, and production promotion remain separate human-authority events even when all source work is green.

## Proposals

1. Compile HELM-649/650 into atomic release requirements, then reuse existing Linear owners and create only missing vertical slices.
2. Converge Kernel source and security first; release artifacts and downstream hashes depend on the final candidate.
3. Run HELM-637 independently in its existing integration branch and owning service repositories; join its evidence only at final reporting.
4. Prepare exact publication, claim, and production packets rather than embedding authority in the implementation branch.

## Validation still required

- Independent answer-key critic with unchanged artifact hashes.
- Current PR diff/ancestry analysis against the exact candidate.
- Repository-native tests, security scans, release rehearsal, and artifact verification.
- Real clean-machine install/rollback and real OrganizationRuntime provider/effect proof.
- Exact-head CI, merges, immutable publication readback, downstream sync, deployment readback, and final independent gauntlet.
