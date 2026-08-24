# Answer key — HELM AI Kernel v0.8.5 exact-source public release

All resolved requirements begin `UNVERIFIED`. Compilation is not execution.

> quantum_posture: this Wayfinder answer key is a planning/evidence description,
> not a cryptographic control or post-quantum assurance.

## AK-001 — Exact candidate source

- **Category:** source identity
- **Criticality:** Critical
- **Requirement:** One clean Kernel commit is named as the v0.8.5 candidate, contains `VERSION=0.8.5`, is reachable from the reviewed release branch, and has no uncommitted release input.
- **Authoritative source:** HELM-649; HELM-650 user stories 1, 11; HELM-221.
- **Rationale:** every downstream artifact and claim needs one immutable source identity.
- **Preconditions:** release-relevant PR disposition is complete enough to freeze the candidate.
- **Verification seam:** Git commit/tree plus repository version contract.
- **Verification method:** inspect exact commit, tree status, ancestry, and parsed `VERSION`; rerun after every candidate change.
- **Required evidence:** full SHA, tree SHA, branch/ref, `git status --porcelain`, version readback.
- **Pass condition:** exactly one clean candidate SHA and tree report 0.8.5.
- **Fail condition:** multiple candidate SHAs, dirty inputs, non-ancestor source, or any version other than 0.8.5.
- **Dependencies:** AK-008, AK-009.
- **Status:** UNVERIFIED

## AK-002 — Built CLI identity

- **Category:** executable product
- **Criticality:** Critical
- **Requirement:** A clean build from AK-001 reports v0.8.5 and the candidate commit through the public headless CLI.
- **Authoritative source:** HELM-650 user stories 1, 11; Kernel build-information seam.
- **Rationale:** source text is not the identity users execute.
- **Preconditions:** AK-001.
- **Verification seam:** released `helm-ai-kernel version`/front-door output.
- **Verification method:** build with the source-owned release flags and compare parsed output to independent literal version/SHA inputs.
- **Required evidence:** build command, binary digest, stdout/stderr, exit code, expected version/SHA.
- **Pass condition:** exit 0; output names v0.8.5 and the exact candidate commit; binary digest is recorded.
- **Fail condition:** fallback/dev/stale version, unknown/wrong commit, nonzero exit, or unbound binary.
- **Dependencies:** AK-001.
- **Status:** UNVERIFIED

## AK-003 — TUI identity parity

- **Category:** executable product
- **Criticality:** High
- **Requirement:** The interactive TUI displays the same v0.8.5 version and candidate commit as AK-002.
- **Authoritative source:** HELM-647; HELM-650 user story 2.
- **Rationale:** interactive chrome must not create a second product identity.
- **Preconditions:** AK-002.
- **Verification seam:** production TUI header rendering with real build information.
- **Verification method:** exercise the existing TUI production seam and compare header values to AK-002.
- **Required evidence:** focused test output or deterministic captured rendering plus binary identity.
- **Pass condition:** TUI version and commit equal AK-002.
- **Fail condition:** stale, hard-coded, missing, or divergent identity.
- **Dependencies:** AK-002.
- **Status:** UNVERIFIED

## AK-004 — Fail-closed TUI security contract

- **Category:** security behavior
- **Criticality:** Critical
- **Requirement:** Listener verbs are refused; destructive commands require an exact full-invocation confirmation; decisions require typed APPROVE/DENY; and secrets are redacted.
- **Authoritative source:** HELM-647 user stories and testing decisions; HELM-650 user stories 3–6.
- **Rationale:** the operator interface cannot become a bypass or credential sink.
- **Preconditions:** AK-001.
- **Verification seam:** production `Run`/`Dispatch` host plus TUI key/mouse/update/view seams.
- **Verification method:** run focused production/adversarial tests including listener, mutation, bad token, click/digit/Enter, JWT/token/PEM redaction, and negative paths.
- **Required evidence:** exact test commands, cases, exit status, and assertions tied to real dispatch/decision seams.
- **Pass condition:** every prohibited path refuses without side effect; only exact ceremony tokens transition; sensitive material is absent from output.
- **Fail condition:** any bind/mutation/decision occurs without its required boundary or any tested secret survives redaction.
- **Dependencies:** AK-001.
- **Status:** UNVERIFIED

## AK-005 — Headless and bounded automation contract

- **Category:** compatibility
- **Criticality:** Critical
- **Requirement:** Pipes, JSON/format output, `HELM_NO_TUI`, and `TERM=dumb` remain non-interactive, and every catalog default is bounded/inspect-first.
- **Authoritative source:** HELM-647; HELM-650 user stories 7–8.
- **Rationale:** 0.8.5 must not hang CI or trigger implicit work.
- **Preconditions:** AK-001.
- **Verification seam:** built CLI with TTY/non-TTY environment matrix and production catalog loop.
- **Verification method:** exercise all configured modes and every catalog default with bounded time and isolated temporary cwd.
- **Required evidence:** matrix results, exit codes, stdout format checks, timeout/side-effect assertions.
- **Pass condition:** no headless mode enters TUI; all defaults terminate within the bound and create no unauthorized bind/write/mutation.
- **Fail condition:** interaction prompt, hang, implicit scan/listener/write, or invalid structured output.
- **Dependencies:** AK-001.
- **Status:** UNVERIFIED

## AK-006 — Public contract and signed-artifact compatibility

- **Category:** contracts
- **Criticality:** Critical
- **Requirement:** v0.8.5 preserves existing public wire and signed-artifact behavior, or any intentional change has its own reviewed versioned contract, reference pack, compatibility evidence, and source-owner decision.
- **Authoritative source:** HELM-650 user story 9 and implementation decisions; source-owned public contracts/reference packs; ADR 0003; Kernel AGENTS.
- **Rationale:** a minor release cannot silently widen signed bytes or break clients.
- **Preconditions:** final candidate diff.
- **Verification seam:** repository contract/reference-pack/boundary/codegen compatibility gates plus exact diff inspection.
- **Verification method:** run all source-owned contract gates and inspect changes to protected/normative sources; compare against v0.8.4.
- **Required evidence:** changed-path inventory, gate output, compatibility report, specialist verdict if protected paths changed.
- **Pass condition:** no unreviewed breaking/widening change and every applicable source-owned gate passes.
- **Fail condition:** silent signed-field change, stale generated binding, broken public API, missing reference vector, or unsupported protected-path edit.
- **Dependencies:** AK-001.
- **Status:** UNVERIFIED

## AK-007 — Offline receipt and named-profile verification

- **Category:** evidence integrity
- **Criticality:** Critical
- **Requirement:** Released receipt.v5 and each named shipped EvidencePack/profile/reference-pack claimed by v0.8.5 verify offline against declared trust material; no generic EvidencePack conformance claim is made.
- **Authoritative source:** HELM-650 user story 10; source-owned receipt.v5 and named profile/reference-pack manifests; ADR 0003; HELM-221 preserved work.
- **Rationale:** portable verification is the product claim; the contradicted generic document cannot be used as authority.
- **Preconditions:** AK-006.
- **Verification seam:** independent reference-pack verifier and public CLI verifier.
- **Verification method:** run Go parity and independent verifier paths, positive and negative vectors, and release-binary offline verification.
- **Required evidence:** pack/profile names, hashes, commands, positive output, negative mutation failures, claim-language inspection.
- **Pass condition:** every named profile verifies and its negative vectors fail; public text does not claim generic EvidencePack conformance.
- **Fail condition:** fixture accepted without trust, negative vector passes, verifier needs a live Mindburn service, or contradicted generic spec is cited as normative.
- **Dependencies:** AK-006.
- **Status:** UNVERIFIED

## AK-008 — Open PR disposition

- **Category:** source estate
- **Criticality:** Critical
- **Requirement:** Every open release-relevant Kernel PR is compared to current main and is merged on green exact-head checks, superseded with preserved behavior, or closed with precise evidence and a successor pointer.
- **Authoritative source:** HELM-430; HELM-650 user stories 12, 14.
- **Rationale:** blindly merging conflicts is unsafe; silently abandoning valid behavior is incomplete.
- **Preconditions:** fresh GitHub PR inventory.
- **Verification seam:** GitHub PR metadata/diff/checks plus candidate ancestry.
- **Verification method:** record base/head/tree, unique patch, checks/reviews, overlap with main, decision, and final state for each PR.
- **Required evidence:** machine-readable ledger and PR URLs/comments/merge SHAs.
- **Pass condition:** no release-relevant PR lacks a defensible disposition and no required unique behavior is absent from candidate main.
- **Fail condition:** open/unreviewed delta, conflict closed without behavior analysis, failed required checks merged, or missing replacement pointer.
- **Dependencies:** none.
- **Status:** UNVERIFIED

## AK-009 — Branch/worktree preservation ledger

- **Category:** source estate
- **Criticality:** Critical
- **Requirement:** Every non-main Kernel branch/worktree is classified for ancestry, unique commits/diff, dirty/untracked work, remote reachability, owner, and disposition before cleanup.
- **Authoritative source:** HELM-430; HELM-650 user stories 13, 50.
- **Rationale:** estate cleanup must not destroy user-owned or sole-copy work.
- **Preconditions:** fresh local/remote/worktree inventory.
- **Verification seam:** Git object graph, worktree porcelain status, remote refs.
- **Verification method:** produce a deterministic ledger and recovery refs for any unique or dirty state.
- **Required evidence:** branch/worktree ledger, commit reachability, dirty paths, recovery ref/push where needed.
- **Pass condition:** every target has complete evidence and deletion candidates have no unpreserved unique/dirty work.
- **Fail condition:** unknown ownership, unreachable unique commit, dirty work without preservation, or cleanup based only on age/name.
- **Dependencies:** none.
- **Status:** UNVERIFIED

## AK-010 — Go 1.25.13 source/toolchain convergence

- **Category:** build security
- **Criticality:** Critical
- **Requirement:** Every active Kernel build, module, workflow, and builder pin owned by HELM-607 uses the supported Go 1.25.13 contract and the correct immutable builder digest.
- **Authoritative source:** HELM-607.
- **Rationale:** v0.8.4's seven HIGH findings originate in Go 1.25.12 stdlib.
- **Preconditions:** official toolchain/image availability.
- **Verification seam:** complete pin inventory and clean build toolchain readback.
- **Verification method:** search active pin sites, inspect builder manifest digest, build/test with the declared toolchain, and prove no stale active 1.25.12 pin.
- **Required evidence:** before/after pin list, official digest readback, `go version`, build/test outputs.
- **Pass condition:** all active required sites are 1.25.13 with matching digest and clean build/tests.
- **Fail condition:** stale active 1.25.12 pin, reused old digest, unsupported toolchain, or build/test regression.
- **Dependencies:** none.
- **Status:** UNVERIFIED

## AK-011 — Shipped-image vulnerability closure

- **Category:** supply-chain security
- **Criticality:** Critical
- **Requirement:** Both v0.8.5 Kernel images are scanned by immutable digest and contain zero unwaived Critical/High findings, including none of HELM-607's seven CVEs.
- **Authoritative source:** HELM-607; HELM-650 user stories 15–17.
- **Rationale:** source pin changes are not proof of shipped bytes.
- **Preconditions:** AK-010 and candidate images built.
- **Verification seam:** image digests and independent vulnerability scanner/Artifact Hub readback.
- **Verification method:** scan full and slim digests with current databases; reconcile every Critical/High row to source-owned evidence.
- **Required evidence:** digests, scanner versions/database timestamps, reports, Artifact Hub readback when published.
- **Pass condition:** zero unwaived Critical/High rows on both digests and none of the seven named CVEs.
- **Fail condition:** any unwaived Critical/High, tag-only scan, stale database without disclosure, or digest mismatch.
- **Dependencies:** AK-010, AK-014.
- **Status:** UNVERIFIED

## AK-012 — Candidate security and quality gates

- **Category:** validation
- **Criticality:** Critical
- **Requirement:** The exact candidate passes applicable dependency, vulnerability, license, secret, policy, lint, full test, race, platform/docs-truth, conformance, crucible, and release-quality gates.
- **Authoritative source:** HELM-649 binary acceptance; HELM-650 user story 18 and testing decisions; Kernel AGENTS.
- **Rationale:** a narrow green suite cannot qualify the product.
- **Preconditions:** AK-001.
- **Verification seam:** repository-native Makefile/CI profiles on exact head.
- **Verification method:** enumerate gates from current source, run locally where deterministic, then verify required CI on the same head.
- **Required evidence:** command matrix, exit codes, logs/artifacts, CI run IDs/attempts/head SHA, skipped-gate reasons.
- **Pass condition:** every applicable required gate passes on the candidate; no required gate is silently disabled or skipped.
- **Fail condition:** failure, timeout without resolution, gate silence, different head, suppressed error, or unexplained skip.
- **Dependencies:** AK-001, AK-004–AK-007, AK-010.
- **Status:** UNVERIFIED

## AK-013 — Non-publishing release rehearsal and mismatch denial

- **Category:** release workflow
- **Criticality:** Critical
- **Requirement:** The source-owned release graph can be rehearsed without publishing and fails closed on deliberate version/tag/source mismatches.
- **Authoritative source:** HELM-650 user stories 22–23.
- **Rationale:** the public run must not be the first full pipeline execution.
- **Preconditions:** AK-001, AK-012.
- **Verification seam:** release preflight/rehearsal workflow or local equivalent using the same scripts/configuration.
- **Verification method:** run the matching candidate case, then three isolated cases that change only the declared version, only the tag, and only the source commit/tree.
- **Required evidence:** commands/workflow runs, literal version/tag/source inputs for all four cases, outputs, exit codes, denial stage, and proof no public tag/release/package was created.
- **Pass condition:** the matching case reaches artifact verification; each isolated version, tag, and source mismatch exits nonzero before publication.
- **Fail condition:** any one of the three mismatches passes or is not exercised, rehearsal skips material release steps, or any public mutation occurs.
- **Dependencies:** AK-001, AK-012.
- **Status:** UNVERIFIED

## AK-014 — Complete configured artifact build

- **Category:** release artifacts
- **Criticality:** Critical
- **Requirement:** Every target declared by the current release configuration produces the expected archive/package/image/chart with v0.8.5 and candidate identity.
- **Authoritative source:** HELM-650 user stories 19, 21, 26 and implementation decisions.
- **Rationale:** partial platform success is not a complete configured release.
- **Preconditions:** AK-013.
- **Verification seam:** release configuration output set and artifact contents.
- **Verification method:** enumerate configured targets independently, build them, unpack/inspect each, and execute where the host permits.
- **Required evidence:** expected-versus-produced manifest, asset hashes/sizes, embedded identity, build logs.
- **Pass condition:** produced set exactly covers configured targets and every item carries the correct identity.
- **Fail condition:** missing/extra unexplained target, corrupt archive, wrong executable, stale version, or unbound image/chart.
- **Dependencies:** AK-013.
- **Status:** UNVERIFIED

## AK-015 — Checksums

- **Category:** release artifacts
- **Criticality:** Critical
- **Requirement:** Published checksum manifests cover and verify every shipped archive/binary asset without omissions or duplicates.
- **Authoritative source:** HELM-650 user story 19.
- **Rationale:** consumers need transport-integrity verification.
- **Preconditions:** AK-014.
- **Verification seam:** independent checksum tool over final asset bytes.
- **Verification method:** parse manifest, compare exact asset set, recompute every digest, and test one isolated mutation fails.
- **Required evidence:** manifest, recomputation output, asset inventory, negative mutation result.
- **Pass condition:** exact coverage and all recomputed digests match; mutation fails.
- **Fail condition:** missing/duplicate entry, mismatch, unsupported parsing, or mutation accepted.
- **Dependencies:** AK-014.
- **Status:** UNVERIFIED

## AK-016 — Signature and provenance bindings

- **Category:** supply chain
- **Criticality:** Critical
- **Requirement:** Signatures/attestations verify and bind every claimed release subject to v0.8.5, the candidate source, and the authorized workflow identity.
- **Authoritative source:** HELM-650 user story 20; source-truth production evidence ladder.
- **Rationale:** presence of a signature file does not prove the right subject or builder.
- **Preconditions:** AK-014.
- **Verification seam:** independent signature/provenance verifier against final subjects.
- **Verification method:** verify cryptography and inspect subject digests, source URI/SHA, workflow identity, run ID/attempt, and issuer.
- **Required evidence:** verification output, subject mapping, attestation identities, immutable workflow/run refs.
- **Pass condition:** every claimed subject verifies and all bindings match the candidate and authorized workflow.
- **Fail condition:** invalid/missing signature, wrong subject/SHA/workflow, mutable-only reference, or unverifiable issuer.
- **Dependencies:** AK-014.
- **Status:** UNVERIFIED

## AK-017 — SBOM and VEX/provenance consistency

- **Category:** supply chain
- **Criticality:** Critical
- **Requirement:** Required SBOM and VEX/provenance artifacts are present, parseable, bound to the shipped subjects, and consistent with scanner results and allowed dispositions.
- **Authoritative source:** HELM-650 user story 21; HELM-607; source-truth.
- **Rationale:** unattached or contradictory metadata is not release evidence.
- **Preconditions:** AK-011, AK-014.
- **Verification seam:** SBOM/VEX/provenance parsers plus subject-digest comparison.
- **Verification method:** validate formats, compare subject hashes/components, reconcile vulnerability dispositions, and reject unknown/contradictory entries.
- **Required evidence:** parsed summaries, validation output, subject map, disposition references.
- **Pass condition:** all required artifacts validate and agree with shipped bytes/security evidence.
- **Fail condition:** missing/invalid document, wrong subject, unexplained discrepancy, or unsupported waiver.
- **Dependencies:** AK-011, AK-014.
- **Status:** UNVERIFIED

## AK-018 — Exact public publication and registry fanout

- **Category:** publication
- **Criticality:** Critical
- **Requirement:** After exact single-use approval, the source-owned release workflow publishes v0.8.5 once, and GitHub plus every configured registry resolves to the same version/source/artifact identity.
- **Authoritative source:** HELM-221/230/531; HELM-650 user story 48 and authority boundary.
- **Rationale:** a tag or one registry alone is not a complete public release.
- **Preconditions:** AK-001–AK-017 and exact release approval packet.
- **Verification seam:** Git tag/release, workflow run, registry APIs, and source-owned drift checker.
- **Verification method:** verify actor/context and candidate immediately before action; invoke only approved workflow/action; poll all configured channels and rerun drift checks.
- **Required evidence:** approval reference, tag object/peeled SHA, workflow run/attempt, release asset IDs, registry version/subject readbacks.
- **Pass condition:** every configured public channel resolves to v0.8.5 bound to AK-001/014 and the workflow is green.
- **Fail condition:** partial publication, wrong SHA/assets, disabled/cancelled/failing workflow, stale channel, unexpected actor/context, or drift.
- **Dependencies:** AK-001–AK-017, AK-037.
- **Status:** UNVERIFIED

## AK-019 — Homebrew formula and clean formula identity

- **Category:** distribution
- **Criticality:** Critical
- **Requirement:** The Homebrew formula resolves to the public v0.8.5 assets with exact version/hashes and installs the AK-002 binary.
- **Authoritative source:** HELM-229/513/531; HELM-650 user stories 24, 28.
- **Rationale:** formula text can be green while pointing to stale or nonexistent bytes.
- **Preconditions:** AK-018 immutable assets.
- **Verification seam:** Homebrew formula metadata, download hashes, and installed executable.
- **Verification method:** update from public asset hashes through the owning repo, pass formula tests/audit, install in a clean prefix, and compare binary digest/identity.
- **Required evidence:** formula commit/PR/CI/merge, public formula readback, install log, binary digest/version.
- **Pass condition:** formula version/URLs/hashes match public v0.8.5 and clean install yields AK-002 identity.
- **Fail condition:** stale coordinate, hash mismatch, source checkout leakage, install failure, or wrong binary.
- **Dependencies:** AK-002, AK-018.
- **Status:** UNVERIFIED

## AK-020 — SDK and MCP coordinate synchronization

- **Category:** distribution contracts
- **Criticality:** High
- **Requirement:** Every configured SDK/MCP coordinate either publishes the compatible v0.8.5 generation bound to current contracts or exposes a documented independent version boundary with no stale install claim.
- **Authoritative source:** HELM-650 user story 29; repo topology SDK ownership; HELM-229/531.
- **Rationale:** consumers must not infer compatibility from inconsistent versions.
- **Preconditions:** AK-006, AK-018.
- **Verification seam:** source-owned generated SDK checks, registry APIs, Go module tags/proxy, and docs drift checks.
- **Verification method:** enumerate configured coordinates, run generation/drift/compatibility gates, then verify public registry identities.
- **Required evidence:** coordinate manifest, codegen/compatibility output, tag/package IDs, registry readback.
- **Pass condition:** all configured coordinates are synchronized or explicitly independent without a false v0.8.5 claim.
- **Fail condition:** stale generated code, missing required tag/package, incompatible client, or ambiguous version wording.
- **Dependencies:** AK-006, AK-018.
- **Status:** UNVERIFIED

## AK-021 — Clean macOS/Homebrew journey

- **Category:** installation
- **Criticality:** Critical
- **Requirement:** A disposable macOS/Homebrew environment installs v0.8.5 with no developer checkout and runs real inspect, protected evaluation, receipt readback, allowed dispatch, denied/unresolved no-dispatch, revocation, and rollback-handoff behavior required by HELM-513.
- **Authoritative source:** HELM-513; HELM-650 user story 24.
- **Rationale:** package availability is not an operational product journey.
- **Preconditions:** AK-019.
- **Verification seam:** published CLI in a clean environment plus bounded external/readback seam.
- **Verification method:** execute HELM-513's journey with isolated config/state and record each decision/effect/readback.
- **Required evidence:** environment identity, install source, binary digest, commands/exits, receipts, allowed/denied effect readbacks, revocation evidence.
- **Pass condition:** all required steps behave as specified with no local build/path contamination.
- **Fail condition:** missing step, fixture-only effect, denied/unresolved dispatch, stale binary, or developer checkout dependency.
- **Dependencies:** AK-019.
- **Status:** UNVERIFIED

## AK-022 — Clean Linux/direct and configured-target journey

- **Category:** installation
- **Criticality:** Critical
- **Requirement:** A disposable Linux/direct-download environment verifies checksums, installs the matching configured artifact, and executes real version and offline verification behavior.
- **Authoritative source:** HELM-650 user stories 25–26.
- **Rationale:** development-host success does not qualify released archives.
- **Preconditions:** AK-014, AK-015, AK-018.
- **Verification seam:** downloaded public archive in clean container/VM of a configured architecture.
- **Verification method:** download, verify checksum, unpack, inspect digest/identity, run version and offline verifier; repeat for each locally executable configured target and inspect the remainder.
- **Required evidence:** environment/architecture, URLs, hashes, commands, exits, outputs.
- **Pass condition:** required clean target(s) execute correctly and every configured artifact passes structural/identity inspection.
- **Fail condition:** checksum/install/execute failure, wrong architecture/content/version, or local workspace leakage.
- **Dependencies:** AK-014, AK-015, AK-018.
- **Status:** UNVERIFIED

## AK-023 — Rollback to v0.8.4 and recovery

- **Category:** recovery
- **Criticality:** Critical
- **Requirement:** The public install path can revert from v0.8.5 to the known-good v0.8.4, execute verified behavior, and return to v0.8.5 without state loss or ambiguous instructions.
- **Authoritative source:** HELM-230/513; HELM-650 user story 27.
- **Rationale:** rollback must be rehearsed before an incident.
- **Preconditions:** AK-018, AK-021 or AK-022.
- **Verification seam:** clean install/package lifecycle and version/receipt verification.
- **Verification method:** perform exact downgrade/rollback, verify v0.8.4 identity and bounded behavior, then reinstall v0.8.5 and verify identity.
- **Required evidence:** commands, package/binary hashes, state backup/restore notes, outputs, failure/abort conditions.
- **Pass condition:** both transitions succeed with exact identities and documented recovery boundary.
- **Fail condition:** no supported downgrade, data/config loss, wrong version, or untested prose-only procedure.
- **Dependencies:** AK-018, AK-021 or AK-022.
- **Status:** UNVERIFIED

## AK-024 — Public docs/version/status truth

- **Category:** public truth
- **Criticality:** Critical
- **Requirement:** Deployed public install, SDK, examples, version-status, and release-status surfaces agree on verified v0.8.5 coordinates/source and carry truthful availability/claim boundaries.
- **Authoritative source:** HELM-229/531; HELM-650 user stories 30–31.
- **Rationale:** merged docs are not the public product users read.
- **Preconditions:** AK-018–AK-020; public-claims approval for changed claim copy.
- **Verification seam:** owning repo drift gates plus deployed HTTP endpoints.
- **Verification method:** apply source-owned updates, pass native tests/CI, deploy through approved path, and fetch every route/manifest listed by the drift checker.
- **Required evidence:** repo SHAs/PRs/CI/deploy runs, URL/status/body hashes, source-version manifest.
- **Pass condition:** all required public endpoints return expected 0.8.5 data and no claim exceeds evidence.
- **Fail condition:** stale/404/mismatched route, wrong source/run, ambiguous status, or unsupported capability/GA claim.
- **Dependencies:** AK-018–AK-020, AK-034, AK-037.
- **Status:** UNVERIFIED

## AK-025 — Immutable GitOps pin

- **Category:** deployment intent
- **Criticality:** Critical
- **Requirement:** Each in-scope non-production consumer intended for v0.8.5 pins the exact released image digest/chart/source identity through its owning GitOps repository.
- **Authoritative source:** HELM-230; HELM-650 user story 32; source-truth.
- **Rationale:** a mutable tag or merged manifest is not runtime identity.
- **Preconditions:** AK-011, AK-018.
- **Verification seam:** GitOps desired-state manifests and PR/merge identity.
- **Verification method:** compare published digest to manifest, run native validation, merge on required green checks through the normal non-production path.
- **Required evidence:** desired-state diff, exact digest/version, PR/checks/merge SHA.
- **Pass condition:** every in-scope desired state pins the released immutable identity and validation passes.
- **Fail condition:** mutable-only tag, wrong digest/chart, unvalidated manifest, or unauthorized production target.
- **Dependencies:** AK-011, AK-018.
- **Status:** UNVERIFIED

## AK-026 — Reconciled non-production workload readback

- **Category:** deployment evidence
- **Criticality:** Critical
- **Requirement:** The in-scope QA/staging reconciler and workload report the AK-025 source/digest, become ready, pass a real Kernel smoke, and have an exercised rollback/readback record; production remains separate.
- **Authoritative source:** HELM-230/531; HELM-650 user stories 33–34.
- **Rationale:** desired state and running state are different gates.
- **Preconditions:** AK-025 and authorized non-production deployment path.
- **Verification seam:** Flux/Helm/deployment/pod/image readback and public Kernel smoke.
- **Verification method:** wait for reconciliation, inspect workload image ID/readiness/restarts, run version and governed smoke, exercise rollback where the gate requires it.
- **Required evidence:** context/namespace, GitOps revision, reconciler conditions, image ID, pod state, smoke receipts, rollback readback.
- **Pass condition:** running workload matches AK-025, is healthy, smoke succeeds, and rollback evidence is complete.
- **Fail condition:** drift, not-ready workload, wrong image, smoke failure, missing rollback, or production inference.
- **Dependencies:** AK-025.
- **Status:** UNVERIFIED

## AK-027 — Real OpenAI governed run

- **Category:** OrganizationRuntime evidence
- **Criticality:** Critical
- **Requirement:** The approved Docs Ops scenario runs through the public OrganizationRuntime API with the real OpenAI adapter and produces a governed draft-only GitHub effect/readback.
- **Authoritative source:** HELM-637/639/640/643/644/645/646/638/641; HELM-650 user stories 35, 39–40.
- **Rationale:** a fake provider cannot prove the real adapter seam.
- **Preconditions:** HELM-639 boot specification, HELM-640 authority boundary, HELM-643 proposal projection, HELM-644 workload trust, and HELM-645 Evidence Signer are complete at exact merged revisions with source/CI evidence; HELM-646 durable public usage projection and HELM-638 runner are merged and complete; approved credentials are available without exposing values.
- **Verification seam:** public `/api/v1/workspaces/{id}/runs` plus provider and GitHub readback.
- **Verification method:** submit canonical fixture, poll ordered events, verify provider snapshot/generation/usage, Kernel decision, effect attempt, draft PR/head/path, and reconciliation.
- **Required evidence:** exact source heads, run/plan IDs, provider/model/generation IDs, redacted usage, decision/effect/reconciliation refs, GitHub PR readback.
- **Pass condition:** real OpenAI generation drives only the authorized governed effect and all required readbacks join.
- **Fail condition:** stub/fake provider, missing governance/effect/readback, wrong target/path, secret exposure, or customer/production effect.
- **Dependencies:** HELM-639, HELM-640, HELM-643, HELM-644, HELM-645, HELM-646, HELM-638, AK-031, AK-032.
- **Status:** UNVERIFIED

## AK-028 — Real Anthropic governed run

- **Category:** OrganizationRuntime evidence
- **Criticality:** Critical
- **Requirement:** The same Docs Ops conformance scenario runs through the same public runtime with the real Anthropic adapter and the same authority/effect boundary.
- **Authoritative source:** HELM-637/639/640/643/644/645/646/638/641; HELM-650 user story 35.
- **Rationale:** multi-provider means the same product path, not parallel demos.
- **Preconditions:** HELM-639 boot specification, HELM-640 authority boundary, HELM-643 proposal projection, HELM-644 workload trust, and HELM-645 Evidence Signer are complete at exact merged revisions with source/CI evidence; HELM-646 durable public usage projection and HELM-638 runner are merged and complete; approved credentials are available without exposing values.
- **Verification seam:** public run API plus Anthropic and GitHub readback.
- **Verification method:** repeat AK-027 with the real Anthropic snapshot model and compare path/invariants, not natural-language output equality.
- **Required evidence:** source/run/plan/provider/model/generation/usage, decision/effect/reconciliation, GitHub readback.
- **Pass condition:** real Anthropic generation traverses the same governed path and only the authorized effect occurs.
- **Fail condition:** fake adapter, product fork, missing evidence, unauthorized effect, or secret exposure.
- **Dependencies:** HELM-639, HELM-640, HELM-643, HELM-644, HELM-645, HELM-646, HELM-638, AK-031, AK-032.
- **Status:** UNVERIFIED

## AK-029 — Second organization without product fork

- **Category:** OrganizationRuntime evidence
- **Criticality:** Critical
- **Requirement:** The materially different Release Evidence Auditor plan runs through the same runtime/API/service composition with a distinct canonical plan hash and outcome contract.
- **Authoritative source:** HELM-637/639/640/643/644/645/638/641; HELM-650 user story 36.
- **Rationale:** one fixture cannot support multi-organization reuse.
- **Preconditions:** HELM-639/640/643/644/645 source and authority prerequisites plus HELM-638 are complete; one real-provider execution path is available.
- **Verification seam:** public run API and source/deployment identity comparison.
- **Verification method:** submit second canonical fixture, assert distinct plan hash/goal/outcome and identical product binary/service path, then capture ordered evidence.
- **Required evidence:** both fixture hashes, run IDs, source/deployment identity, event/effect/outcome refs.
- **Pass condition:** two materially different plans use the same product path without conditionally forked product code.
- **Fail condition:** reused/equivalent fixture, product fork, missing distinct outcome, or unverifiable plan hash.
- **Dependencies:** HELM-639, HELM-640, HELM-643, HELM-644, HELM-645, HELM-638, AK-027 or AK-028.
- **Status:** UNVERIFIED

## AK-030 — Restart/resume without duplicate effect

- **Category:** recovery and exactly-once
- **Criticality:** Critical
- **Requirement:** A controlled interruption after durable progress resumes from Postgres and does not create a second GitHub effect.
- **Authoritative source:** HELM-637/639/640/643/644/645/638/641; HELM-650 user story 37.
- **Rationale:** recovery proof must include external idempotency, not merely process restart.
- **Preconditions:** HELM-639/640/643/644/645 source and authority prerequisites plus HELM-638 are complete; a real governed run is ready for the approved interruption point.
- **Verification seam:** public run/event state, durable store, Data Plane attempt/reconciliation, and GitHub readback.
- **Verification method:** record pre-interruption state, stop/restart the owning service, resume/poll, compare attempt/idempotency/effect identities and GitHub PR count.
- **Required evidence:** timestamps, state/event sequence, restart identity, attempts, idempotency key, reconciliation, before/after GitHub readback.
- **Pass condition:** run completes/reconciles with exactly one authorized external effect.
- **Fail condition:** duplicate PR/effect, lost progress, manual state surgery, or fixture substitution.
- **Dependencies:** HELM-639, HELM-640, HELM-643, HELM-644, HELM-645, HELM-638, AK-027 or AK-028, AK-031, AK-032.
- **Status:** UNVERIFIED

## AK-031 — Durable joined runtime evidence

- **Category:** evidence traceability
- **Criticality:** Critical
- **Requirement:** Every runtime scenario joins run, node, provider/model/generation identity, bounded prompt/completion/total usage, Kernel decision, Data Plane attempt, connector receipt, reconciliation, plan hash, and evidence references by durable identifiers.
- **Authoritative source:** HELM-637/639/640/643/644/645/646/638/641; HELM-650 user stories 38–39.
- **Rationale:** isolated logs cannot prove an end-to-end governed loop.
- **Preconditions:** HELM-639/640/643/644/645 source and authority prerequisites plus HELM-646 and HELM-638 are merged and complete; source-owner stores are available.
- **Verification seam:** public ordered events plus source-owned readback APIs/stores exposed by the approved runner.
- **Verification method:** collect redacted evidence and validate referential integrity, ordering, hashes/signatures, and exact source/deployment refs.
- **Required evidence:** redacted evidence directory, schema/manifest, provider/model/generation/usage readback, join validation output, immutable source refs.
- **Pass condition:** every mandatory node and bounded usage field is present and joins without guessed or synthetic identifiers.
- **Fail condition:** orphan/missing record, fabricated join, unredacted secret, invalid signature/hash, or ambiguous source.
- **Dependencies:** HELM-639, HELM-640, HELM-643, HELM-644, HELM-645, HELM-646, HELM-638.
- **Status:** UNVERIFIED

## AK-032 — Fail-closed dispatch and read-only reconciliation

- **Category:** runtime security
- **Criticality:** Critical
- **Requirement:** Denied/unresolved Kernel decisions and real-provider failure cause no unauthorized dispatch, provider failure is durably observable without optimistic success, and ambiguous/retryable effect state settles only through read-only reconciliation.
- **Authoritative source:** HELM-637/639/640/643/644/645/638/641/642; HELM-650 negative testing decisions.
- **Rationale:** successful-path evidence is insufficient for an execution firewall.
- **Preconditions:** HELM-639/640/643/644/645 source and authority prerequisites plus HELM-638 are complete; the live stack and approved sandbox target are available.
- **Verification seam:** public run API, Kernel decision, Data Plane attempt state, connector/GitHub readback.
- **Verification method:** exercise denied, unresolved/escalated, controlled real-provider failure, and ambiguous retry cases; count dispatch/effects, verify durable failure events/readback, and verify reconciliation transitions.
- **Required evidence:** decisions, provider failure identity/category with secrets redacted, durable events/outcome, attempts, connector calls, external readback, event sequence, and exit/outcome states.
- **Pass condition:** denied/unresolved/provider-failure cases dispatch zero unauthorized effects; provider failure remains durably visible and non-successful; ambiguous state is resolved by read-only observation without duplicate write.
- **Fail condition:** any prohibited dispatch, provider failure reported as success or lost after restart/readback, optimistic success, write-based reconciliation, duplicate effect, swallowed error, or secret exposure.
- **Dependencies:** HELM-639, HELM-640, HELM-643, HELM-644, HELM-645, HELM-638.
- **Status:** UNVERIFIED

## AK-033 — Runtime proof claim boundary

- **Category:** claim control
- **Criticality:** Critical
- **Requirement:** The runtime report names exact non-production scenarios and explicitly does not claim Product Release R2/R3/R4, production, customer acceptance, GA, or arbitrary organization/tool coverage.
- **Authoritative source:** HELM-637/642; HELM-650 user stories 41–42.
- **Rationale:** precise evidence must not be promoted into a broader product claim.
- **Preconditions:** AK-027–AK-032 results.
- **Verification seam:** final runtime evidence/report and public/tracker wording.
- **Verification method:** compare every claim to its supporting source/runtime evidence and forbidden claim list.
- **Required evidence:** claim inventory with evidence pointers and explicit non-proof section.
- **Pass condition:** every positive claim is bounded to observed scenarios and every forbidden inference is absent/denied.
- **Fail condition:** OrganizationRuntime, production, customer, GA, or arbitrary-coverage claim beyond evidence.
- **Dependencies:** AK-027–AK-032.
- **Status:** UNVERIFIED

## AK-034 — Public release claim control

- **Category:** public truth
- **Criticality:** Critical
- **Requirement:** Public v0.8.5 copy states only verified Kernel capabilities, retains the execution-firewall wedge/status label, and is approved separately from code/package publication.
- **Authoritative source:** workspace public messaging boundary; HELM-647 exclusions; HELM-650 user story 31 and authority decisions.
- **Rationale:** published code does not authorize availability or broader HELM claims.
- **Preconditions:** candidate/public evidence and exact public-claims review packet.
- **Verification seam:** full changed public-copy diff plus deployed readback.
- **Verification method:** run source-owned docs/claim gates and specialist review; compare claims to AK evidence before deployment.
- **Required evidence:** claim inventory, source refs, approval reference, tests/CI, deployed URLs/hashes.
- **Pass condition:** only evidence-backed Kernel claims appear; status/wedge are correct; separate approval is recorded.
- **Fail condition:** unapproved copy, GA/world-class/100%/OrganizationRuntime/production/customer inference, or stale deployed text.
- **Dependencies:** relevant AK evidence, AK-037.
- **Status:** UNVERIFIED

## AK-035 — Linear reconciliation

- **Category:** tracker governance
- **Criticality:** High
- **Requirement:** Release/runtime issues and project naming/state are reconciled to v0.8.5 from exact source, CI, merge, artifact, deployment, and runtime evidence, with stale v0.8.4 gates closed or version-forwarded and replacement pointers preserved. HELM-650 is the delivery parent and names the Git conductor plus integration validation. Every child implementation ticket names a unique delivery order, blockers, answer-key requirements, owning repository and exact owned paths (or an explicit no-source boundary), and observable acceptance evidence. Concurrent `Owns` entries do not overlap; shared files remain conductor-owned or force sequential execution; blockers outside the loaded graph are explicitly documented on HELM-650.
- **Authoritative source:** HELM-649/650 user stories 43–44; issue-tracker contract.
- **Rationale:** stale tracker shells cause duplicate work and false status.
- **Preconditions:** evidence exists for the state being asserted.
- **Verification seam:** Linear issue/project graph and source-owned evidence links.
- **Verification method:** update titles/bodies/states/relations only after evidence, then list every open HELM-650 child, load each issue, and audit parent, unique numeric delivery order, blocker closure, AK coverage, repository/`Owns`, ownership overlap, observable acceptance, delegate/assignee, and conductor/integration-validation fields; query for stale/duplicate blockers and require every external blocker on HELM-650.
- **Required evidence:** before/after issue IDs, comments with immutable refs, dependency query, project status readback, the HELM-650 Git-conductor and integration-validation fields, and a per-ticket graph audit table covering parent, order, blockers, AKs, repository/paths, overlap, acceptance, delegate/assignee, and conductor; include an external-blocker ledger even when empty.
- **Pass condition:** tracker accurately distinguishes completed, active, human-only, deployed, runtime, and non-proof states with no stale v0.8.4 release shell; HELM-650 owns the delivery graph and integration validation; every child has all required fields, unique order, complete AK coverage, non-overlapping concurrent ownership, and no undocumented external blocker.
- **Fail condition:** task closure without evidence; wrong/missing parent; duplicate/missing order; duplicate owner; missing blocker/AK/repository/owned-path/acceptance/conductor/integration-validation field; overlapping concurrent ownership; undocumented external blocker; missing AK coverage; or stale contradictory project/status.
- **Dependencies:** evidence-producing AKs.
- **Status:** UNVERIFIED

## AK-036 — Independent review and verified gauntlet

- **Category:** independent verification
- **Criticality:** Critical
- **Requirement:** Separate builder, Standards critic, Specification critic, answer-key critic, and fresh final verifier contexts grade the exact integrated result without critic edits.
- **Authoritative source:** HELM-642; HELM-650 user stories 45, 49; verified-gauntlet and code-review contracts.
- **Rationale:** the implementer cannot grade its own release.
- **Preconditions:** fixed candidate/ticket slice and recorded starting hashes/status.
- **Verification seam:** separate run identifiers, unchanged critic hashes, exact diff and answer-key scorecard.
- **Verification method:** dispatch bounded independent contexts, run required checks, return failures to the same builder, repeat until all mandatory AKs pass.
- **Required evidence:** run IDs/roles/input packets, before/after hashes/status, verdicts/findings, remediation commits, final report.
- **Pass condition:** no critic edited inputs; both review axes and final verifier return GO/PASS for every applicable mandatory requirement.
- **Fail condition:** simulated self-review, critic edit, missing axis, unresolved Critical/High finding, or unverified requirement.
- **Dependencies:** all implementation/evidence requirements.
- **Status:** UNVERIFIED

## AK-037 — Exact separated approval packets

- **Category:** authority
- **Criticality:** Critical
- **Requirement:** Separate single-use packets exist for (a) tag/package publication, (b) public-claim approval, and (c) production promotion, each naming identity, target, exact command/action, candidate/artifact/environment, expected readback, rollback limit, and abort-on-drift rules.
- **Authoritative source:** Kernel AGENTS; workspace merge/privilege policy; HELM-650 user stories 46–47.
- **Rationale:** broad “ship” intent cannot silently widen privileged authority.
- **Preconditions:** exact candidate and relevant evidence fixed.
- **Verification seam:** packet text plus live preflight identity/context readback.
- **Verification method:** independently inspect for completeness and execute only the specifically approved packet once, aborting on any mismatch.
- **Required evidence:** packet hashes/content, approval reference, preflight and post-action readback, unused/aborted state as applicable.
- **Pass condition:** all packets are executable and non-overlapping; any executed action exactly matches its approval and readback.
- **Fail condition:** ambiguous identity/target/command, bundled authority, missing abort/rollback/readback, or action outside approval.
- **Dependencies:** AK-001 and evidence relevant to each packet.
- **Status:** UNVERIFIED

## AK-038 — Safe final estate cleanup

- **Category:** source estate
- **Criticality:** High
- **Requirement:** Only branches/worktrees proven merged, superseded, or task-created and preserved are removed; final Kernel estate state is recorded without deleting tags, recovery refs, or unrelated user work.
- **Authoritative source:** HELM-430; HELM-650 user story 50.
- **Rationale:** cleanup is the last step because evidence/repair may still depend on refs.
- **Preconditions:** AK-008, AK-009, relevant PRs merged/closed, human/task ownership known.
- **Verification seam:** GitHub/local branch/worktree inventories and reachability.
- **Verification method:** re-query immediately before each scoped cleanup, use normal branch/worktree deletion only, then re-query final state.
- **Required evidence:** pre/post ledgers, exact removed targets/reasons, recovery locations, final main alignment.
- **Pass condition:** every removed target was safe by the ledger and all retained exceptions are explicit.
- **Fail condition:** broad/mass deletion, lost unique/dirty work, tag/recovery loss, or cleanup claim based on stale inventory.
- **Dependencies:** AK-008, AK-009.
- **Status:** UNVERIFIED

## AK-039 — Final integrated release report

- **Category:** release decision
- **Criticality:** Critical
- **Requirement:** A final report scores every AK, records exact commands/identities/evidence, separates all delivery states, lists unsupported claims/risks, and returns GO only when every mandatory requirement is PASS or justified NOT APPLICABLE.
- **Authoritative source:** HELM-649 binary acceptance; HELM-650 user story 49; verified-gauntlet contract.
- **Rationale:** completion must be falsifiable and resumable.
- **Preconditions:** all applicable AK verification attempts complete.
- **Verification seam:** `.wayfinder/.../verification-report.md` plus referenced immutable evidence.
- **Verification method:** fresh final verifier reruns integrated gates and validates every traceability row/evidence pointer.
- **Required evidence:** requirement scorecard, commands/results, source/CI/merge/artifact/deploy/runtime/public refs, risks and non-proof.
- **Pass condition:** every mandatory AK is PASS or legitimately NOT APPLICABLE; report evidence resolves and matches exact final heads.
- **Fail condition:** any mandatory FAIL/BLOCKED/UNVERIFIED, stale evidence, optimistic state collapse, or missing unsupported-claim section.
- **Dependencies:** AK-001–AK-038.
- **Status:** UNVERIFIED

## AK-040 — Exact release notes and change inventory

- **Category:** release communication
- **Criticality:** High
- **Requirement:** Changelog/release notes enumerate only changes present between public v0.8.4 and the exact v0.8.5 candidate, include security/compatibility/rollback notes, and exclude unproved runtime or availability claims.
- **Authoritative source:** HELM-650 solution, user stories 31, 41–42, 48; HELM-647 claim exclusions.
- **Rationale:** release notes are part of the public contract and must match the bytes.
- **Preconditions:** AK-001, AK-008, AK-033, AK-034.
- **Verification seam:** Git diff/log from public v0.8.4 to candidate plus release-note diff.
- **Verification method:** generate/curate from exact merged history, reconcile every bullet to commits/tests, and run claim/docs checks.
- **Required evidence:** commit range, categorized inventory, source pointer per material claim, review/approval result.
- **Pass condition:** every note is present in candidate evidence and all material security/compatibility/rollback information is included.
- **Fail condition:** missing material change, phantom/unmerged feature, unsupported claim, or wrong version/source range.
- **Dependencies:** AK-001, AK-008, AK-033, AK-034.
- **Status:** UNVERIFIED
