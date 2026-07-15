# HELM AI Kernel OSS 1.0 Release Train

<!-- quantum_posture: this planning doc mentions release signature and provenance assets but does not implement cryptographic controls. -->

Status: internal release planning source, not release notes.
Current audit date: 2026-07-15.
Current source base: `origin/main@586a5d62`.
Current source version: `VERSION=0.7.2`.
Current GitHub release and tag: `v0.7.2` (lockstep acceptance incomplete).

Do not add this file to the public docs manifest. Future release scope becomes
public only through tagged release notes, changelog entries, release assets, and
published drift evidence for that exact version.

## Current State Audit

| Surface | Current state | Evidence | Plan impact |
| --- | --- | --- | --- |
| Release baseline | `v0.7.2` is the latest GitHub tag and Release, published from exact current `main`; the release run is red because Homebrew failed and post-release drift skipped. | `VERSION`, `gh release view v0.7.2`, release run `29338793179` | Keep tag/assets/channel/runtime evidence separate; do not call the lockstep release complete from the Release object alone. |
| Open PR dependencies | Eighteen kernel PRs are open as of this audit; branch presence does not declare release scope. | `gh pr list --state open` on 2026-07-15 | Re-evaluate approved, green prerequisites at the next release cut. |
| Unreleased main delta | Tag `v0.7.2` and current `origin/main` both resolve to `586a5d62`; this candidate docs PR is not part of that release. | `git rev-parse v0.7.2 origin/main` | Establish the next release scope only through a new, authorized release train. |
| EvidencePack structure | Mandatory pack structure, optional host evidence, and declared `99_EXT/` extensions exist. | `core/pkg/conform/evidencepack.go:13` | Historical `v0.7.0` scope; future release planning must start from the current release state above. |
| EvidencePack seal and verifier | Native seal and verification paths exist. | `core/pkg/evidence/seal.go:191`, `core/pkg/evidence/seal.go:349` | Historical `v0.7.0` exit criteria; do not treat this row as a current release-gap claim. |
| ProofGraph | ProofGraph refs are used by runtime adapters, exports, and evidence packs. | `core/pkg/evidence/arc/pack_builder.go:39`, `core/pkg/workstation/evidence.go:63` | Historical `v0.7.0` scope; verify current behavior through source and release evidence. |
| Agent risk scan | `helm-ai-kernel scan` exists with RiskEnvelope, preview, evidence-pack, receipt projection, and upload gates. | `core/cmd/helm-ai-kernel/scan_cmd.go:31`, `core/pkg/riskscan/scan.go:56` | `v0.8.0` should stabilize and contract-freeze the scan surface. |
| RiskEnvelope schema | JSON Schema and Go model exist with raw-data non-collection fields. | `protocols/json-schemas/risk-envelope/v1.json:19`, `core/pkg/riskenvelope/envelope.go:142` | `v0.8.0` must decide SDK/API parity and lock schema compatibility. |
| RiskEnvelope SDK parity | OpenAPI/SDKs expose MCP scan, not the local RiskEnvelope contract. | `api/openapi/helm.openapi.yaml:3204` | Add OpenAPI component and SDK generated types, or explicitly declare CLI-only scope. |
| Release gates | Maintained gates exist: `quality-merge`, `quality-release`, `release-readiness`, `release-assets`, `version-drift-published`. | `Makefile:88`, `Makefile:130`, `Makefile:143`, `Makefile:146`, `Makefile:262` | Keep the per-release loop gate-driven. |

## Release Train

| Version | Theme | Scope | Exit criteria |
| --- | --- | --- | --- |
| `v0.7.0` | EvidencePack and ProofGraph beta | Freeze EvidencePack authority, ProofGraph refs, transparency proofs, offline verifier, conformance oracle, and tamper-failure coverage. | Downloaded release pack verifies offline; tampered pack fails. |
| `v0.7.1` | Evidence hardening | Verifier UX, pack compatibility, docs/examples, and conformance regressions only. | Focused verifier/proofgraph tests plus release gates pass. |
| `v0.7.2` | Enforcement and dependency hardening | Governed MCP execution, boundary-contract alignment, emergency-stop and replay hardening, and dependency/toolchain refreshes. | GitHub assets exist; lockstep acceptance remains blocked on the red release run and skipped post-release drift. |
| `v0.8.0` | RiskEnvelope and agent risk scan beta | Stabilize `helm-ai-kernel scan`, RiskEnvelope schema, local preview, EvidencePack export, optional anonymized upload, observe/shadow/enforce mapping, and SDK parity. | Redaction tests prove no raw secret, prompt, command body, source snippet, or sensitive path leakage. |
| `v0.8.1` | Risk scan hardening | Redaction, schema parity, SDK examples, upload/privacy docs only. | Scan CLI/API, SDK, docs-truth, and RiskEnvelope tests pass. |
| `v0.9.0` | Release candidate freeze | No net-new features. Refresh OpenAPI, proto, schemas, SDKs, chart, Homebrew, VEX, changelog, release docs, repo manifest, and fanout readiness. | `make quality-release`, `make release-readiness`, and `make release-assets` pass from clean `origin/main`. |
| `v0.9.1` | RC fix pass | Only release, asset, fanout, token, Homebrew, docs-truth, or contract-drift fixes. | Clean downloaded release verifies across all published surfaces. |
| `v0.9.2` | Optional RC2 | Cut only if RC1 exposes a real release defect. | Same as `v0.9.1`; otherwise skip. |
| `v1.0.0` | Stable OSS Kernel | Freeze public contracts and publish complete lockstep release assets/channels. | Local gates, tag workflow, post-release drift, and clean-download verification all pass. |

## Cross-Release Rules

- One release has one theme. Do not mix EvidencePack, RiskEnvelope, release
  infrastructure, and product-scope work in the same tag unless the prior tag
  failed and the fix is required to publish correctly.
- Public scope is Kernel and HELM Enterprise only. No app website, product-site,
  cloud GA, self-serve checkout, connector certification, or Company AI OS GA
  claim belongs in this train.
- Docs follow code. Public docs can explain a released mechanism, but they must
  not define release scope or promote unreleased behavior.
- Compatibility shims are allowed only when validation proves a downstream
  break. Do not add speculative aliases.
- Generated OpenAPI, proto, schema, and SDK outputs change only when source
  contracts change.
- `sdk/go/v<version>` must point at the same commit as `v<version>`. Never move
  an existing tag.
- Homebrew and downstream fanout are release-completeness gates, not follow-up
  niceties.

## Per-Release Execution Loop

1. Create a fresh worktree from `origin/main`; record branch, upstream, dirty
   state, `VERSION`, latest release tag, current head SHA, and open PR
   dependencies.
2. Run scoped `/helm-audit`; use codebase-memory or CodeGraph for structural
   code discovery.
3. Merge only approved and green prerequisite PRs, preserving attribution.
4. Apply one release theme and keep unrelated changes out.
5. Run `make prepare-version VERSION=<target>`.
6. Regenerate OpenAPI, proto, schema, and SDK outputs only when source contracts
   changed.
7. Add exact `release/vex/v<target>.openvex.json`.
8. Update `CHANGELOG.md`, release docs, publishing/verification/security docs,
   SDK docs, and version-surface references.
9. Run focused tests for the release theme, then:

```bash
make quality-merge
make quality-release
make release-readiness
make release-assets
```

10. Open one release PR. Require CI, CodeQL, Scorecard, docs truth, SDKs,
    contract drift, deployment smoke, kind smoke, release smoke, and launchpad
    smoke to pass.
11. Merge only after required review.
12. Tag merged `main` as `v<target>`; create `sdk/go/v<target>` at the same
    commit if the workflow does not already do it.
13. Monitor the tag workflow: version contract, validate, deployment smoke, kind
    smoke, release smoke, binaries, cosign, reproducibility, container, chart,
    ArtifactHub, npm, PyPI, crates, Maven, Homebrew, downstream fanout, version
    status, GitHub Release, and post-release drift.
14. Download published assets into a clean directory and verify checksums,
    cosign bundles, SBOM, SLSA/provenance, OpenVEX, release attestation,
    Homebrew formula, Docker/Helm tags, SDK registry versions, Go proxy,
    pkg.go.dev, docs-site claims, and EvidencePack offline.
15. Close or retarget superseded PRs and update Linear with final release
    evidence.

## Historical `v0.7.0` Planning Record

`v0.7.0` is already a published historical release. The following original
planning record is retained for provenance only; it is not a claim that these
items remain missing from current `main`.

Original planned implementation:

- Define the frozen EvidencePack authority contract:
  - mandatory top-level entries and optional entries;
  - declared `99_EXT/<name>` extension rules;
  - canonical hash inputs;
  - seal path and signature preimage;
  - trust profile states for dev-local, anchored, stored, and externally signed
    packs.
- Define ProofGraph refs:
  - stable ref string grammar;
  - required node fields for receipts, replay, and pack export;
  - terminal graph binding in `00_INDEX.json`;
  - replay root semantics.
- Add a conformance oracle:
  - one valid golden pack;
  - one tampered pack for each required failure class;
  - deterministic expected verifier output.
- Add offline verifier coverage:
  - valid downloaded pack;
  - changed `00_INDEX.json`;
  - changed receipt;
  - changed ProofGraph node;
  - missing declared extension;
  - undeclared extension;
  - stale seal signature;
  - mismatched storage or transparency anchor.
- Update docs/examples only after tests exist.

Focused validation:

```bash
go test ./core/pkg/conform ./core/pkg/evidence ./core/pkg/workstation ./core/cmd/helm-ai-kernel
make docs-coverage docs-truth
make quality-merge
make release-readiness
make release-assets
```

Release note boundary:

- Say: EvidencePack and ProofGraph verifier beta.
- Do not say: customer-grade audit archive, compliance certification, cloud
  attestation, or production legal evidence.

## Historical `v0.7.1` Planning Record

`v0.7.1` is the published historical predecessor to `v0.7.2`. The following original scope is
retained for release-history context and does not define an unimplemented
backlog for current `main`.

Original allowed changes:

- clearer verifier error output;
- compatibility fixes for packs produced by retained `v0.7.0` writers;
- published-release SLSA subject integrity checks and repair-only provenance
  workflow fixes;
- documentation examples that mirror tested commands;
- conformance regression fixtures.

Not allowed:

- new pack layout;
- new ProofGraph node classes;
- new upload, cloud, or enterprise product promise.

Focused validation:

```bash
go test ./core/pkg/conform ./core/pkg/evidence ./core/cmd/helm-ai-kernel
make docs-coverage docs-truth
make quality-merge
make release-readiness
make release-assets
```

## `v0.8.0` Missing Parts

Current source already has:

- `helm-ai-kernel scan`;
- static local scan;
- receipt projection;
- RiskEnvelope JSON;
- Markdown and HTML preview;
- anonymized scan EvidencePack tar;
- explicit upload URL plus `--yes` gate;
- local-only salt file.

Required implementation:

- Freeze RiskEnvelope schema compatibility:
  - JSON Schema is authoritative;
  - Go enum to schema parity remains tested;
  - no free-text sinks for raw identifiers;
  - content hash binds findings and posture fields.
- Decide and implement SDK parity:
  - preferred: add RiskEnvelope schema/components to OpenAPI and regenerate Go,
    Java, Python, Rust, and TypeScript types;
  - fallback: explicitly mark RiskEnvelope as CLI-only in docs and remove SDK
    parity from the release claim.
- Map scan outputs to runtime policy vocabulary:
  - observe means report only;
  - shadow means compare to boundary decisions without changing dispatch;
  - enforce means existing runtime boundary paths, not `scan`, block effects.
- Keep upload privacy hard:
  - no raw prompts;
  - no source snippets;
  - no secret values;
  - no command bodies;
  - no raw paths or repository names;
  - no local salt.
- Add clean examples for static scan and receipt projection.

Focused validation:

```bash
go test ./core/pkg/riskenvelope ./core/pkg/riskscan ./core/pkg/shadow ./core/cmd/helm-ai-kernel
make sdk-openapi-check
make test-sdk-go-standalone
make test-sdk-ts
make test-sdk-py
make test-sdk-rust
make test-sdk-java
make docs-coverage docs-truth
make quality-merge
make release-readiness
make release-assets
```

Release note boundary:

- Say: local-first agent risk scan beta with anonymized RiskEnvelope export.
- Do not say: remote scanning service, managed ingestion backend, self-serve
  risk portal, or k-anonymity.

## `v0.8.1` Missing Parts

Allowed changes:

- redaction misses;
- schema/SDK parity drift;
- docs examples;
- upload privacy docs;
- receipt-projection regressions.

Not allowed:

- new scanner domains;
- new upload backend;
- new enforcement behavior.

Focused validation:

```bash
go test ./core/pkg/riskenvelope ./core/pkg/riskscan ./core/cmd/helm-ai-kernel
make sdk-openapi-check
make docs-coverage docs-truth
make quality-merge
make release-readiness
make release-assets
```

## `v0.9.0` Missing Parts

Required implementation:

- Freeze public OpenAPI, proto, JSON Schema, and SDK generated outputs.
- Refresh all version surfaces through `make prepare-version VERSION=0.9.0`.
- Add exact `release/vex/v0.9.0.openvex.json`.
- Ensure chart, Homebrew formula asset, MCP bundle, high-risk config,
  EvidencePack, release attestation, SBOM, and checksums are staged.
- Verify downstream fanout readiness for contracts catalog and Homebrew.
- Ensure public docs contain only released Kernel and HELM Enterprise scope.

Validation:

```bash
make quality-release
make release-readiness
make release-assets
```

Exit rule:

- If this release needs feature work, it is not an RC. Move that work back to
  `v0.8.x` or cut a new beta version.

## `v0.9.1` Missing Parts

Allowed changes only:

- failed release asset generation;
- missing or bad registry token wiring;
- Homebrew formula drift;
- downstream fanout drift;
- docs-truth or contract-drift failure;
- package registry publication recovery;
- clean-download verification defect.

Validation:

```bash
make quality-release
make release-readiness
make release-assets
make version-drift-published
```

## `v0.9.2` Missing Parts

Cut only if `v0.9.1` exposes a real release defect after publication. If
`v0.9.1` is clean, skip this version and move to `v1.0.0`.

Allowed scope and validation are identical to `v0.9.1`.

## `v1.0.0` Missing Parts

Required implementation:

- Freeze public contracts:
  - OpenAPI;
  - proto;
  - JSON schemas;
  - SDK package APIs;
  - CLI behavior documented in public docs;
  - release asset contract.
- Publish lockstep release channels:
  - GitHub Release;
  - GHCR image and chart;
  - ArtifactHub;
  - npm;
  - PyPI;
  - crates.io;
  - Maven Central;
  - Homebrew;
  - Go proxy and pkg.go.dev;
  - downstream contracts catalog.
- Attach complete release evidence:
  - binaries;
  - checksums;
  - cosign bundles;
  - SBOM;
  - SLSA/provenance;
  - OpenVEX;
  - release attestation;
  - EvidencePack;
  - high-risk config;
  - MCP bundle;
  - Homebrew formula asset;
  - `version-status.json`.
- Run clean-download verification from an empty directory after publication.
- Run `make version-drift-published` after registries settle.

Release note boundary:

- Say: stable OSS Kernel contracts and complete lockstep publication.
- Do not say: HELM Cloud GA, self-serve paid checkout, Company AI OS GA,
  customer certification, or production legal compliance.

## Clean-Download Verification Checklist

Use a new temporary directory and download only published release artifacts.
Do not use locally built files.

```bash
version=<target>
repo=Mindburn-Labs/helm-ai-kernel
mkdir -p "/tmp/helm-ai-kernel-${version}-verify"
cd "/tmp/helm-ai-kernel-${version}-verify"
gh release download "v${version}" -R "$repo"
shasum -a 256 -c SHA256SUMS.txt
binary=./helm-ai-kernel-<platform-asset-for-this-host>
"$binary" verify evidence-pack.tar
```

Then verify:

- every primary asset has a matching `.cosign.bundle`;
- `sbom.json` is present;
- `v<target>.openvex.json` is present;
- `release-attestation.json` is present;
- `version-status.json` reports pass;
- GHCR image and chart tags exist;
- ArtifactHub shows chart `version=<target>` and `app_version=v<target>`;
- npm, PyPI, crates.io, Maven, Homebrew, Go proxy, and pkg.go.dev expose the
  same version;
- docs-site install and SDK claims mention only that version;
- `make version-drift-published` passes from source `main`.

## Linear Update Template

Use one Linear update per release:

```text
Release: v<target>
Source branch:
Merge commit:
Tags:
GitHub Release:
Validation:
- focused:
- quality-merge:
- quality-release:
- release-readiness:
- release-assets:
- version-drift-published:
Published channels:
- GitHub Release:
- GHCR image/chart:
- ArtifactHub:
- npm:
- PyPI:
- crates:
- Maven:
- Homebrew:
- Go proxy/pkg.go.dev:
- contracts catalog fanout:
Known exclusions:
- no website/product-site work
- no cloud GA claim
- no self-serve checkout claim
```
