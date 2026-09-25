# Retirement wave 1: caller inventory (HELM-756)

quantum_posture: inventory only; this document names packages and commands but
exercises, changes, or asserts no cryptographic behaviour.

Status: slices 1 and 2 of HELM-756, 2026-09-24. Slice 1 was measured on `main`
at `a26ce1ca`, slice 2 on `main` at `2f1c11ab`.

Architecture rev 3.4 §14.4 lists retirement *candidates*. It is not a
bulk-deletion instruction. Before a candidate is removed, this inventory
records four things about it:
- its callers;
- its consumers outside this repository;
- the historical verification it must keep supporting;
- the invariants it holds.

A candidate is removed only when all four are clear. Everything else waits for
the slice that clears it.

## Method

- **Reverse imports inside the repository.** `GOWORK=off go list -e -json ./...`
  runs in each of the 13 Go modules. It separates non-test importers from
  test-only importers and computes reachability from every `core/cmd/*` main.
  The importer-less census is `scripts/ci/dead-packages.sh`.
- **Dead functions.** `GOWORK=off deadcode ./...` runs in `core` over all ten
  `core/cmd` mains. Of these, only `helm-ai-kernel` ships: it is the only
  binary in `.goreleaser.yml`, `Dockerfile` and `Dockerfile.slim`.
- **Workspace imports.** Every repository under the workspace root was searched
  for Go imports of `github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/...`.
  Kernel checkouts and the kernel source mirror inside `app-helm-docs`
  worktrees were excluded.
  - 19 kernel packages are imported, by `svc-helm-control-plane`,
    `svc-helm-data-plane`, `svc-agent-sandbox-runner`, `helm-ai-enterprise` and
    `integration-helm`.
  - Their transitive closure reaches only one candidate, `compliance/jcs`. It
    arrives through `evidence` and `boundary/approvalceremony`.
- **Workspace text references.** A second search looked for each candidate's
  path in files of every type across the workspace, which catches non-Go
  consumers such as string contracts, pins and documents.
- **Public surfaces.** The OpenAPI contract, the CLI, published SDK
  coordinates, `app-helm-docs`, and this repository's `docs/`, `README.md`
  and `CLAIMS.md`.
- **Invariants.** The `verify:` hints in `HELM_INVARIANTS.md`.

The 19 packages imported from outside the kernel are listed here because they
cannot be removed before the §14.6 port:
- `agentruntime`, `canonicalize`, `contracts`, `crypto`, `effects`, `events`,
  `evidence`, `networkproof`, `otel`, `packs/install`, `pdp`,
  `policy/reconcile`, `privacy`, `skillpacks`, `tracing`;
- `boundary/approvalceremony`, `boundary/extauthz`,
  `boundary/generatedspecapproval`, `boundary/generatedspecapprovalceremony`.

No §14.4 candidate is in that list.

## Decisions

| Candidate | Kernel callers (non-test / test-only) | Consumers outside the repo | Invariants | Decision | Slice |
|---|---|---|---|---|---|
| `core/pkg/zkgov`, `zkgov/proofmarket` (1,075 LOC) | None. `zkgov` is imported only by its own `proofmarket`. | None. `docs_for_team` has a capability inventory that describes it as "source-present". | — | **Remove now** | s1 |
| `core/pkg/federation` (533) | None | None | — | **Remove now** | s1 |
| `core/pkg/forge` (681) | None | None. The Control Plane and Enterprise import `helm-ai-enterprise/core/pkg/forge`, a separate package. | — | **Remove now** | s1 |
| `core/pkg/harness` (2,518) | None | None. The `integration-helm` `pins.yaml` note describes the Prime Agent adapter as part of pinned commit `de136a36`: a historical description, not a caller. | INV-021, INV-022, INV-023 | **Remove now**; the invariants are retired below | s1 |
| `core/pkg/worktree` (253) | Only `harness`, removed in the same slice | None | INV-020 | **Remove now** | s1 |
| `core/pkg/patchdelivery` (988) | None | None | INV-013 to INV-019 | **Remove now** | s1 |
| `core/pkg/connectors/ton/acton` (2,259) | None | Yes; see the notes below the table. | — | **Keep (blocked)**. Remove once the Control Plane TON connector is retired (§14.4, in the list of Control Plane code that is not ported) and the reason codes are deprecated. | s3 |
| `core/pkg/identity/iatp` (537) | None / `tests/conformance/did` | None | — | **Removed**. The IATP handshake test is removed from the DID smoke suite; the DID and VC tests stay. | s2 |
| `core/pkg/proofgraph/consensus` (554), `proofgraph/crdt` (595) | None | None | — | **Removed**. Both are protected paths; the boundary manifest is regenerated. | s2 |
| `core/pkg/orgdna` (239), `core/pkg/genesis/ceremony` (318) | None | None. `docs/KERNEL_SCOPE.md` lists `genesis/ceremony` as Active, which is false. | — | **Removed**; the KERNEL_SCOPE row is gone | s2 |
| `core/pkg/a2a/payments` (837) | None | None | — | **Removed**. The `a2a` root package stays. | s2 |
| `core/pkg/certification` and `certification/admission` (1,445) | None. The root is imported only by `admission`. | None | — | **Removed**. The top-level `certify` CLI was already removed by #971 (HELM-742). | s2 |
| `core/pkg/policy/wasm` (325) | None | None. It is named by `protocols/policy-schema/v1/canonicalization.md` and `docs/PCAS_AUTHORIZATION_PROPAGATION_GAP_ANALYSIS.md`. | **INV-005** | **Removed** after INV-005 was re-homed to the CEL `decide` in `core/pkg/kernel/authority`, which the Guardian calls in production and whose fail-closed tests now back the invariant. Both documents are corrected. | s2 |
| `core/pkg/compliance/*` (24 packages, 13,010 LOC) and the `compliance/zkprovider/gdpr17` module | `governance` and `registry`, through `compliance/jcs` only | `compliance/jcs` reaches the Control Plane, Enterprise and Data Plane through `evidence` and `boundary/approvalceremony` | — | **Removed** (s4a). `compliance/jcs` moved verbatim to `canonicalize/legacyjson`, so governance and registry hashes stay byte-identical; the regulated packs (H12) and the `gdpr17` module are deleted. | s4a |
| `core/pkg/conform` (3 packages, 6,078 LOC), gates G0–G15 | `cmd/helm-ai-kernel`: `conform`, `verify`, `demo`, `demo finance`, receipt evaluation | Six HTTP 501 routes from #971. See the notes below the table. | — | **Split** (s4d). Gates G1–G15 and GX, their profiles and `--level` are retired: `--level` exits 2. G0 stays for the signed release report. `adversarial` stays for `threat`. The `verify` helpers stay. The six routes were removed in s4b. | s4d |
| `core/pkg/launchkit` (893), `core/pkg/launchpad/*` (18 packages, 13,236 LOC) | `cmd/helm-ai-kernel` (`up`), `pkg/api` / `tests/launchpad` | None through Go imports. Launchpad retirement is HELM-762. | — | **Off by default** (s4d). `helm-ai-kernel up` needs `HELM_LAUNCHKIT_ENABLED=1`. Launchpad retirement and the egress-proxy image stay with HELM-762. | s4d |
| `core/pkg/channels/*` (1,588), `core/cmd/channel_gateway` (277) | The `channel_gateway` main; `packs/antispoof` (protected) / `tests/conformance/channels`, `antispoof` | None. `channel_gateway` is not in the release or the images. | — | **Removed** (s4d), together with `packs/antispoof`, its only importer, and both conformance suites. The boundary manifest is regenerated. | s4d |
| MCP rug-pull detector (`core/pkg/mcp/rugpull.go`) and pinned-schema checks | Rug-pull: no non-test caller. `core/pkg/mcp` itself stays. | `mcp-bundle.json` advertises `rug-pull-detection` | — | **Rug-pull: removed** (s4c). **Pinned schema: disabled by default** (s4c): the published docs-site MCP guide still passes `--require-pinned-schema=true`, so the flags and the `pinned_schema_hash` field stay accepted but ignored. | s4c |
| `tee` CLI (`tee_cmd.go`), `core/cmd/tee-collateral`, `.github/workflows/tee-collateral.yml` | `cmd/helm-ai-kernel` | None | — | **Removed** (s4c). No caller in the Console, the Control Plane or the docs site. | s4c |
| `core/pkg/riskscan` (1,780) | `cmd/helm-ai-kernel` (`scan`, `verify scan`) | None | — | **Extracted** (s4e) to `tools/riskscan` (binary `helm-risk-scan`); kernel `scan`/`verify-scan` are one-release stubs; `--upload` dropped. | s4e |
| `core/pkg/shellscan` (3,380) | `cmd/helm-ai-kernel` (`hook`) | None | — | **Keep**, but only inside the observed-only hook (§7.4). The H8 repair is tracked separately. | — |
| Java SDK (`sdk/java`), Rust SDK (`sdk/rust`) | Not applicable | See the notes below the table. | — | Remove in s5. **Publishing the deprecation is a human action.** | s5 |
| TLA+ specifications (`proofs/*.tla`, 7 specs), `.github/workflows/tla.yml` | Not applicable | None | — | Review each spec. Keep only the specs tied to code. | s6 |
| Verification-shaped commands not in §11.4, including `workstation certify` | `cmd/helm-ai-kernel` | Not yet mapped | — | Map them against §11.4 first | s6 |

Notes on the rows marked "see the notes below the table":

- **`core/pkg/connectors/ton/acton`.**
  - In the Control Plane, `internal/connectors/ton/acton/contract.go:106` delegates execution to this package. The same file pins the hashes of `protocols/json-schemas/connectors/ton/*`.
  - Its reason codes are published in `protocols/json-schemas/reason-codes`.
  - Protected golden cases live in `core/pkg/conformance/golden/ton-acton`.
  - It also appears in a policy template and in two documents.
- **`core/pkg/conform`, the six HTTP 501 routes.** Removed in s4b; see the
  slice 4b evidence below.
- **Java and Rust SDKs.**
  - No workspace repository consumes either SDK.
  - Publishing is configured for both, but whether they reached a registry was not checked:
    - Java: coordinates `io.github.mindburnlabs:helm-sdk` 0.8.5, through `maven-publish.yml` and `jitpack.yml`;
    - Rust: the `helm-sdk` 0.8.5 crate, through `crates-publish.yml`.
  - `protocols/conformance/v1/compatibility-registry.json` (protected) lists both SDKs.

This slice does not touch the routes the Control Plane calls today:
- `/api/v1/evaluate`
- `/internal/v1/organization-runtime/evaluate`
- `/api/v1/receipts`
- `/internal/v1/generated-spec-approvals/*`
- `/internal/emergency-stop/fence`

## Historical verification needs and fixtures

- **Slice 1 packages.** None of them emitted a receipt, an EvidencePack, a
  ProofGraph node, or a published format. The deleted design doc
  `docs/architecture/agent-process-ownership.md` said so in its claim
  boundaries. The algorithm id `helm-zkgov-v1` appears in no protocol, schema,
  fixture or reference pack, so no persisted proof exists that would need a
  verify-only reader. No fixture is kept.
- **Later slices.**
  - `acton`: its EvidencePack fixtures, golden cases and reason codes are decided together with the reason-code deprecation.
  - Conformance reports: if any signed report was ever handed out, a verify-only `VerifyReport` reader stays.
  - Receipt versions: they stay verify-only per §14.5.

## Invariants

Removing a package does not remove its requirement (§14.4). Each invariant held
by a slice-1 package is retired only after its behaviour is shown to be out of
scope for the kernel, or the requirement is assigned to the replacement path. The
entries in `HELM_INVARIANTS.md` keep their ids and text, carry a `RETIRED`
marker, and point at a successor.

| Invariant | Held by | Why it is out of scope in the kernel | Successor / owner |
|---|---|---|---|
| INV-013 Apply policy decided in one place | `patchdelivery` | No kernel code writes to a live tree. A repository write is an effect admitted through the gateway (§7.1–7.2). | INV-008 (permit scope) |
| INV-014 Override clears unknown, never proven-false | `patchdelivery` | Same reason as INV-013 | INV-005 (cannot decide → DENY) |
| INV-015 Override binds exact patch bytes | `patchdelivery` | Same reason as INV-013 | INV-008 |
| INV-016 Override scoped to a run awaiting decision | `patchdelivery` | Same reason as INV-013 | INV-010 |
| INV-017 Every live-tree mutation path registered | `patchdelivery` | Same reason as INV-013 | INV-024 |
| INV-018 Refused apply leaves tree byte-identical | `patchdelivery` | Same reason as INV-013 | INV-009 |
| INV-019 Verify never mutates; silence is not a pass | `patchdelivery` | Same reason as INV-013 | INV-025 |
| INV-020 Diff capture is byte-faithful | `worktree` | Same reason as INV-013 | INV-008, INV-001 |
| INV-021 Cross-provider credential scrub | `harness` | The kernel spawns no agent process. The sandbox holds no credentials (§7.2, §8). | INV-011. The requirement moves to the episode runner and must acquire a tested owner in the control registry. |
| INV-022 Exactly one terminal event per run | `harness` | Same reason as INV-021 | The episode protocol (§7.1, contract 9) owns the requirement. INV-024 bars any lifecycle claim until then. |
| INV-023 Unenforceable read-only claim refused | `harness` | Same reason as INV-021 | INV-024 |

INV-005 was held by `policy/wasm`. Slice 2 re-homes it before deleting the
package: its owner is now the CEL `decide` in `core/pkg/kernel/authority`, the
production policy path (HELM-750). The tests `TestDecideFailsClosed`,
`TestCompileErrorsDenyOnlyTheirAction`, `TestDecideCostLimitDenies`,
`TestCompileNilGraphDeniesEverything` and `TestPropertyUnknownActionDenies`
prove it. The rule is kept, not retired. INV-024 cites `core/pkg/runtimeadapters`, which is not a
candidate.

## Slice 1 evidence

| Measure | Before | After |
|---|---|---|
| `core/pkg` packages with non-test Go files | 290 | 283 |
| Importer-less packages (`dead-packages.sh`) | 135 | 129 |
| Unreachable from every `core/cmd` main | 146 | 139 |
| `deadcode ./...` unreachable functions, all `core/cmd` mains | 5,076 | 4,897 |
| `deadcode ./cmd/helm-ai-kernel` (shipped) | not re-measured | 2,815 |

The shipped count cannot change: no slice-1 package is in the shipped binary's
import graph, so `deadcode` never loaded them for that main. The package-wide count drops by the 179 functions in
the deleted packages.

The slice deletes:
- 54 files;
- 6,048 non-test lines and 8,314 test lines of Go;
- the design doc that described the three process-ownership packages.

No protected path is touched, so the boundary manifest does not change.

## Slice 2 evidence

Slice 2 removes:
- `proofgraph/consensus` and `proofgraph/crdt`;
- `orgdna` and `genesis/ceremony`;
- `identity/iatp`;
- `a2a/payments`;
- `certification` and `certification/admission`;
- `policy/wasm`.

None of them has a non-test importer in any module or an importer in any
workspace repository. Outside the kernel, only planning and audit documents
name them: the HELM Genesis plans in the workspace `docs/superpowers`, and
estate inventories.

| Measure | Before (`2f1c11ab`) | After |
|---|---|---|
| `core/pkg` packages with non-test Go files | 283 | 275 |
| Importer-less packages (`dead-packages.sh`) | 129 | 121 |
| Unreachable from every `core/cmd` main | 139 | 130 |
| `deadcode ./...` unreachable functions, all `core/cmd` mains | 4,897 | 4,740 |

The slice deletes:
- 43 files;
- 4,850 non-test lines and 5,728 test lines of Go.

Two protected paths change: `core/pkg/proofgraph/*` and
`protocols/policy-schema/v1/canonicalization.md`. The regenerated boundary
manifest drops exactly the 12 deleted protected files and re-hashes the edited
protocol document. `check_reason_code_reachability.py` passes, because none of
the removed packages was the only emitter of a declared reason code.

## Slice 4a evidence

Slice 4a retires `core/pkg/compliance/*`: 24 packages and 13,010 non-test
lines, plus the `compliance/zkprovider/gdpr17` module. The repository now has
12 Go modules instead of 13.

- **Callers.** Only `compliance/jcs` had importers: `governance/pdp.go` and
  `registry/pack_registry.go`. The Control Plane, Enterprise and Data Plane
  reach it transitively through `evidence` and `boundary/approvalceremony`.
- **Treatment of `compliance/jcs`.** It moved byte-for-byte to
  `core/pkg/canonicalize/legacyjson`, with its test. It is `encoding/json`
  plus a NaN/Inf refusal, not RFC 8785 JCS. Moving it rather than switching
  its callers to `canonicalize.JCS` keeps every existing decision and pack
  hash stable. No package outside the kernel imports it directly.
- **Documentation.** Three coverage rows and the private-docs entry for the
  compliance README are removed, along with the package test line in
  `docs/compliance/eu-ai-act-high-risk-pack.md`. The page is a mapping pack
  backed by `TestCanonicalEUAIActMappingPackContract`, not by the deleted
  packages, so it stays.

Two reason codes, `ERR_VERIFICATION_SCOPE_REQUIRED` and
`ERR_HARNESS_CHANGE_CONTRACT_INVALID`, lost their only emitter
(`core/pkg/harness`) in s1. They now leave:
- the registry, `verdict.go` and the negative conformance vectors that named
  them;
- `reason-codes-known-unreachable.txt`.

The Go core and SDK constants are regenerated with `gen_reason_codes.py`. The
registry drops from 106 to 104 codes; the reachability gate reports 59 emitted
and 45 allowlisted.

`dead-packages.sh` after this slice, measured on top of slice 2, reports 101
importer-less packages, 107 unreachable from every `core/cmd` main, and 252
`core/pkg` packages (from 121, 130 and 275).

## Slice 4b evidence

Slice 4b removes the six routes that HELM-742 had already turned into 501s:
- `POST /api/v1/conformance/run`;
- `GET /api/v1/conformance/reports` and `GET /api/v1/conformance/reports/{report_id}`;
- `POST /api/v1/gui/receipts/verify`;
- `POST /api/v1/trust/keys/add` and `POST /api/v1/trust/keys/revoke`.

Callers were checked read-only on 2026-09-24:
- **`svc-helm-control-plane`:** none.
- **`app-helm-console` (`31b6c19`):** the operations appear only in the
  generated clients (`lib/api/kernel.gen.ts`, `enterprise.gen.ts`) and in
  `contracts/openapi-operation-index.tsv`. No UI code calls them. The Console
  reads only the `policies` and `audit` entries of the kernel's surface
  catalog. `contracts/SURFACE-BACKING-REGISTER.md` names
  `POST /api/v1/gui/receipts/verify` as backing for a planned verifier
  surface, but that surface is not built. The Console regenerates its clients
  on its own side.
- **`helm-ai-enterprise`:** it serves its own copies of the conformance and
  trust-key paths, and its SDKs call those copies. None of them calls the
  kernel.
- **Kernel SDKs:** the Go, TypeScript, Python, Java and Rust clients each had
  conformance run, get and list methods. They are removed, together with their
  tests, READMEs and five examples, and CHANGELOG records the break.

The kernel's own Console surface catalog drops its `conformance` and `trust`
entries. `TrustKeyHandler` in `core/pkg/api` stays: it has no route, but the
HELM-495 context-logging contract test uses it as its positive control. Its
removal belongs to s6.

`oasdiff breaking` reports no incompatible change, because the removed
operations were deprecated. The SDK models were regenerated from the spec,
which drops the inline trust-key request and response schemas, and every
OpenAPI digest pin was updated.

## Slice 4c evidence

Callers were checked read-only in `app-helm-console`, `svc-helm-control-plane`,
`app-helm-docs` and `helm-ai-enterprise`.

| Surface | Callers found | Decision |
|---|---|---|
| `RugPullDetector` (`core/pkg/mcp/rugpull.go`) | None in any module or repo. Claimed only in `mcp-bundle.json` and in kernel docs. | Removed, with its tests and the claim. `ToolDefinition` and the `fixedClock` test helper move to `docscan.go` and `mcptox_test.go`, because `mcp scan` and other tests use them. |
| Pinned schema: `RequirePinnedSchema` and `ToolCallAuthorization.PinnedSchemaHash` in the firewall | Set only by `mcp authorize-call` (CLI and HTTP). The production bridge runs with no firewall (audit E-05). | **Disabled.** The firewall no longer reads a pin, but still denies a schema it cannot hash. |
| `mcp wrap --require-pinned-schema` | The docs site's `integrations/mcp.md` passes `--require-pinned-schema=true`. | **Kept and ignored.** The flag defaults to `false`, and the profile no longer claims a `schema_pin` control. The kernel docs drop the flag; the docs-site copy is re-synced by its owner. |
| `mcp authorize-call --pinned-schema-hash`, HTTP `pinned_schema_hash`, discovery `schema_pin_required` | The docs site publishes the OpenAPI field. The Console's generated client carries it, but no UI calls `authorizeMcpCall`. | **Kept and ignored.** The OpenAPI properties are marked `deprecated`, and `schema_pin_required` is always `false`. Removal waits for the next contract major. |
| `SCHEMA_VIOLATION` | A general reason code emitted by the PDPs, the executor and shellscan. | **Kept.** Only its remediation text in `deny-reason-codes.md` changes. |
| `helm-ai-kernel tee`, `core/cmd/tee-collateral`, `.github/workflows/tee-collateral.yml` | None. The docs site does not document them. | Removed. `make tee-collateral-verify` keeps running the package tests, so the `ci.yml` step, which #983 is rewriting, needs no edit. `core/pkg/crypto/tee` and `crypto/tee/collateral` are now importer-less protected packages and go to s6 with `deadcode`. |

Not changed in this slice:
- `scripts/launch/demo-mcp.sh` is updated for the new behaviour but fails on
  `main` before it reaches the MCP section: `/api/v1/evaluate` now requires a
  `session_id`. That fix is separate.
- Launchpad's `require_schema_pin` app-spec field stays; it belongs to the
  Launchpad slice (HELM-762).

## Slice 4d evidence

**Conformance gates.** Audit 08-01 found that no EvidencePack could pass G1 and
G7 together. Other gates passed vacuously (08-02, 08-07), passed by probing an
in-process library (08-05), or never failed (08-06). So `conform --level L1/L2`
and every profile built on those gates could not return a truthful result.

- **Removed:** gates G1–G15 and GX, the seeded local baseline, and the G1
  receipt-verifier environment hook.
- **Profiles:** only `SMB` remains, and it requires only G0.
- **Kept:**
  - G0, build identity, because the release pipeline signs a G0 report
    (`make conformance-release-report`, `scripts/release/stage_release_assets.sh`,
    `conformance_release_gate.sh`);
  - `conform vectors`, `conform negative` and `conform managed-agents`, which
    come from the protected `conformance` package;
  - `conform/adversarial`, which `helm-ai-kernel threat` uses;
  - the `verify` helpers `ValidateEvidencePackStructure`, `VerifyReport`,
    `SignReport` and `CreateEvidencePackDirs`;
  - the historical fixture `fixtures/minimal`, which records gate results from
    a past run and is still read by `verify`.
- **`--level` is disabled, not removed.** The docs site's `conformance`,
  `quickstart`, `troubleshooting` and `write-policies` pages show
  `conform --level L1/L2`. The flag still parses, exits 2, and points to
  `conform vectors`.
- **Docs updated:** kernel `CONFORMANCE`, `QUICKSTART`, `TROUBLESHOOTING`,
  `policy-languages`, `tests/conformance/README.md`, and the protected
  `CONFORMANCE_GUIDE` and `policy-bundle-v1` spec.
- **Scripts updated:** `proof-path.sh` and `generate-golden.sh`.
- **Newly dead code removed:** `config/profile_loader.go`, which only G9 read,
  and the gate helper `dirExists`.

**Channels.** `core/pkg/channels/*` and `core/cmd/channel_gateway` had no
caller outside their own main, no release artifact and no workspace consumer.
They are removed. So are:
- `core/pkg/packs/antispoof` (protected), a pack built on the channels
  anti-spoof validator with no importer;
- the `tests/conformance/{channels,antispoof}` suites.

**LaunchKit.** Following §14.7, LaunchKit is off by default:
- `helm-ai-kernel up` refuses, exiting 2, unless `HELM_LAUNCHKIT_ENABLED=1`;
- help still works;
- the Hermes docs show the opt-in.

Launchpad retirement stays with HELM-762, and the egress-proxy image rebuild is
outside this slice.

**Gates.** Stale allowlist lines removed: 18 deadcode, 32 gosec and 2 gitleaks.

## Slice 4e evidence

The decision (HELM-756, 2026-09-25) was to extract the scan, not delete it. The
public docs site opens its quickstart with it, it only observes configuration,
and §14.4 says to move it to a separate optional tool if kept.

- **Callers.** Only `helm-ai-kernel scan` and `verify-scan`. No route serves
  it, and the Console, the Control Plane and Enterprise do not call it.
- **What moves.**
  - `core/pkg/riskscan` and `core/pkg/riskenvelope` go to
    `tools/riskscan/internal/`, a separate Go module with its own `main`
    (`helm-risk-scan`) and tests. The code sits outside the kernel binary, the
    TCB and the line budget.
  - The EvidencePack producer in `core/pkg/executor`, together with its tests,
    moves to `tools/riskscan/internal/scanpack`. The scan was its only caller:
    Enterprise tests use Enterprise's own copy. Leaving it would have made it
    new dead code in the shipped binary.
- **Stubs.** `helm-ai-kernel scan` and `verify-scan` stay for one release. They
  print the new command and exit 2. The TUI's safety handling for `scan` is
  unchanged.
- **Removed.** `--upload`, `--upload-url`, `--yes` and `UploadEnvelope`. No
  service in the target architecture receives the upload.
- **Kept.** The default salt path, so pseudonyms stay stable.
- **Fixtures.** The key-shaped test fixture is now built at runtime, so the
  secret scanner does not flag the moved tests.
- **Gates.**
  - 3 gitleaks, 15 gosec and 1 deadcode allowlist lines went stale and are
    removed.
  - The gosec gate scans `core` and `sdk/go` only, so `tools/riskscan` is now
    outside its scope. Extending the gate to it means allowlisting its
    findings under their new paths. That is a HELM-745 decision.
- **Release.** `.goreleaser.yml` gains a `helm-risk-scan` build, archive and
  Homebrew formula. No workflow runs goreleaser today: the live release path
  (`make release-binaries`, `scripts/release/*`) does not build the new binary
  yet.

## Slice 6c evidence

quantum_posture: this section names `core/pkg/crypto/hsm`, a key-management
package; the slice removes it and adds no cryptographic behaviour.

Deleting the conform gates in s4d (#1002) orphaned two protected packages.
G13 was the only importer of `core/pkg/crypto/hsm` (346 non-test lines, a
PKCS#11 HSM abstraction). G15 was the only importer of
`core/pkg/proofgraph/condensation` (323 non-test lines, a condensation engine).

Callers, checked read-only:
- The reverse-import census over all modules finds no non-test importer and no
  test-only importer.
- `helm-ai-enterprise`, `svc-helm-control-plane`, `platform-*` and `worker-*`
  import neither package.

The dead-packages gate from #1000 reported both as unlisted. Its frozen list
only shrinks, so both are deleted.

What changes and what does not:
- `core/pkg/crypto/hsm.go` (SoftHSM, in the `crypto` package) stays. Its
  comment no longer points production users at the removed PKCS#11 provider.
- `contracts/condensation.go` and the checkpoint schema stay.
- No deadcode, gosec or gitleaks allowlist line named either package: the gosec
  lines for `core/pkg/crypto/hsm.go` belong to the file that stays. So no line
  is removed.
- The boundary manifest is regenerated for the two protected paths.
- `tcb-coverage-floors.txt` lists neither package and is untouched.
