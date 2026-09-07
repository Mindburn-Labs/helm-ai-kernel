# Dead package decisions (core/pkg)

quantum_posture: inventory only; this document names crypto packages but
exercises, changes, or asserts no cryptographic behaviour.

Status: proposed, 2026-09-07. No package is deleted by this document; every
row is a proposal for the package owner. A row closes when the owner either
adds the package to `scripts/ci/dead-packages-allowlist.txt` (KEEP), lands a
PR that gives it a real importer (WIRE), or lands a deletion PR (DELETE).
When zero rows remain open, flip `dead-packages` in
`scripts/ci/quality-gates.json` from advisory to blocking.

## How the list was produced

`scripts/ci/dead-packages.sh` runs `GOWORK=off go list -e -json ./...` in
every Go module of the checkout (`core`, `tools/*`, `tests/*`, `sdk/go`,
`examples/*`, `core/pkg/compliance/zkprovider/gdpr17`) and reports every
`core/pkg/...` package that no other package imports from non-test code.
Test-only importers (`_test.go` in another package) are counted separately
and do not rescue a package. Reachability from every `core/cmd/*` main is
reported for context.

Census on `main` at `04d48de2` (2026-09-07):

| measure | count |
|---|---|
| `core/pkg` packages with non-test Go files | 289 |
| importer-less | 134 |
| of which have test-only importers | 14 |
| unreachable from any `core/cmd/*` main | 145 |
| imported by a downstream repo in the workspace | 2 |
| proposed KEEP / WIRE / DELETE | 28 / 0 / 106 |

The 2026-09-07 audit reported 122 importer-less packages; it treated a
test-only importer as an importer. This census does not, which adds 12.

Evidence columns were gathered with `git grep -P 'pkg/<name>(?![A-Za-z0-9_/-])'`
over `docs/`, `protocols/`, `reference_packs/`, `sdk/`, `CLAIMS.md`,
`README.md`, `HELM_INVARIANTS.md`, `deploy/`, `launchpad/` (doc evidence) and
over `core/`, `tools/`, `tests/`, `scripts/`, `examples/` (code evidence, the
package's own directory excluded), plus a search of every sibling repo in the
workspace for Go imports of the package. `reference_packs/`, `sdk/` and
`CLAIMS.md` name none of the 134 packages.

## Decision rules

- KEEP: named in a shipped doc, protocol, or policy template; imported by a
  downstream repo; imported by the `tests/conformance` suite; listed in
  `tools/boundary/protected-dirs.sh`; or a protected `crypto/` or `verifier/`
  library package exercised by a cross-package test.
- WIRE: a Linear issue (HELM-658, HELM-674, HELM-682) names the package as
  work to wire into a `cmd/` with a test. None of the three names
  `harness`, `worktree`, `patchdelivery`, or `runtimeadapters/*` by package,
  so no row is WIRE. `docs/architecture/agent-process-ownership.md` (which
  labels three of them "not yet wired") is a design doc, not a ticket.
- DELETE: everything else, including packages whose only reference is a
  "not to be confused with" comment or their own test files.

A DELETE row under a protected path (`kernel/`, `contracts/`, `crypto/`,
`evidencepack/`, `proofgraph/`, `receipts`, `verifier/`, `connectors/sandbox`,
`conformance/`, `api/`, `packs/`) needs the `helm-kernel-reviewer` pass and a
boundary-manifest regeneration in its deletion PR.

## Table

LOC counts non-test Go lines. "last commit" is the last commit touching the
package directory.

| package | LOC | last commit | tests? | test-only importers | proposed | evidence |
|---|---|---|---|---|---|---|
| `core/pkg/a2a/payments` | 837 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/actiongraph` | 318 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/aibom` | 313 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/api/trust` | 287 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/attention` | 463 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/authority` | 56 | 2026-05-12 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/buildguard` | 125 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/celcheck` | 147 | 2026-05-28 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/certification/admission` | 777 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/channels/lark` | 273 | 2026-06-02 | yes | 1 | KEEP | conformance suite: tests/conformance/channels |
| `core/pkg/compliance` | 633 | 2026-08-24 | yes | 0 | KEEP | doc: docs/documentation-coverage.csv — row in docs/documentation-coverage.csv; parent of the compliance/* cluster |
| `core/pkg/compliance/cftc` | 448 | 2026-06-20 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/controls` | 173 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/csr` | 1551 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/docs` | 419 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/dora` | 579 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/enforcement` | 386 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/euaiact` | 593 | 2026-08-10 | yes | 0 | KEEP | doc: docs/compliance/eu-ai-act-high-risk-pack.md |
| `core/pkg/compliance/evidence` | 256 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/fca` | 138 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/gdpr` | 164 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/hipaa` | 247 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/mica` | 326 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/normalize` | 327 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/obligations` | 191 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/risk` | 570 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/sec` | 218 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/sox` | 149 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/templates` | 88 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/compliance/zkprovider/gdpr17` | 628 | 2026-08-24 | yes | 0 | KEEP | doc: docs/documentation-coverage.csv — own Go module; row in docs/documentation-coverage.csv |
| `core/pkg/conformance/agentsafety` | 142 | 2026-06-04 | yes | 1 | KEEP | doc: docs/security/agent-safety-conformance-cases.md; test importer: core/pkg/conformance/scenarios |
| `core/pkg/conformance/cases` | 402 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/conformance/negative` | 303 | 2026-07-28 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/conformance/sandbox` | 987 | 2026-06-02 | yes | 4 | KEEP | doc: docs/INTEGRATIONS/claude-managed-agents-self-hosted.md; doc: docs/security/owasp-agentic-top10-coverage.md; doc: protocols/conformance/managed-agents/claude-self-hosted/v1/conformance-pack.json; ref: core/pkg/conformance/agentsafety/registry.go; test importer: core/pkg/connectors/sandbox/claudemanaged; test importer: core/pkg/connectors/sandbox/daytona; test importer: core/pkg/connectors/sandbox/e2b; test importer: core/pkg/connectors/sandbox/opensandbox |
| `core/pkg/conformance/scenarios` | 16 | 2026-06-04 | yes | 0 | KEEP | doc: docs/security/agent-safety-conformance-cases.md; doc: docs/security/owasp-agentic-top10-coverage.md; ref: core/pkg/conformance/agentsafety/registry.go |
| `core/pkg/connectors/arc` | 1074 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/connectors/linear` | 1423 | 2026-08-13 | yes | 1 | DELETE | test importer: core/pkg/runtimeadapters/mcp — only importer is core/pkg/runtimeadapters/mcp/bridge_test.go (fixture); rewrite the fixture if deleted |
| `core/pkg/connectors/oauth2` | 235 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/connectors/sandbox` | 219 | 2026-07-01 | yes | 0 | KEEP | ref: tools/boundary/protected-dirs.sh |
| `core/pkg/connectors/sandbox/claudemanaged` | 1545 | 2026-07-01 | yes | 0 | KEEP | doc: docs/INTEGRATIONS/claude-managed-agents-self-hosted.md; doc: protocols/conformance/managed-agents/claude-self-hosted/v1/conformance-pack.json; doc: protocols/conformance/v1/compatibility-registry.json; ref: core/pkg/connectors/sandbox/README.md |
| `core/pkg/connectors/sandbox/opensandbox` | 511 | 2026-07-01 | yes | 0 | KEEP | ref: core/pkg/connectors/sandbox/README.md — listed in core/pkg/connectors/sandbox/README.md; protected dir |
| `core/pkg/connectors/siem/datadog_logs` | 212 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/connectors/siem/elastic_ecs` | 213 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/connectors/siem/loki` | 240 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/connectors/siem/splunk_hec` | 189 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/connectors/siem/sumo` | 167 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/connectors/slack` | 860 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/connectors/ton/acton` | 2259 | 2026-06-11 | yes | 0 | KEEP | ref: core/pkg/policy/templates/ton_acton.mapl — core/pkg/policy/templates/ton_acton.mapl ships a policy template for it |
| `core/pkg/constitution` | 616 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/contracts/schemas` | 61 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/crypto/keystore` | 477 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/crypto/mtls` | 627 | 2026-06-11 | yes | 1 | KEEP | test importer: core/pkg/crypto |
| `core/pkg/crypto/sdjwt` | 301 | 2026-04-23 | yes | 2 | KEEP | ref: core/pkg/evidencepack/inclusionproof.go; ref: core/pkg/evidencepack/merkle.go; test importer: core/pkg/crypto; test importer: core/pkg/evidencepack |
| `core/pkg/crypto/shredding` | 193 | 2026-04-23 | yes | 1 | KEEP | test importer: core/pkg/crypto |
| `core/pkg/crypto/tls` | 98 | 2026-04-23 | yes | 1 | KEEP | test importer: core/pkg/crypto |
| `core/pkg/crypto/zk` | 257 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/database` | 142 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/delegation` | 308 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/delivery` | 286 | 2026-05-13 | yes | 0 | DELETE | doc: docs/architecture/agent-process-ownership.md; ref: core/pkg/patchdelivery/verifier.go — named only in 'not to be confused with' notes (agent-process-ownership.md, patchdelivery/verifier.go) |
| `core/pkg/disclosure` | 42 | 2026-04-23 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/edge` | 306 | 2026-05-01 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/edgegovernance` | 74 | 2026-04-23 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/envelope` | 1527 | 2026-08-02 | yes | 0 | DELETE | doc: docs/architecture/agent-process-ownership.md; ref: core/pkg/worktree/worktree.go — named only in 'not to be confused with' notes (agent-process-ownership.md, worktree/worktree.go); 1527 LOC, last commit 2026-08-02 |
| `core/pkg/escalation` | 242 | 2026-08-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/escalation/ceremony` | 237 | 2026-05-13 | yes | 0 | DELETE | ref: core/pkg/genesis/ceremony/ceremony.go — named only in a 'not to be confused with' comment in core/pkg/genesis/ceremony |
| `core/pkg/evaluation` | 62 | 2026-04-23 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/evidence/arc` | 64 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/evidence/externalhost/adapters` | 584 | 2026-06-20 | yes | 1 | KEEP | test importer: core/pkg/verifier/externalreceipt |
| `core/pkg/evidencepack/retention` | 110 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/exportadmin` | 268 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/federation` | 533 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/forensics` | 65 | 2026-04-23 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/forge` | 681 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/gateway` | 74 | 2026-04-23 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/genesis/ceremony` | 318 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/harness` | 2518 | 2026-09-01 | yes | 0 | DELETE | doc: docs/architecture/agent-process-ownership.md — named only by docs/architecture/agent-process-ownership.md ("not yet wired"); HELM-658/674/682 do not name the package; last commit 2026-09-01 (#921, Prime Agent harness adapter; introduced by HELM-319 in #772) - owner to confirm before deletion |
| `core/pkg/identity/iatp` | 537 | 2026-05-21 | yes | 1 | KEEP | conformance suite: tests/conformance/did |
| `core/pkg/integrations/receipts` | 161 | 2026-08-02 | yes | 0 | KEEP | ref: tools/boundary/protected-dirs.sh |
| `core/pkg/intervention` | 136 | 2026-04-25 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/kernel/celdp` | 231 | 2026-06-20 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/kernel/consistency` | 513 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/kernel/errorir` | 74 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/kernel/formal` | 59 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/kernel/pdp` | 87 | 2026-05-12 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/kernel/retry` | 156 | 2026-04-25 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/kernel/sovereignty` | 132 | 2026-06-03 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/launchpad/conformance` | 229 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/launchpad/install` | 120 | 2026-05-18 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/launchpad/redact` | 104 | 2026-05-31 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/ledger` | 446 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/networkproof` | 2198 | 2026-08-02 | yes | 0 | KEEP | svc-helm-control-plane imports it |
| `core/pkg/orgdna` | 239 | 2026-04-23 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/packs/antispoof` | 256 | 2026-05-13 | yes | 1 | KEEP | ref: core/pkg/packs/install/install.go; conformance suite: tests/conformance/antispoof |
| `core/pkg/packs/install` | 744 | 2026-07-27 | yes | 0 | KEEP | svc-helm-control-plane imports it; ref: core/pkg/contracts/pack_manifest_v2.go |
| `core/pkg/patchdelivery` | 988 | 2026-08-04 | yes | 0 | DELETE | doc: docs/architecture/agent-process-ownership.md — same doc; not named by HELM-658/674/682 |
| `core/pkg/policy/lint` | 392 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/policy/suggest` | 202 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/policy/verify` | 224 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/policy/wasm` | 325 | 2026-04-23 | yes | 0 | KEEP | doc: HELM_INVARIANTS.md; doc: docs/PCAS_AUTHORIZATION_PROPAGATION_GAP_ANALYSIS.md; doc: protocols/policy-schema/v1/canonicalization.md |
| `core/pkg/policyloader` | 153 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/proofgraph/aigp` | 624 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/proofgraph/attribution` | 218 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/proofgraph/cloudevents` | 208 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/proofgraph/consensus` | 554 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/proofgraph/crdt` | 595 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/proofgraph/graphql` | 136 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/rbac` | 309 | 2026-05-17 | yes | 0 | KEEP | doc: docs/security/agent-safety-conformance-cases.md |
| `core/pkg/receipts` | 3 | 2026-05-21 | yes | 0 | KEEP | doc: docs/EXECUTION_SECURITY_MODEL.md; doc: docs/reference/execution-boundary.md; ref: tools/boundary/protected-dirs.sh — doc.go + policies fixtures + conformance test; named in docs/EXECUTION_SECURITY_MODEL.md, docs/reference/execution-boundary.md and tools/boundary/protected-dirs.sh |
| `core/pkg/releasegovernance` | 69 | 2026-04-23 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/replay` | 1225 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/rir` | 197 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/router` | 685 | 2026-06-20 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/runtime` | 172 | 2026-08-03 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/runtime/budget` | 86 | 2026-04-23 | yes | 1 | DELETE | test importer: core/pkg/runtime/sandbox — only importer is core/pkg/runtime/sandbox/wasi_adversarial_test.go; fold the budget type into runtime/sandbox or delete both |
| `core/pkg/runtimeadapters/a2a` | 134 | 2026-05-13 | yes | 1 | KEEP | conformance suite: tests/conformance/a2a |
| `core/pkg/runtimeadapters/generic_http` | 98 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — no doc, no importer; HELM-682 speaks of adapter/model selection at Control Plane level, not this package |
| `core/pkg/runtimeadapters/grpc` | 133 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — as generic_http |
| `core/pkg/runtimeadapters/websocket` | 136 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — as generic_http |
| `core/pkg/saga` | 256 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/scheduler` | 1136 | 2026-04-23 | yes | 1 | KEEP | conformance suite: tests/conformance/scheduling |
| `core/pkg/security/suites` | 153 | 2026-06-11 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/signals` | 592 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/skills` | 995 | 2026-06-11 | yes | 0 | KEEP | doc: docs/skills/SKILL_PACK_REPO_AUDIT.md |
| `core/pkg/slo` | 367 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/store/objstore/fs` | 136 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/surface` | 61 | 2026-04-23 | no | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/tenants` | 215 | 2026-05-13 | yes | 0 | KEEP | doc: docs/security/agent-safety-conformance-cases.md |
| `core/pkg/truth` | 557 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/util/resiliency` | 148 | 2026-06-02 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/verifier/agentprovenance` | 549 | 2026-07-27 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer — protected path: deletion PR needs helm-kernel-reviewer + boundary manifest regen |
| `core/pkg/versioning` | 329 | 2026-04-23 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/witness` | 402 | 2026-04-24 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
| `core/pkg/worktree` | 253 | 2026-08-04 | yes | 0 | DELETE | doc: docs/architecture/agent-process-ownership.md; ref: core/pkg/harness/harness.go; ref: core/pkg/patchdelivery/verifier.go — same doc; not named by HELM-658/674/682; imported only by core/pkg/harness (itself importer-less) |
| `core/pkg/zkgov/proofmarket` | 482 | 2026-05-13 | yes | 0 | DELETE | no doc, no protocol, no reference pack, no SDK, no importer |
