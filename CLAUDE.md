# CLAUDE.md — helm-oss

Per-project guide for Claude Code. Inherits from `../CLAUDE.md`. Read both.

## What this project is

Open-source fail-closed AI execution firewall. Go 1.25 core (`core/pkg/`, 150+ packages) with Protobuf-generated SDKs for TypeScript, Python, Go, Rust, and Java. Single purpose: every AI agent tool call passes through HELM, or it is blocked. Version 0.4.0. p99 overhead target: 75µs.

## What this project is NOT

- Not the commercial control plane. Multi-tenancy, billing, federation, enterprise RBAC, hosted Studio live in `helm/` — do not port them here.
- Not a trading system. Titan consumes HELM; research/strategy logic does not live in `core/pkg/`.
- Not a model training pipeline. `helm-compiler-lab/` trains compilers; this repo runs them as policy artifacts.
- Not a Python-first project. Python SDK is generated; source of truth is `protocols/proto/helm/`.
- Not a place for ad-hoc connectors. New connectors go through `connectors/` with contract fixtures.
- Not a place to regress determinism. Any non-JCS serialization in hot paths is a regression.

## Build / test / lint

```bash
make build              # bin/helm
make test               # Go unit tests (core/pkg/...)
make test-race          # Race detector
make lint               # go vet
make codegen            # Regenerate SDKs from protocols/proto/helm/
make codegen-check      # Fail if SDKs drift from proto IDL
make crucible           # L1 + L2 conformance
make crucible-full      # L1 + L2 + L3 + A2A + OTel
make bench              # crypto, store, guardian microbench
make bench-report       # benchmarks/results/latest.json (overhead)
cd core && go test -run TestName ./pkg/...
```

## Canonical paths

- `core/pkg/` — 150+ Go packages; the firewall
- `protocols/proto/helm/` — Protobuf IDL (source of truth for all SDKs)
- `protocols/policy-schema/v1/policy_bundle.proto` — P1 bundle schema
- `protocols/json-schemas/` — 39 JSON schemas (access, audit, effects, identity, intent, ...)
- `proofs/GuardianPipeline.tla` — TLA+ spec for the 6-gate guardian pipeline
- `reference_packs/` — 9 signed policy bundles (customer_ops, eu_ai_act_high_risk, exec_ops, hipaa_covered_entity, iso_42001, pci_dss_4, procurement, recruiting, soc2_type2 — all `.v1.json`)
- `examples/` — 20 example clients across Go, Python, TS, Rust, Java
- `tests/conformance/` — L1/L2/L3 harnesses
- `go.work` — workspace spans `core/` and `tests/conformance/`
- `VERSION` — release string (0.4.0)

## Architectural invariants

- MUST canonicalize all serializable structures with JCS (RFC 8785) + SHA-256. Cross-platform hash equality is mandatory.
- MUST sign receipts, permits, and attestations with Ed25519. No alternative signature schemes in the hot path.
- MUST stay fail-closed: empty allowlist means deny-all (see `firewall/`). Never substitute "allow everything by default" as a shortcut.
- MUST preserve the execution path `Intent → PEP (guardian) → KernelVerdict → EffectPermit → Gateway → Connector → Receipt`. Skipping a stage is a security regression.
- MUST compose policy as three layers: P0 ceilings → P1 bundles (signed) → P2 overlays. P2 may narrow but never widen.
- MUST NOT introduce non-deterministic iteration, map order, or goroutine race in kernel/guardian/proofgraph hot paths.
- MUST run `make codegen-check` whenever `protocols/proto/helm/**` changes. Drift is a CI failure.
- MUST keep imports one-directional: `examples/** → core/pkg/**` and `tests/conformance/** → core/pkg/**`, never reverse.

## Subagents to prefer

- `kernel-guardian` — any change under `core/pkg/{kernel,crypto,guardian,proofgraph,evidencepack,contracts}`
- `conformance-engineer` — `tests/conformance/`, golden fixtures, `reference_packs/`
- `wedge-product-owner` — CLI surface, SDK ergonomics, public examples
- `docs-truth-checker` — SDK docs, README claims, example parity

## Skills to prefer

- `helm-audit` — before touching anything cross-cutting
- `helm-conformance` — when extending the harness or adding a reference pack
- `helm-pr-preflight` — before opening a PR that touches `core/pkg/` or `protocols/`

## Danger zones

- `core/pkg/kernel/**` — determinism-critical; changes require kernel-guardian
- `core/pkg/crypto/**` — Ed25519, HSM, mTLS, SD-JWT; changes require kernel-guardian
- `core/pkg/guardian/**` — TLA+ spec in `proofs/` must stay in sync
- `core/pkg/proofgraph/**` — Lamport-ordered causal DAG; node-type additions are schema changes
- `core/pkg/evidencepack/**` — content-addressed archive format; any change breaks verifiers
- `core/pkg/contracts/**` — canonical types; wire-breaking
- `protocols/**` — proto IDL + JSON schemas + policy schema; all SDKs regenerate
- `reference_packs/**` — signed bundles; changes require re-signing and golden fixture bumps
