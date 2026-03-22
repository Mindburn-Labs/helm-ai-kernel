# Changelog

All notable changes to HELM Core OSS are documented here.

## [0.3.0] — 2026-03-22

### Changed — Truth-Reset Release

**Version Unification**
- Canonical version now lives in `VERSION` file at repo root
- `buildinfo.go`, `Makefile`, root `package.json`, `@mindburn/helm-cli` all read from or match VERSION
- Eliminated 5-way version drift (0.1.1, 0.2.0, 1.0.0, 1.0.1, 3.0.0)

**License Unification**
- All OSS components now Apache-2.0 (intentional, permanent)
- npm verifier `@mindburn/helm-cli`: BSL-1.1 → Apache-2.0
- Protocol spec `openapi.yaml`: BSL-1.1 → Apache-2.0
- Root `package.json`: ISC → Apache-2.0

**CLI/Doc Alignment**
- Fixed `--profile L2` → `--level L2` across all docs (README, QUICKSTART, DEMO, VERIFICATION, CONFORMANCE, START_HERE, index.md)
- The `--level` flag is the correct shortcut for L1/L2; `--profile` expects profile names (SMB, CORE, ENTERPRISE)
- Fixed fabricated JSON outputs to match actual `conform.go` struct shape
- Updated CLI command count: 11 → 20+ (actual count from Registry pattern)

**Cleanup**
- Root `package.json` marked `private`, removed vestigial `main` field, cleaned description
- `RELEASE.md` now references `VERSION` file instead of hardcoded example tags

## [0.2.0] — 2026-03-05

### Added

**CLI**

- `helm onboard` — one-command local setup (SQLite + Ed25519 keys + helm.yaml)
- `helm demo organization` — starter organization demo with governed agents and receipts (legacy `company` alias preserved for compatibility)
- `helm sandbox exec` — governed sandbox execution with strict preflight and receipt preimage binding
- `helm sandbox conform` — sandbox conformance checker (Compatible/Verified/Sovereign tiers)
- `helm mcp serve` — MCP server (stdio + remote HTTP + remote SSE)
- `helm mcp install` — Claude Code plugin generator
- `helm mcp pack` — .mcpb bundle generator (binary + platform_overrides)
- `helm mcp print-config` — config snippets for Windsurf, Codex, VS Code, Cursor

**Orchestrator Adapters**

- OpenAI Agents SDK Python adapter with governance routing and EvidencePack export
- MS Agent Framework Python adapter
- MS Agent Framework .NET minimal example

**Documentation**

- CLI-first QUICKSTART (10-minute proof loop)
- MCP clients, sandboxes, orchestrators, proxy snippets, troubleshooting guides
- COMPATIBILITY.md with tier definitions and matrix
- RELEASE.md with release engineering process

**Release Engineering**

- SBOM (CycloneDX) for binaries and containers
- Signed checksums, container signing/attestation
- MCPB toolchain for Claude Desktop bundles

### Changed

- Version bumped to 0.2.0
- Help text reorganized into sections
- EvidencePack default: `.tar` (deterministic), `.tar.gz` optional via `--compress`

## [3.0.0] — 2026-02-21

### Added

- **`@mindburn/helm-cli` CLI v3** — `npx @mindburn/helm-cli` for one-command verification with progressive disclosure, cryptographic proof (Ed25519 + real Merkle tree), and HTML evidence reports.
- **v3 bundle format spec** (`docs/cli_v3/FORMAT.md`) — canonicalization rules, Merkle tree construction, attestation schema.
- **Key rotation policy** (`docs/cli_v3/KEYS.md`).
- **Release pipeline** — evidence bundle build job with Ed25519 attestation signing in `release.yml`.
- **Verification guide** (`docs/verify.md`).

### Security

- **Removed `.env.release`** containing plaintext tokens from repo and git history.
- **Purged 376MB of compiled binaries** from `artifacts/` tracked in git history via `git filter-repo`.
- **Hardened `.gitignore`** — secrets hard lock (`.env*`, `*.key`, `*.pem`), `artifacts/` blanket ignore.
- Removed committed encrypted cookie from `core/pkg/console/.auth/`.

### Removed

- `cli/` directory (v2, superseded by `packages/mindburn-helm-cli/`).
- Internal planning docs: `OSS_CUTLINE.md`, `UNKNOWNs.md`, TITAN docs, investment memo.
- Dead redirect stubs for `HELM_Unified_Canonical_Standard.md`.

## [0.1.1] — 2026-02-19

### Fixed

- Resolved `MockSigner` build failure in `core/pkg/guardian` by implementing missing `PublicKeyBytes`.
- Fixed redundant signature assignment in `Ed25519Signer.SignDecision`.
- Standardized `ImmunityVerifier` hashing logic and cleaned up misleading test comments.
- Corrected version display in `helm` CLI help output.

### Improved

- Increased `governance` package test coverage from 60.8% to 79.5%.
- Added comprehensive unit tests for `LifecycleManager`, `PolicyEngine`, `EvolutionGovernance`, `SignalController`, and `StateEstimator`.

## [0.1.0] — 2026-02-15

### Added

- **Proxy sidecar** (`helm proxy`) — OpenAI-compatible reverse proxy. One line changed, every tool call gets a receipt.
- **SafeExecutor** — single execution boundary with schema validation, hash binding, and signed receipts.
- **Guardian** — policy engine with configurable tool allowlists and deny-by-default.
- **ProofGraph DAG** — signed nodes (INTENT, ATTESTATION, EFFECT, TRUST_EVENT, CHECKPOINT) with Lamport clocks and causal `PrevHash` chains.
- **Trust Registry** — event-sourced key lifecycle (add/revoke/rotate), replayable at any height.
- **WASI Sandbox** — deny-by-default (no FS, no net) with gas/time/memory budgets and deterministic trap codes.
- **Approval Ceremonies** — timelock + deliberate confirmation + challenge/response, suitable for disputes.
- **EvidencePack Export** — deterministic `.tar.gz` with sorted paths, epoch mtime, root uid/gid.
- **Replay Verify** — offline session replay with full signature and schema re-validation.
- **CLI** — 11 commands: `proxy`, `export`, `verify`, `replay`, `conform`, `doctor`, `init`, `trust add/revoke`, `version`, `serve`.
- **SDK Stubs** — TypeScript and Python client libraries.
- **Regional Profiles** — US, EU, RU, CN with Island Mode for network partitions.
- **12 executable use cases** with scripted validation.
- **Conformance gates** — L1 (kernel invariants) and L2 (profile-specific).

### Security

- Fail-closed execution: undeclared tools are blocked, schema drift is a hard error.
- Ed25519 signatures on all decisions, intents, and receipts.
- ArgsHash (PEP boundary) cryptographically bound into signed receipt chain.
- 8-package TCB with forbidden-import linter.
