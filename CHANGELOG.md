# Changelog

All notable changes to HELM Core OSS are documented here.

## [0.4.0] — 2026-04-15 — Truth Gate, Real Connectors, Dashboard

This release closes every docs-to-code claim gap in the repo, ships the first real connector set (GitHub, Slack, Linear) replacing stubs, introduces a zero-backend EvidencePack viewer at `try.mindburn.org`, and formalizes a six-axis Conformance Profile v1 with TLA+ invariants model-checked in CI. Standards-body submission drafts ship alongside the technical work.

### Distribution — v0.4.0 published to

| Registry | Coordinate | Install |
|----------|------------|---------|
| **PyPI** | `helm-sdk` + 6 framework adapters | `pip install helm-sdk helm-langchain helm-crewai helm-openai-agents helm-anthropic helm-autogen helm-semantic-kernel` |
| **npm** | `@mindburn/helm` + 7 adapters + `@mindburn/helm-cli` | `npm install @mindburn/helm @mindburn/helm-anthropic @mindburn/helm-crewai-js @mindburn/helm-langchain @mindburn/helm-openai-agents @mindburn/helm-claude-code @mindburn/helm-semantic-kernel` |
| **crates.io** | `helm-sdk` | `cargo add helm-sdk` |
| **JitPack** (Java) | `com.github.Mindburn-Labs:helm-oss:v0.4.1-java` | See README Java install block |
| **GitHub Pages** | Dashboard | https://try.mindburn.org (pending DNS CNAME) |
| **Go** | `github.com/Mindburn-Labs/helm-oss/sdk/go` | `go get .../sdk/go@v0.4.0` |

Maven Central publication is deferred pending namespace verification (requires DNS TXT challenge) and GPG key email verification; JitPack serves the Java SDK with equivalent consumer ergonomics in the meantime.

### Added — Truth-Gate + Packaging (Phase 0 + 1)
- **Dashboard** at `dashboard/` — zero-backend, zero-telemetry EvidencePack viewer. Drop a `.tar` pack; parses TAR in-browser and verifies SHA-256 via Web Crypto. Hosted at `try.mindburn.org` via GitHub Pages.
- **`helm shadow scan`** — static shadow-AI discovery CLI + package (`core/pkg/shadow/`). Detects agent SDK imports, MCP configs, hardcoded API keys. Distinguishes HELM-routed vs un-governed agent usage.
- **`helm mcp scan`** — static MCP tool-catalog scanner combining DocScanner (DDIPE patterns), ArgScanner (shell injection / SSRF / path traversal), and typosquat detection (Levenshtein ≤2 against 18 known tools).
- **`tests/conformance/profile-v1/`** — six-axis HELM Conformance Profile v1 (draft): fail-closed firewall / canonical receipts / causal ProofGraph / delegation narrowing-only / EvidencePack round-trip / deterministic replay. Machine-readable `checklist.yaml` (14 checks, verification kinds: go_test / shell / fixture / tla).
- **`docs/research/replay.md`** — deterministic replay as HELM's forensic primitive for AI agent sessions. Covers debug / audit / dispute-resolution use cases + determinism boundary.
- **`docs/research/policy-composition-proof.md`** — P0/P1/P2 three-layer composition theorem, grounded in four arXiv papers.
- **`docs/compliance/enforcement-vs-mapping.md`** — explicit split between the compliance enforcement engine (DENYing PolicyResult) and framework record-keeping engines (logging + audit reports).
- **`docs/architecture/path-aware-policy.md`** — documents how CEL/WASM policies access `session_history` via Context map today; typed binding deferred to P5.
- **`docs/architecture/tool-execution-sandbox.md`** — explicit stance: HELM policy WASM sandbox != tool-execution sandbox. Roadmap for optional `SandboxDispatcher`.
- **`docs/architecture/guardian-pipeline.md`** — maps all 6 Guardian gates to their `WithXxx` options and implementation packages.

### Added — CI Workflows
- `.github/workflows/apalache.yml` — TLA+ model-check all 6 specs (GuardianPipeline, DelegationModel, ProofGraphConsistency, TenantIsolation, TrustPropagation, CSNFDeterminism) on every PR + nightly.
- `.github/workflows/benchmarks.yml` — nightly `make bench-report` + auto-commit `benchmarks/results/latest.json`; regression gate at p99 > 5000µs.
- `.github/workflows/fuzz.yml` — 18-target fuzz matrix across canonicalize, crypto, kernel, guardian, contracts, threat scanner, compliance, saga, a2a. 90s per-PR / 10m nightly.
- `.github/workflows/chaos-drill.yml` — 6 fail-closed invariant scenarios co-located in `core/pkg/*/chaos_test.go`.

### Added — Phase 2 Real Connectors
- **`core/pkg/connectors/github/client.go`** — real GitHub REST v3 client. Bearer PAT auth, retry with exponential backoff (500ms/1s/2s), 429 + 403-with-RLR=0 rate-limit handling, Retry-After + X-RateLimit-Reset, structured `APIError` with 422 field validation, pagination (5 pages / 500 PRs). Token-less mode returns sentinel errors preserving unit tests.
- **`core/pkg/connectors/slack/client.go`** — real Slack Web API client. Bot-token auth, `{"ok": false, "error": ...}` envelope parsed into structured `APIError` with `needed`/`provided` scope, cursor-based pagination for `conversations.list`, 429 + `ratelimited` retry, Slack TS timestamp parsed into `time.Time`.
- **`core/pkg/connectors/linear/client.go`** — real Linear GraphQL client. Personal API key or OAuth bearer auth (auto-detected), HELM priority-string → Linear integer mapping, GraphQL errors[] → structured `APIError` with extensions, retry on 5xx/429.
- Env-guarded integration tests for all three: `HELM_GITHUB_PAT`+`HELM_GITHUB_REPO`, `HELM_SLACK_BOT_TOKEN`+`HELM_SLACK_CHANNEL`, `HELM_LINEAR_API_KEY`+`HELM_LINEAR_TEAM_ID`.

### Added — Phase 4 Differentiation
- **Standards-body submission drafts** at `docs/standards/submissions/`:
  - `owasp-agentic-top10-helm-proposal.md` — enforcement-layer code references for each ASI-01..ASI-10 risk + six-axis Conformance Profile v1 as acceptance standard.
  - `cosai-proofgraph-taxonomy.md` — 7-node ProofGraph type taxonomy (+3 extensions) as cross-organizational audit interchange standard.
  - `lfai-conformance-profile-v1.md` — proposes hosting Conformance Profile v1 under LFAI governance for neutrality; Q2 2026 review target aligned with EU AI Act 2026-08-02 deadline.
- **Python AutoGen adapter test** (`sdk/python/autogen/test_helm_autogen.py`) closing the primary-adapter test gap.
- **TypeScript adapter tests** for anthropic, crewai-js, langchain (`sdk/ts/*/src/index.test.ts`) closing the vitest-config-without-tests gap. Critical fail-closed invariant — "wrapped fn must not run when HELM denies" — asserted in each.

### Changed — Messaging Pivot (Phase 0 REFRAME)
- README lead repositioned from "runtime governance kernel" to **"fail-closed AI execution substrate"**.
- Compliance claim corrected: "22 regulatory frameworks" → **7 framework Go packages + 9 signed reference policy bundles** (SOC 2, PCI-DSS, ISO 42001, EU AI Act high-risk, HIPAA covered entity, GDPR, customer-ops, procurement, recruiting).
- Connector claim corrected: "12+ more" → accurate list of real adapters (OpenAI-compatible proxy, Anthropic, LangChain, CrewAI, etc.).
- JSON schemas claim corrected: "50+" → **39** (actual count under `protocols/json-schemas/`).
- SDK claim corrected: previously claimed "SDKs for Go/Py/TS/Rust/Java" without matching directory; now matches real `sdk/` tree.
- MAMA multi-agent runtime moved from `core/pkg/mama/` to `core/pkg/experimental/mama/` with explicit README labeling it experimental. 15 import references across 9 consumer files updated atomically.
- 9 stub connectors marked with package-level `STUB` doc (gmail, gcalendar, gdocs_drive, docs/chandra, asr/vibevoice, forecast/timesfm; plus github/slack/linear which graduated from stub to real).

### Security
- **SECURITY.md** expanded: supported-versions updated to 0.3.x/0.4.x, cryptographic signing + provenance section (cosign + SLSA Level 3 + CycloneDX SBOM), vulnerability scanning inventory (Scorecard, Dependabot, fuzz, chaos, Apalache), responsible disclosure policy with safe harbor + bug bounty pointer, disclosure timeline, security contact with PGP fingerprint URL.
- **`.well-known/security.txt`** served from `try.mindburn.org` per RFC 9116.

### Fixed
- `docs/security/owasp-agentic-top10-coverage.md` — three stale "22 regulatory frameworks" lines corrected to match reality (7 Go packages + 9 reference bundles).
- `benchmarks/results/latest.json` — committed with the numbers already recorded in `docs/BENCHMARKS.md` at commit `4e52909d` so the artifact matches the documented claim. CI auto-refresh begins with the benchmarks.yml workflow.

---

### Added — Prior [Unreleased] content (pre-2026-04-15, in-flight)
- **Hybrid PQ Signing**: Ed25519 + ML-DSA-65 dual signatures on every receipt (`crypto/hybrid_signer.go`)
- **W3C DID**: Decentralized identifiers for agent identity (`identity/did/`)
- **DDIPE Doc Scanner**: Detects supply chain attacks in MCP tool documentation (`mcp/docscan.go`)
- **Memory Integrity**: SHA-256 hash-protected governed memory (`kernel/memory_integrity.go`)
- **Memory Trust Scoring**: Temporal decay trust with injection detection (`kernel/memory_trust.go`)
- **Ensemble Scanner**: Multi-scanner voting (ANY/MAJORITY/UNANIMOUS) (`threatscan/ensemble.go`)
- **Evidence Summaries**: Constant-size O(1) completeness proofs (`evidencepack/summary.go`)
- **SkillFortify**: Static capability verification for skills (`pack/verify_capabilities.go`)
- **Provenance Verification**: Cryptographic publisher signature checking (`pack/provenance.go`)
- **Cost Attribution**: Per-agent cost breakdown in ProofGraph (`effects/types.go`)
- **Cost Estimation**: Pre-execution cost prediction (`budget/estimate.go`)
- **Policy Suggestions**: Auto-generate rules from execution history (`policy/suggest/`)
- **Policy Verification**: Static analysis (circular deps, shadowed rules) (`policy/verify/`)
- **AIP Delegation**: Agent Identity Protocol for MCP (`mcp/aip.go`)
- **Continuous Delegation**: AITH time-bound revocable delegation (`identity/continuous_delegation.go`)
- **Replay Comparison**: Trace diff across governance sessions (`replay/compare.go`)
- **Federated Trust**: Cross-org reputation scoring (`mcp/trust.go`)
- **ZK Proof Interfaces**: Privacy-preserving compliance verification (`crypto/zkp/`)
- **MCPTox Harness**: Benchmark validating 0% ASR (`mcp/mcptox_test.go`)
- **Evidence Pack Spec v1.0**: Formal interchange standard (`protocols/spec/evidence-pack-v1.md`)
- **Circuit Breakers**: CLOSED/OPEN/HALF_OPEN per connector (`effects/circuitbreaker.go`)
- **Reversibility Classification**: Effect types tagged by reversibility (`effects/reversibility.go`)
- **SLO Engine**: Latency/error-rate objectives with budgets (`slo/engine.go`)
- **OpenTelemetry**: Guardian + Effects spans and metrics (`guardian/otel.go`, `effects/otel.go`)
- **CloudEvents**: ProofGraph SIEM export (`proofgraph/cloudevents/`)
- **Rug-Pull Detection**: MCP tool fingerprinting (`mcp/rugpull.go`)
- **Typosquatting Detection**: Levenshtein distance on tool names (`mcp/typosquat.go`)
- **GitHub Action**: Governance scan CI/CD (`.github/actions/governance-scan/`)
- **`helm doctor`**: Diagnostic CLI command
- **`helm certify`**: Evidence pack certification (7 frameworks)
- **`helm workforce`**: Agent fleet management (hire/list/suspend/terminate)

## [0.3.0] — 2026-03-22

### Changed — Truth-Reset Release

**Performance Evidence (Phase 2)**
- Benchmark harness: measured hot-path p99 = 75µs (governed allow: Guardian eval + Ed25519 sign + SQLite persist)
- Deny path: 29µs p99, mean allow overhead: 48µs
- Public claim upgraded from generic `< 5ms` to measured `75µs p99` with full methodology
- New `make bench` and `make bench-report` targets
- Machine-readable results at `benchmarks/results/latest.json`
- Full methodology: `docs/BENCHMARKS.md`

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
- Internal planning docs: `OSS_CUTLINE.md`, `UNKNOWNs.md`, and other internal-only materials.
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
