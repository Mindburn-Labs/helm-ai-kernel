# Mindburn Labs Canonical Test Matrix (UCS v1.3)

This document defines the strictly enforced minimum test matrix required for all repositories governed by the HELM Unified Canonical Standard (UCS v1.3). Any PR merging to `main` across governed repositories must satisfy these requirements.

## 1. Governance Boundaries
All systems contributing to or interacting with the **Trusted Computing Base (TCB)** must enforce:
- **Offline Determinism:** No tests asserting KERNEL_VERDICT, PEP, or ProofGraph generation may utilize mocks, spies, or active network connections. All must assert against offline golden fixtures.
- **Fail-Closed Verification:** A negative vector test must exist for every structural change to an integration, ensuring unhandled inputs yield a DENY or ESCALATE state rather than a silent failure.

## 2. Minimum Coverage Matrix by Repository

### HELM OSS (`helm-oss`)
- **Go Kernel:** Unit tests, race detector, memory leak assertions.
- **SDKs:** Cross-language vector parity hashes (Python, Rust, Java, TS must produce identical byte hashes).
- **ProofGraph:** Redaction boundary and proof condensation fixtures.

### HELM Commercial (`helm`)
- **API & Routes:** OpenAPI vs Code route registry bidirectional drift test (`openapi:check`).
- **Auth & Tenant:** Testcontainers real-database isolation tests (NO IN-MEMORY MOCKS).
- **Console:** Playwright semantic E2E for the high-risk Approval Ceremony.

### Titan (`titan`)
- **Policy Engine:** Fuzzing and property tests for HMAC and Risk Policy bounds.
- **Execution:** Rust side-by-side NATS integration spin-ups.

### Pilot (`pilot`)
- **Connectors:** Offline schema drift fixtures (`schema_hash_mismatch`).
- **Orchestrator:** Postgres rollback checkpoint verification.

## 3. CI Branch Protection Baseline
The following jobs MUST pass. Skipping is forbidden without an explicit
Advisory suppression linked to a tracked risk:

1. `quality-pr` / `make quality-pr` (Make-first summary gate with impact filtering)
2. `hygiene` (presentation, unfinished-marker, and tracked-file hygiene)
3. `kernel` (lint, build, native tests, fixtures, boundary, crucible, benchmark report)
4. `contract-drift` (generated schema and SDK alignment)
5. `deployment-smoke` and `release-smoke` (Docker/Compose/chart and release evidence)
6. `codeql` and `scorecard` (SAST and supply-chain posture)

Nightly runs `make quality-nightly`. New noisy gates remain Advisory until their
baselines are clean or `QUALITY_STRICT=1` promotes them to blocking.

**No mock tests are permitted to define canonical execution truth.**
